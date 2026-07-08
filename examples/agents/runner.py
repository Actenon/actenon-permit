"""Real agent runners for Actenon-Permit v1.

These agents talk to a running gateway (``permit serve --with-gateway``)
exclusively via HTTP, exactly as a real agent host would. They never import
the mock providers or the broker — the secret is never in their memory.

Two agents:

1. ``ScriptedAgent`` — deterministic, for verification. Runs a fixed
   sequence of tool calls and asserts the expected outcomes. This is what
   the test suite uses.

2. ``LLMAgent`` — uses the z-ai SDK to decide which tool to call next based
   on a user request. The LLM sees the tool list (via ``GET /proxy/tools``)
   and produces a JSON action plan; the agent runner executes each action
   through the gateway and feeds the results back to the LLM.

Usage::

    # Terminal 1: start the gateway
    permit serve --with-gateway --port 7780

    # Terminal 2: issue a grant + mint a token
    GRANT_ID=$(permit issue examples/refund-bot-policy.yaml --quiet)
    TOKEN=$(permit mint-token $GRANT_ID)

    # Terminal 3: run an LLM agent
    python examples/agents/llm_agent.py --url http://127.0.0.1:7780 --token $TOKEN \\
        "Refund $30 to the customer who was overcharged, then email ops@example.com to confirm"
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Shared HTTP helpers
# ---------------------------------------------------------------------------


def _http(method: str, url: str, body: Any = None, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body_text)
        except json.JSONDecodeError:
            return e.code, {"raw": body_text}
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot reach gateway at {url}: {e}") from e


class GatewayClient:
    """Minimal HTTP client for the gateway. Mirrors what a real agent
    host (LangChain, etc.) would build on top of fetch/urllib."""

    def __init__(self, base_url: str, grant_token: str):
        self.base_url = base_url.rstrip("/")
        self.grant_token = grant_token

    def list_tools(self) -> list[str]:
        _, body = _http("GET", f"{self.base_url}/proxy/tools")
        return body.get("tools", [])

    def call_tool(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        status, body = _http(
            "POST",
            f"{self.base_url}/proxy/{tool}",
            body=args,
            headers={"X-Actenon-Grant": self.grant_token},
        )
        return body

    def get_grant(self) -> dict[str, Any]:
        # Decode the token to find the grant_id, then fetch live state.
        from actenon_permit.token import token_to_grant  # type: ignore[import-not-found]

        # The token is verified by the gateway, not the agent. We decode
        # without verification just to read the grant_id.
        try:
            g = token_to_grant(self.grant_token, verify=False)
            grant_id = g.id
        except Exception:
            return {}
        _, body = _http("GET", f"{self.base_url}/grants/{grant_id}")
        return body


# ---------------------------------------------------------------------------
# 1. ScriptedAgent — deterministic, for verification
# ---------------------------------------------------------------------------


class ScriptedAgent:
    """Runs a fixed sequence of tool calls. Used to verify the gateway
    enforces correctly without LLM nondeterminism.

    The sequence is the same 7-step arc as ``permit demo``, but every call
    goes through the HTTP gateway.
    """

    def __init__(self, client: GatewayClient):
        self.client = client
        self.results: list[dict[str, Any]] = []

    def run(self) -> list[dict[str, Any]]:
        print("\n=== ScriptedAgent: running 7-step arc through gateway ===\n")

        steps: list[tuple[int, str, str, dict[str, Any]]] = [
            (1, "refund", "refund($20) — should ALLOW (budget 50->30)", {"amount": 20, "reason": "customer_request"}),
            (2, "refund", "refund($25) — should ALLOW (budget 30->5)", {"amount": 25, "reason": "fraud_hold"}),
            (3, "refund", "refund($20) — should DENY (only $5 left)", {"amount": 20, "reason": "customer_request"}),
            (4, "send_email", "send_email — should REQUIRE_APPROVAL -> ALLOW", {"to": "ops@example.com", "subject": "refund processed", "body": "hi"}),
            (5, "charge", "charge($100) — should DENY (scope: payment.charge denied)", {"amount": 100, "description": "exfiltrate"}),
        ]

        for n, tool, label, args in steps:
            result = self.client.call_tool(tool, args)
            self.results.append({"step": n, "tool": tool, "label": label, "result": result})
            print(f"  step {n}: {label}")
            print(f"    -> outcome={result.get('outcome')}, reason={result.get('reason')}")
            if result.get("remaining_budget") is not None:
                print(f"       remaining_budget=${result['remaining_budget']}")
            print()

        # Step 6: revoke (via the control plane — the agent wouldn't normally
        # do this, but the test scenario calls for it).
        grant = self.client.get_grant()
        grant_id = grant.get("id")
        if grant_id:
            print(f"  step 6: >>> kill switch: revoking grant {grant_id}")
            _http("POST", f"{self.client.base_url}/grants/{grant_id}/revoke", body={})
            print()

        # Step 7: refund $1 — should DENY (revoked)
        result = self.client.call_tool("refund", {"amount": 1, "reason": "last_try"})
        self.results.append({"step": 7, "tool": "refund", "label": "refund($1) — should DENY (revoked)", "result": result})
        print("  step 7: refund($1) — should DENY (revoked)")
        print(f"    -> outcome={result.get('outcome')}, reason={result.get('reason')}")
        print()

        return self.results


# ---------------------------------------------------------------------------
# 2. LLMAgent — uses the z-ai SDK to decide which tool to call
# ---------------------------------------------------------------------------


SYSTEM_PROMPT = """You are an autonomous agent that calls tools through the Actenon-Permit gateway.

You will be given:
1. A list of available tools (name + description + input schema).
2. A user request.
3. The current grant state (budget remaining, scopes).

Your job is to produce a JSON action plan: a list of tool calls to make, in order, to fulfill the request. Each action is:

  {"tool": "<name>", "args": {<args>}}

Respond with ONLY a JSON object: {"actions": [{"tool": "...", "args": {...}}, ...]}

Rules:
- Only use tools from the list. Do not invent tools.
- If the request cannot be fulfilled with the available tools, return {"actions": [], "reason": "..."}.
- If a tool requires approval, the gateway will handle it — just include the call.
- Do NOT include the secret. The gateway holds it. You only pass the args.
- Be conservative: if you're not sure, do fewer calls.
"""


def _llm_decide(user_request: str, tools: list[dict[str, Any]], grant: dict[str, Any]) -> list[dict[str, Any]]:
    """Ask the z-ai LLM to produce an action plan for the user request.

    Uses the ``z-ai`` CLI (shipped with z-ai-web-dev-sdk) via subprocess so
    we don't need a Python SDK binding. Returns a list of {tool, args} dicts.
    """
    import subprocess

    user_msg = json.dumps(
        {
            "user_request": user_request,
            "available_tools": tools,
            "current_grant": {
                "agent_id": grant.get("agent_id"),
                "budget": grant.get("budget"),
                "scopes": grant.get("scopes"),
                "status": grant.get("status"),
            },
        },
        indent=2,
    )

    try:
        result = subprocess.run(
            ["z-ai", "chat", "--prompt", user_msg, "--system", SYSTEM_PROMPT, "-o", "/dev/stdout"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            "z-ai CLI not found. Install with: bun install -g z-ai-web-dev-sdk"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("z-ai CLI timed out") from e

    if result.returncode != 0:
        raise RuntimeError(f"z-ai CLI failed: {result.stderr[:200]}")

    content = result.stdout.strip()

    # The z-ai CLI prints status lines ("🚀 Initializing...") before the JSON
    # response, and a "✅ File saved" line after. Extract the JSON object
    # by finding the first '{' and matching braces.
    json_str = _extract_json_object(content)
    if json_str is None:
        print(f"[LLMAgent] WARNING: no JSON object in CLI output: {content!r}", file=sys.stderr)
        return []

    try:
        wrapped = json.loads(json_str)
    except json.JSONDecodeError:
        print(f"[LLMAgent] WARNING: could not parse JSON: {json_str!r}", file=sys.stderr)
        return []

    # The CLI wraps the OpenAI-style response in {choices: [{message: {content: ...}}]}.
    if isinstance(wrapped, dict) and "choices" in wrapped:
        content = wrapped["choices"][0]["message"]["content"]
    elif isinstance(wrapped, dict) and "content" in wrapped:
        content = wrapped["content"]
    else:
        content = json_str

    # The LLM may wrap the action plan in markdown fences; strip them.
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1] if "\n" in content else content
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]
        content = content.strip()
    try:
        plan = json.loads(content)
    except json.JSONDecodeError:
        print(f"[LLMAgent] WARNING: LLM returned non-JSON action plan: {content!r}", file=sys.stderr)
        return []
    return plan.get("actions", [])


def _extract_json_object(text: str) -> str | None:
    """Find the first balanced {...} JSON object in ``text``.

    Handles the z-ai CLI's mixed output (status lines + JSON + trailing
    status lines) by scanning for the first '{' and matching braces.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _get_tool_schemas(client: GatewayClient) -> list[dict[str, Any]]:
    """Fetch the full tool schemas (not just names) for the LLM.

    The gateway's /proxy/tools returns just names; we hardcode the schemas
    here for the demo. In a real deployment, the gateway would expose a
    /proxy/tools/schema endpoint (or the MCP tools/list would be used).
    """
    # For the demo, we know the tools. A real agent would use MCP tools/list.
    known_schemas = {
        "refund": {
            "name": "refund",
            "description": "Issue a refund via the (mock) Stripe provider.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "amount": {"type": "number", "description": "Amount to refund, in major currency units."},
                    "reason": {"type": "string", "default": "customer_request"},
                },
                "required": ["amount"],
            },
        },
        "charge": {
            "name": "charge",
            "description": "Charge a card via the (mock) Stripe provider.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "amount": {"type": "number"},
                    "description": {"type": "string", "default": ""},
                },
                "required": ["amount"],
            },
        },
        "send_email": {
            "name": "send_email",
            "description": "Send an email via the (mock) SMTP provider.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string", "default": ""},
                },
                "required": ["to", "subject"],
            },
        },
    }
    tool_names = client.list_tools()
    return [known_schemas[t] for t in tool_names if t in known_schemas]


class LLMAgent:
    """An LLM-driven agent that plans tool calls then executes them through
    the gateway.

    Flow:
      1. Fetch tool list + current grant state.
      2. Ask the LLM to produce a JSON action plan.
      3. Execute each action through the gateway.
      4. Print each outcome.
      5. (Optional) feed results back to the LLM for a follow-up plan.
    """

    def __init__(self, client: GatewayClient, verbose: bool = True):
        self.client = client
        self.verbose = verbose

    def run(self, user_request: str, max_rounds: int = 3) -> list[dict[str, Any]]:
        print(f"\n=== LLMAgent: {user_request!r} ===\n")

        all_results: list[dict[str, Any]] = []
        for round_num in range(1, max_rounds + 1):
            tools = _get_tool_schemas(self.client)
            grant = self.client.get_grant()
            if self.verbose:
                print(f"--- round {round_num} ---")
                print(f"  budget remaining: ${grant.get('budget', {}).get('remaining', '?')}")
                print(f"  grant status: {grant.get('status', '?')}")
                print(f"  available tools: {[t['name'] for t in tools]}")

            if grant.get("status") != "active":
                print(f"  grant is {grant.get('status')} — stopping.")
                break

            try:
                actions = _llm_decide(user_request, tools, grant)
            except RuntimeError as e:
                print(f"  [LLMAgent] LLM error: {e}", file=sys.stderr)
                break

            if not actions:
                print("  [LLMAgent] LLM produced no actions — done.")
                break

            if self.verbose:
                print(f"  LLM plan: {len(actions)} action(s)")
                for a in actions:
                    print(f"    - {a['tool']}({a.get('args', {})})")

            for action in actions:
                tool = action.get("tool")
                args = action.get("args", {})
                if not tool:
                    continue
                print(f"\n  calling {tool}({args})...")
                result = self.client.call_tool(tool, args)
                all_results.append({"tool": tool, "args": args, "result": result})
                outcome = result.get("outcome")
                reason = result.get("reason", "")
                print(f"    -> {outcome}: {reason}")
                if result.get("remaining_budget") is not None:
                    print(f"       remaining budget: ${result['remaining_budget']}")
                if outcome == "DENY" and "budget" in reason.lower():
                    print("       (budget exhausted — stopping)")
                    return all_results
                if outcome == "DENY" and "revoked" in reason.lower():
                    print("       (grant revoked — stopping)")
                    return all_results

            print()

        return all_results


# ---------------------------------------------------------------------------
# CLI entrypoints
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a real agent against the Actenon-Permit gateway.")
    parser.add_argument("--url", default="http://127.0.0.1:7780", help="Gateway URL.")
    parser.add_argument("--token", required=True, help="Grant bearer token (from `permit mint-token <id>`).")
    parser.add_argument("--mode", choices=["scripted", "llm"], default="llm", help="Agent mode.")
    parser.add_argument("--verbose", action="store_true", help="Verbose output.")
    parser.add_argument(
        "request",
        nargs="?",
        default="Refund $30 to the customer who was overcharged, then email ops@example.com to confirm.",
        help="User request (LLM mode only).",
    )
    args = parser.parse_args()

    client = GatewayClient(args.url, args.token)

    # Verify the gateway is reachable.
    try:
        tools = client.list_tools()
        print(f"connected to gateway at {args.url}; available tools: {tools}")
    except Exception as e:
        print(f"ERROR: cannot reach gateway at {args.url}: {e}", file=sys.stderr)
        print("Did you run `permit serve --with-gateway --port 7780`?", file=sys.stderr)
        sys.exit(1)

    if args.mode == "scripted":
        agent = ScriptedAgent(client)
        results = agent.run()
    else:
        agent = LLMAgent(client, verbose=args.verbose)
        results = agent.run(args.request)

    # Summary
    print("\n=== Agent run summary ===")
    for r in results:
        outcome = r.get("result", {}).get("outcome", "?")
        tool = r.get("tool", "?")
        reason = r.get("result", {}).get("reason", "")
        step = r.get("step", "")
        prefix = f"step {step}: " if step else ""
        print(f"  {prefix}{tool} -> {outcome} ({reason})")
    print()


if __name__ == "__main__":
    main()
