"""Actenon-Permit v1 out-of-process PEP gateway.

The gateway is the v1 "airlock": it runs in a separate process from the agent,
holds the real credentials, and enforces every decision server-side. An agent
with arbitrary code-exec can no longer bypass enforcement by importing the
provider SDK directly — it doesn't have the secret, only a grant token.

Two transports are supported:

  1. **HTTP proxy** — ``POST /proxy/{tool}`` with ``X-Actenon-Grant`` header.
     Returns the tool's result on ALLOW, 403 with a JSON body on DENY, 202
     with an approval URL on REQUIRE_APPROVAL.

  2. **MCP stdio** — JSON-RPC 2.0 over stdin/stdout. ``tools/list`` returns
     the registered tools as MCP tool specs; ``tools/call`` enforces the
     decision and executes. The grant token is passed in
     ``params._meta.actenon_grant``.

Both transports share the same ``ToolRegistry`` and the same enforcement
path: validate token -> load live grant state -> ``PDP.decide()`` -> on ALLOW
run the real call via the broker -> reconcile cost -> return.

The gateway extends v0's ``control.py`` FastAPI app rather than replacing it.
The control plane endpoints (/grants, /approvals, /ledger) still work; the
gateway adds /proxy/* and the MCP stdio entrypoint.
"""

from __future__ import annotations

import contextlib
import json
import sys
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .broker import Broker, CredentialMissing, extract_cost
from .enforce import ApprovalGate, AutoApproveGate
from .ledger import Ledger
from .model import Action, Decision, DecisionOutcome, Grant, GrantStatus
from .pdp import PDP
from .state import SQLiteStore, StateStore
from .token import TokenError, token_to_grant

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    """A guarded tool registered with the gateway."""

    name: str
    action_type: str
    real_call: Callable[..., Any] = field(repr=False)
    target: str = ""
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": True})
    cost_from: str | None = None
    credential_name: str | None = None


class ToolRegistry:
    """Registry of guarded tools the gateway exposes."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._lock = threading.RLock()

    def register(
        self,
        name: str,
        *,
        action_type: str,
        target: str = "",
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        cost_from: str | None = None,
        credential_name: str | None = None,
        real_call: Callable[..., Any],
    ) -> ToolSpec:
        spec = ToolSpec(
            name=name,
            action_type=action_type,
            target=target or action_type,
            description=description or f"{action_type} tool",
            input_schema=input_schema or {"type": "object", "properties": {}, "additionalProperties": True},
            cost_from=cost_from,
            credential_name=credential_name,
            real_call=real_call,
        )
        with self._lock:
            if name in self._tools:
                raise ValueError(f"tool '{name}' is already registered")
            self._tools[name] = spec
        return spec

    def get(self, name: str) -> ToolSpec | None:
        with self._lock:
            return self._tools.get(name)

    def list(self) -> list[ToolSpec]:
        with self._lock:
            return list(self._tools.values())

    def to_mcp_tools(self) -> list[dict[str, Any]]:
        """Return the registry as MCP ``tools/list`` result entries."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self.list()
        ]


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class Gateway:
    """The out-of-process PEP. Holds tool registry, state, ledger, PDP, broker.

    The gateway is transport-agnostic: ``call_tool()`` is the single
    enforcement path used by both the HTTP proxy and the MCP stdio server.
    """

    def __init__(
        self,
        *,
        state: StateStore | None = None,
        ledger: Ledger | None = None,
        pdp: PDP | None = None,
        broker: Broker | None = None,
        tools: ToolRegistry | None = None,
        approval_gate: ApprovalGate | None = None,
    ):
        self.state = state or SQLiteStore()
        self.ledger = ledger or Ledger(self.state)
        self.pdp = pdp or PDP(self.state, self.ledger)
        self.broker = broker or Broker(self.pdp)
        self.tools = tools or ToolRegistry()
        # Default to auto-approve for tests; production callers should set a
        # BlockingApprovalGate wired to the control plane's ApprovalStore.
        self.approval_gate: ApprovalGate = approval_gate or AutoApproveGate()

    # ------------------------------------------------------------------
    # Grant token handling
    # ------------------------------------------------------------------

    def resolve_grant(self, token: str) -> Grant:
        """Decode a bearer token and return the live Grant from the state store.

        The token carries the grant's signature and identity; the state store
        carries the live status/budget. We trust the token for identity
        (signature-verified) but the state store for status — so a revoked
        grant's token is still decodable but the next decision is DENY.
        """
        try:
            grant_from_token = token_to_grant(token, verify=True)
        except TokenError:
            raise
        # Load live state (status may have changed since the token was issued)
        live = self.state.get_grant(grant_from_token.id)
        if live is None:
            # Token is valid but the grant has been deleted from the store.
            # Treat as revoked — fail closed.
            grant_from_token.status = GrantStatus.REVOKED
            return grant_from_token
        return live

    # ------------------------------------------------------------------
    # The single enforcement path
    # ------------------------------------------------------------------

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        grant_token: str,
    ) -> dict[str, Any]:
        """Enforce-then-execute a tool call. Returns a structured result.

        Returns a dict with shape::

            {
              "outcome": "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
              "reason": str,
              "rule_matched": str | None,
              "result": <tool return value, only on ALLOW>,
              "action_id": str,
              "grant_id": str,
              "remaining_budget": float | None,
            }
        """
        spec = self.tools.get(tool_name)
        if spec is None:
            return {
                "outcome": "DENY",
                "reason": f"unknown tool: {tool_name}",
                "rule_matched": "tool:unknown",
                "action_id": None,
                "grant_id": None,
                "remaining_budget": None,
            }

        try:
            grant = self.resolve_grant(grant_token)
        except TokenError as e:
            return {
                "outcome": "DENY",
                "reason": f"invalid grant token: {e}",
                "rule_matched": "token:invalid",
                "action_id": None,
                "grant_id": None,
                "remaining_budget": None,
            }

        # Build the Action from the call args. The cost is extracted from the
        # argument named by ``cost_from`` (or params['amount'] / ['cost']).
        params = {k: v for k, v in arguments.items() if isinstance(v, (str, int, float, bool, type(None)))}
        est_cost: float | None = None
        if spec.cost_from and spec.cost_from in arguments and isinstance(arguments[spec.cost_from], (int, float)):
            est_cost = float(arguments[spec.cost_from])
        elif "amount" in params and isinstance(params["amount"], (int, float)):
            est_cost = float(params["amount"])
        elif "cost" in params and isinstance(params["cost"], (int, float)):
            est_cost = float(params["cost"])

        action = Action(
            action_id=f"act_{uuid.uuid4().hex[:16]}",
            grant_id=grant.id,
            ts=datetime.now(UTC),
            type=spec.action_type,
            target=spec.target,
            params=params,
            est_cost=est_cost,
        )

        # Use decide_and_mint_pccb so we get a kernel PCCB on ALLOW.
        # The PCCB is verified at the edge before the broker releases the
        # real credential — this is the "agent physically cannot exceed"
        # guarantee from ARCHITECTURE.md §3.
        decision, intent, pccb = self.pdp.decide_and_mint_pccb(grant, action, ctx={})

        if decision.outcome == DecisionOutcome.DENY:
            return self._deny_response(action, decision, grant)

        if decision.outcome == DecisionOutcome.REQUIRE_APPROVAL:
            approved = self.approval_gate.request(grant, action, decision)
            if not approved:
                return {
                    "outcome": "DENY",
                    "reason": "approval denied or timed out",
                    "rule_matched": decision.rule_matched,
                    "action_id": action.action_id,
                    "grant_id": grant.id,
                    "remaining_budget": grant.budget.remaining,
                }
            # Re-run decision + PCCB mint after approval — state and clock moved.
            grant = self.state.get_grant(grant.id) or grant
            decision, intent, pccb = self.pdp.decide_and_mint_pccb(
                grant, action, ctx={"approved_action_id": action.action_id}
            )
            if decision.outcome != DecisionOutcome.ALLOW:
                return self._deny_response(action, decision, grant)

        # EDGE VERIFICATION — the kernel verifies the PCCB is bound to the
        # EXACT action before we release the credential. This is the call
        # that makes "the agent physically cannot exceed" true: a mutated
        # amount, a different target, a replayed proof, an expired grant —
        # any of these raises ProofVerificationError and we DENY.
        if intent is not None and pccb is not None:
            try:
                from .kernel_bridge import verify_pccb_at_edge

                verify_pccb_at_edge(intent, pccb, grant, action)
            except Exception as e:
                # Kernel verification failed — release the reservation and
                # fail closed. The credential is NOT released.
                if action.est_cost:
                    with contextlib.suppress(Exception):
                        self.state.release(grant.id, action.action_id, action.est_cost)
                return {
                    "outcome": "DENY",
                    "reason": f"proof verification failed at edge: {e}",
                    "rule_matched": "kernel:proof_verification_failed",
                    "action_id": action.action_id,
                    "grant_id": grant.id,
                    "remaining_budget": grant.budget.remaining,
                }

        # ALLOW — execute the real call via the broker (or directly if no
        # credential is needed).
        try:
            if spec.credential_name is None:
                result = spec.real_call(**arguments)
                actual_cost = extract_cost(result, action)
                self.pdp.commit(grant, action, actual_cost)
            else:
                result, actual_cost = self.broker.execute(
                    grant,
                    action,
                    decision,
                    lambda secret: spec.real_call(secret=secret, **arguments),
                    spec.credential_name,
                )
        except CredentialMissing as e:
            # Release the reservation and fail closed.
            if action.est_cost:
                with contextlib.suppress(Exception):
                    self.state.release(grant.id, action.action_id, action.est_cost)
            return {
                "outcome": "DENY",
                "reason": f"credential missing: {e}",
                "rule_matched": "broker:credential_missing",
                "action_id": action.action_id,
                "grant_id": grant.id,
                "remaining_budget": grant.budget.remaining,
            }
        except Exception as e:
            # The real call raised. Reconcile cost as 0 (nothing happened
            # in the real world) and surface the error as a DENY.
            if action.est_cost:
                with contextlib.suppress(Exception):
                    self.state.release(grant.id, action.action_id, action.est_cost)
            return {
                "outcome": "DENY",
                "reason": f"tool execution error: {type(e).__name__}: {e}",
                "rule_matched": "broker:execution_error",
                "action_id": action.action_id,
                "grant_id": grant.id,
                "remaining_budget": grant.budget.remaining,
            }

        # Reload grant to get the post-commit remaining.
        live = self.state.get_grant(grant.id) or grant
        return {
            "outcome": "ALLOW",
            "reason": decision.reason,
            "rule_matched": decision.rule_matched,
            "result": result,
            "action_id": action.action_id,
            "grant_id": grant.id,
            "remaining_budget": live.budget.remaining,
        }

    @staticmethod
    def _deny_response(action: Action, decision: Decision, grant: Grant) -> dict[str, Any]:
        return {
            "outcome": "DENY",
            "reason": decision.reason,
            "rule_matched": decision.rule_matched,
            "action_id": action.action_id,
            "grant_id": grant.id,
            "remaining_budget": grant.budget.remaining,
        }


# ---------------------------------------------------------------------------
# HTTP proxy (extends the v0 control plane)
# ---------------------------------------------------------------------------


def mount_proxy(app, gateway: Gateway) -> None:
    """Mount /proxy/* endpoints on an existing FastAPI app.

    Delegates to ``_proxy_routes.mount`` which is a module that does NOT use
    ``from __future__ import annotations``. FastAPI's Request-type detection
    happens at runtime via isinstance checks on the annotation, and
    stringified annotations (which the future import produces) break it —
    the route handler's ``request: Request`` parameter gets treated as a
    required query param and returns 422.
    """
    from . import _proxy_routes

    _proxy_routes.mount(app, gateway)


# ---------------------------------------------------------------------------
# MCP stdio server (JSON-RPC 2.0 over stdin/stdout)
# ---------------------------------------------------------------------------


def mcp_serve(gateway: Gateway, *, infile=None, outfile=None) -> None:
    """Run the MCP stdio server.

    Reads JSON-RPC 2.0 requests line-by-line from ``infile`` (default stdin),
    writes responses line-by-line to ``outfile`` (default stdout). Implements:

      - ``initialize`` — handshake, returns server capabilities
      - ``tools/list`` — returns registered tools as MCP tool specs
      - ``tools/call`` — enforces decision and executes; grant token is read
        from ``params._meta.actenon_grant``

    The server exits cleanly on EOF or on an ``exit`` notification.
    """
    infile = infile or sys.stdin
    outfile = outfile or sys.stdout

    server_info = {
        "name": "actenon-permit-gateway",
        "version": "1.0.0",
    }
    capabilities = {
        "tools": {"listChanged": False},
    }

    for line in infile:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _write_jsonrpc(outfile, None, error={"code": -32700, "message": "Parse error"})
            continue

        if not isinstance(req, dict):
            _write_jsonrpc(outfile, None, error={"code": -32600, "message": "Invalid Request"})
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        # Notification (no id) — only handle exit.
        if req_id is None and method == "exit":
            return

        if method == "initialize":
            _write_jsonrpc(
                outfile,
                req_id,
                result={
                    "protocolVersion": "2024-11-05",
                    "capabilities": capabilities,
                    "serverInfo": server_info,
                },
            )
        elif method == "initialized":
            # notification, no response
            pass
        elif method == "tools/list":
            _write_jsonrpc(outfile, req_id, result={"tools": gateway.tools.to_mcp_tools()})
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            meta = params.get("_meta") or {}
            grant_token = meta.get("actenon_grant")
            if not grant_token:
                _write_jsonrpc(
                    outfile,
                    req_id,
                    error={"code": -32602, "message": "missing _meta.actenon_grant"},
                )
                continue
            result = gateway.call_tool(tool_name, arguments, grant_token)
            # MCP expects an isError flag for tool errors. We map ALLOW to
            # success and anything else to isError=true with the reason as text.
            if result["outcome"] == "ALLOW":
                content = _mcp_content(result.get("result"))
                _write_jsonrpc(outfile, req_id, result={"content": content, "isError": False})
            else:
                content = [{"type": "text", "text": f"{result['outcome']}: {result['reason']}"}]
                _write_jsonrpc(outfile, req_id, result={"content": content, "isError": True})
        elif method == "ping":
            _write_jsonrpc(outfile, req_id, result={})
        else:
            _write_jsonrpc(
                outfile,
                req_id,
                error={"code": -32601, "message": f"Method not found: {method}"},
            )


def _write_jsonrpc(stream, req_id, *, result=None, error=None) -> None:
    msg: dict[str, Any] = {"jsonrpc": "2.0"}
    if req_id is not None:
        msg["id"] = req_id
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    stream.write(json.dumps(msg) + "\n")
    stream.flush()


def _mcp_content(value: Any) -> list[dict[str, Any]]:
    """Wrap a tool result value as MCP content blocks."""
    if value is None:
        return [{"type": "text", "text": "null"}]
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    return [{"type": "text", "text": json.dumps(value, default=str, sort_keys=True)}]


__all__ = [
    "ToolSpec",
    "ToolRegistry",
    "Gateway",
    "mount_proxy",
    "mcp_serve",
]
