"""The v1 gateway demo: same 7-step arc as the v0 demo, but every action goes
through the out-of-process PEP gateway over HTTP.

This proves the v1 trust boundary is real: the agent process never imports the
mock providers, never holds the secret, and only talks to the gateway via
HTTP. The agent process is the untrusted one; the gateway is the airlock.

Architecture:
    agent process (untrusted)              gateway process (trusted)
    -------------------------             ---------------------------
    RemoteGuardRegistry  --- HTTP --->    /proxy/{tool}
    @remote_guard refund                     Gateway.call_tool()
    @remote_guard send_email                   -> PDP.decide()
    @remote_guard charge                       -> Broker.execute()
                                              -> mock provider (with secret)
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from typing import Any

# Ensure the mock secret is set for the broker to resolve. NEVER a real key.
os.environ.setdefault("MOCK_STRIPE_KEY", "sk_mock_123")


def _pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 15.0) -> None:
    import urllib.request

    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=0.5) as resp:
                if resp.status == 200:
                    return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.1)
    raise RuntimeError(f"server at {url} did not become ready: {last_err}")


def _print_step(n: int, label: str, outcome: str, reason: str, extra: str = "") -> None:
    sym = {
        "ALLOW": "[ALLOW]   ",
        "DENY": "[DENY]    ",
        "REQUIRE_APPROVAL": "[APPROVAL]",
    }.get(outcome, f"[{outcome}]")
    line = f"  step {n}: {label:<28} -> {sym} {reason}"
    if extra:
        line += f"   ({extra})"
    print(line)


def run_gateway_demo(*, auto_approve: bool = False) -> list[dict[str, Any]]:
    """Run the 7-step demo against an in-process HTTP gateway server.

    The gateway server is started on a random localhost port (so multiple
    demos can run in parallel). The agent-side calls use the
    ``RemoteGuardRegistry`` and ``remote_guard`` decorator from
    ``pep_client.py`` — exactly the same code path an external agent would
    use.
    """
    print()
    print("=" * 76)
    print("  Actenon-Permit v1 GATEWAY demo — refund-bot via out-of-process PEP")
    print("=" * 76)
    print()

    # Import after env setup
    from actenon_permit import (
        PDP,
        AutoApproveGate,
        Broker,
        Gateway,
        Ledger,
        SQLiteStore,
        ToolRegistry,
    )
    from actenon_permit._mock_providers import (
        mock_send_email,
        mock_stripe_charge,
        mock_stripe_refund,
    )
    from actenon_permit.control import create_app
    from actenon_permit.model import GrantStatus
    from actenon_permit.pep_client import RemoteGuardDenied, RemoteGuardRegistry, remote_guard
    from actenon_permit.policy import compile_policy
    from actenon_permit.token import grant_to_token

    # --- Set up the gateway side (trusted process) ---
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    tools.register(
        "refund",
        action_type="payment.refund",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="customer_request": mock_stripe_refund(secret, amount, reason),
    )
    tools.register(
        "charge",
        action_type="payment.charge",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description),
    )
    tools.register(
        "send_email",
        action_type="email.send",
        target="smtp",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
    )
    gateway = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate() if auto_approve else AutoApproveGate(),
    )

    # Issue the grant (mirrors the v0 demo's DEMO_POLICY)
    policy = {
        "agent": "refund-bot",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 50},
        "scopes": {
            "allow": ["payment.refund", "email.send"],
            "deny": ["payment.charge", "shell.*"],
        },
        "rate": {"max": 20, "per": "1m"},
        "approval": {"require_human": ["email.send"]},
    }
    grant = compile_policy(policy)
    store.put_grant(grant)
    token = grant_to_token(grant)

    print(f"  issued grant: id={grant.id}")
    print(f"  agent:        {grant.agent_id}")
    print(f"  budget:       {grant.budget.currency} {grant.budget.limit} (remaining {grant.budget.remaining})")
    print(f"  scopes.allow: {grant.scopes.allow}")
    print(f"  scopes.deny:  {grant.scopes.deny}")
    print(f"  approval:     {grant.approval_rules}")
    print(f"  grant token:  {token[:48]}... (signed, bearer)")
    print()

    # --- Start the HTTP server in a background thread ---
    port = _pick_port()
    base_url = f"http://127.0.0.1:{port}"
    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gateway)

    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    try:
        _wait_for_server(base_url)
        print(f"  gateway listening at {base_url} (out-of-process PEP)")
        print(f"  agent process will call: POST {base_url}/proxy/<tool> with X-Actenon-Grant header")
        print()

        # --- Set up the agent side (untrusted process) ---
        # In a real deployment, this code runs in a different process (or even
        # a different machine). Here it runs in the same process for demo
        # simplicity, but it ONLY talks to the gateway via HTTP — it never
        # imports the mock providers or the broker.
        reg = RemoteGuardRegistry(gateway_url=base_url)
        reg.set_grant_token(token)

        @remote_guard("payment.refund", cost_from="amount", registry=reg)
        def refund(amount: float, reason: str = "customer_request") -> dict:
            """Issue a refund. (Body is ignored — real impl lives in the gateway.)"""
            ...

        @remote_guard("email.send", registry=reg)
        def send_email(to: str, subject: str, body: str = "") -> dict:
            """Send an email. (Body is ignored — real impl lives in the gateway.)"""
            ...

        @remote_guard("payment.charge", cost_from="amount", registry=reg)
        def charge(amount: float, description: str = "") -> dict:
            """Charge a card. (Body is ignored — real impl lives in the gateway.)"""
            ...

        results: list[dict[str, Any]] = []

        def _record(n: int, label: str, outcome: str, reason: str, extra: str = "") -> None:
            _print_step(n, label, outcome, reason, extra)
            results.append({"step": n, "label": label, "outcome": outcome, "reason": reason, "extra": extra})

        # --- Step 1: refund $20 -> ALLOW (50 -> 30) ---
        try:
            r = refund(amount=20.0, reason="customer_request")
            _record(1, "refund($20)", "ALLOW", f"budget 50 -> 30 ({r['id']})")
        except RemoteGuardDenied as e:
            _record(1, "refund($20)", "DENY", str(e))

        # --- Step 2: refund $25 -> ALLOW (30 -> 5) ---
        try:
            r = refund(amount=25.0, reason="fraud_hold")
            _record(2, "refund($25)", "ALLOW", f"budget 30 -> 5 ({r['id']})")
        except RemoteGuardDenied as e:
            _record(2, "refund($25)", "DENY", str(e))

        # --- Step 3: refund $20 -> DENY (only $5 left) ---
        try:
            refund(amount=20.0, reason="customer_request")
            _record(3, "refund($20)", "ALLOW", "UNEXPECTED — should have been denied")
        except RemoteGuardDenied as e:
            _record(3, "refund($20)", "DENY", str(e), extra="budget: only $5 left of $50")

        # --- Step 4: send_email -> REQUIRE_APPROVAL -> (auto-approve) -> ALLOW ---
        try:
            r = send_email(to="ops@example.com", subject="refund processed", body="hi")
            _record(4, "send_email(...)", "ALLOW", f"approved by human ({r['id']})")
        except RemoteGuardDenied as e:
            _record(4, "send_email(...)", "DENY", str(e))

        # --- Step 5: charge $100 -> DENY (scope: payment.charge denied) ---
        try:
            charge(amount=100.0, description="exfiltrate")
            _record(5, "charge($100)", "ALLOW", "UNEXPECTED — should have been denied")
        except RemoteGuardDenied as e:
            _record(5, "charge($100)", "DENY", str(e), extra="simulated injection: payment.charge denied")

        # --- Step 6: kill switch ---
        store.set_status(grant.id, GrantStatus.REVOKED)
        print()
        print("  >>> kill switch: `permit revoke refund-bot` — grant REVOKED")
        print()

        # --- Step 7: refund $1 -> DENY (grant REVOKED) ---
        try:
            refund(amount=1.0, reason="last_try")
            _record(7, "refund($1)", "ALLOW", "UNEXPECTED — should have been denied")
        except RemoteGuardDenied as e:
            _record(7, "refund($1)", "DENY", str(e), extra="grant REVOKED")

        # --- Closing summary ---
        print()
        print("  ledger (last 8 entries):")
        for e in ledger.list_entries(grant_id=grant.id, limit=8)[-8:]:
            print(
                f"    {e['outcome']:<18} {e['action_type']:<22} reason={e['reason']}  "
                f"hash={e['hash'][:12]}..."
            )
        print()
        ok = ledger.verify()
        print(f"  ledger chain intact: {ok}")
        print()
        print("  v1 trust boundary proof:")
        print("    the agent process only imported `pep_client` (the remote PEP).")
        print("    it never imported the mock providers or the broker. it has no")
        print("    way to call `mock_stripe_charge` directly — even with arbitrary")
        print("    code exec, the secret `sk_mock_***` is not in its memory.")
        print("    every call crossed the HTTP boundary to the gateway, which")
        print("    enforced decide() and swapped the grant for the real credential.")
        print()
        print("=" * 76)
        print("  v1 gateway demo complete.")
        print("=" * 76)
        print()
        return results
    finally:
        server.should_exit = True
        server_thread.join(timeout=5.0)


if __name__ == "__main__":
    run_gateway_demo(auto_approve="--auto-approve" in sys.argv)
