"""The Actenon-Permit demo: a scripted agent exercising the full 7-step arc.

This module is imported by `permit demo`. It uses mock providers only — no
LLM, no network, no real money. The demo runs end-to-end in well under a
second.

Expected sequence (asserted by `tests/test_demo.py`):

    1. refund($20)      -> ALLOW    (budget 50 -> 30)
    2. refund($25)      -> ALLOW    (budget 30 -> 5)
    3. refund($20)      -> DENY     (budget: only $5 left of $50)
    4. send_email(...)  -> REQUIRE_APPROVAL -> (auto-approve) -> ALLOW
    5. charge($100)     -> DENY     (scope: payment.charge is denied)
    6. <caller runs `permit revoke refund-bot`>                  # kill switch
    7. refund($1)       -> DENY     (grant REVOKED)
"""

from __future__ import annotations

import os
from typing import Any

# Ensure the mock secret is set for the broker to resolve. NEVER a real key.
os.environ.setdefault("MOCK_STRIPE_KEY", "sk_mock_123")

from actenon_permit import (  # noqa: E402
    PDP,
    AutoApproveGate,
    Broker,
    GuardRegistry,
    Ledger,
    SQLiteStore,
    StdinApprovalGate,
    guard,
)
from actenon_permit._mock_providers import (  # noqa: E402
    mock_send_email,
    mock_stripe_charge,
    mock_stripe_refund,
)
from actenon_permit.model import GrantStatus  # noqa: E402
from actenon_permit.policy import compile_policy  # noqa: E402

# ---------------------------------------------------------------------------
# The policy that drives the demo (mirrors the SPEC)
# ---------------------------------------------------------------------------


DEMO_POLICY: dict[str, Any] = {
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


# ---------------------------------------------------------------------------
# Symbol printing
# ---------------------------------------------------------------------------


def _symbol(outcome: str) -> str:
    return {
        "ALLOW": "[ALLOW]   ",
        "DENY": "[DENY]    ",
        "REQUIRE_APPROVAL": "[APPROVAL]",
    }.get(outcome, f"[{outcome}]")


def _print_step(n: int, label: str, outcome: str, reason: str, extra: str = "") -> None:
    line = f"  step {n}: {label:<28} -> {_symbol(outcome)} {reason}"
    if extra:
        line += f"   ({extra})"
    print(line)


# ---------------------------------------------------------------------------
# Run the demo
# ---------------------------------------------------------------------------


def run_demo(*, auto_approve: bool = False) -> list[dict[str, Any]]:
    """Run the 7-step demo. Returns a list of step records for test assertion."""
    print()
    print("=" * 72)
    print("  Actenon-Permit demo — refund-bot (scripted agent, no LLM, no network)")
    print("=" * 72)
    print()

    # Set up the stack: store, ledger, PDP, broker, registry.
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    registry = GuardRegistry(store, pdp, broker)

    # Issue the grant from the demo policy.
    grant = compile_policy(DEMO_POLICY)
    store.put_grant(grant)
    registry.set_grant(grant.id)
    print(f"  issued grant: id={grant.id}")
    print(f"  agent:        {grant.agent_id}")
    print(f"  budget:       {grant.budget.currency} {grant.budget.limit} (remaining {grant.budget.remaining})")
    print(f"  scopes.allow: {grant.scopes.allow}")
    print(f"  scopes.deny:  {grant.scopes.deny}")
    print(f"  approval:     {grant.approval_rules}")
    print()

    # Approval gate — auto-approve in CI mode, stdin-blocking otherwise.
    if auto_approve:
        registry.set_approval_gate(AutoApproveGate())
        print("  approval mode: AUTO (CI)")
    else:
        registry.set_approval_gate(StdinApprovalGate())
        print("  approval mode: INTERACTIVE (will prompt on step 4)")
    print()

    # Define guarded tools. The wrapped functions take `secret` as the first
    # parameter; the agent-side call (which is what the demo invokes) omits it.
    @guard(
        "payment.refund",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        registry=registry,
    )
    def refund(secret: str, amount: float, reason: str = "customer_request") -> dict[str, Any]:
        return mock_stripe_refund(secret, amount, reason)

    @guard(
        "email.send",
        target="smtp",
        credential_name="MOCK_STRIPE_KEY",
        registry=registry,
    )
    def send_email(secret: str, to: str, subject: str, body: str = "") -> dict[str, Any]:
        return mock_send_email(secret, to, subject, body)

    @guard(
        "payment.charge",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        registry=registry,
    )
    def charge(secret: str, amount: float, description: str = "") -> dict[str, Any]:
        return mock_stripe_charge(secret, amount, description)

    # Track results for test assertion.
    results: list[dict[str, Any]] = []

    def _record(n: int, label: str, outcome: str, reason: str, extra: str = "") -> None:
        _print_step(n, label, outcome, reason, extra)
        results.append({"step": n, "label": label, "outcome": outcome, "reason": reason, "extra": extra})

    # --- Step 1: refund $20 -> ALLOW (50 -> 30) ---
    try:
        r = refund(amount=20.0, reason="customer_request")
        _record(1, "refund($20)", "ALLOW", f"budget 50 -> 30 ({r['id']})")
    except Exception as e:  # noqa: BLE001
        _record(1, "refund($20)", "DENY", str(e))

    # --- Step 2: refund $25 -> ALLOW (30 -> 5) ---
    try:
        r = refund(amount=25.0, reason="fraud_hold")
        _record(2, "refund($25)", "ALLOW", f"budget 30 -> 5 ({r['id']})")
    except Exception as e:  # noqa: BLE001
        _record(2, "refund($25)", "DENY", str(e))

    # --- Step 3: refund $20 -> DENY (only $5 left of $50) ---
    try:
        refund(amount=20.0, reason="customer_request")
        _record(3, "refund($20)", "ALLOW", "UNEXPECTED — should have been denied")
    except Exception as e:  # noqa: BLE001
        _record(3, "refund($20)", "DENY", str(e), extra="budget: only $5 left of $50")

    # --- Step 4: send_email -> REQUIRE_APPROVAL -> (auto-approve) -> ALLOW ---
    try:
        r = send_email(to="ops@example.com", subject="refund processed", body="hi")
        _record(4, "send_email(...)", "ALLOW", f"approved by human ({r['id']})")
    except Exception as e:  # noqa: BLE001
        _record(4, "send_email(...)", "DENY", str(e))

    # --- Step 5: charge $100 -> DENY (scope: payment.charge denied) ---
    # This simulates a prompt-injected agent trying to charge instead of refund.
    try:
        charge(amount=100.0, description="exfiltrate")
        _record(5, "charge($100)", "ALLOW", "UNEXPECTED — should have been denied")
    except Exception as e:  # noqa: BLE001
        _record(5, "charge($100)", "DENY", str(e), extra="simulated injection: payment.charge denied")

    # --- Step 6: kill switch ---
    store.set_status(grant.id, GrantStatus.REVOKED)
    # Re-fetch the live grant so the next call sees REVOKED.
    print()
    print("  >>> kill switch: `permit revoke refund-bot` — grant REVOKED")
    print()

    # --- Step 7: refund $1 -> DENY (grant REVOKED) ---
    try:
        refund(amount=1.0, reason="last_try")
        _record(7, "refund($1)", "ALLOW", "UNEXPECTED — should have been denied")
    except Exception as e:  # noqa: BLE001
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
    print("  proof the agent never held the real key:")
    print("    the call signature the agent used was `refund(amount=20)` — no `secret` arg.")
    print("    the broker resolved MOCK_STRIPE_KEY=sk_mock_*** internally and passed it")
    print("    only to the mock provider. the agent only saw the allow/deny result.")
    print()
    print("=" * 72)
    print("  demo complete.")
    print("=" * 72)
    print()
    return results


if __name__ == "__main__":
    import sys

    run_demo(auto_approve="--auto-approve" in sys.argv)
