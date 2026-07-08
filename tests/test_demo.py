"""End-to-end demo test: run the 7-step scenario and assert the exact
expected decision sequence.
"""

from __future__ import annotations


def test_demo_seven_step_sequence(fresh_env, capsys):
    """The demo must produce the exact 7-step ALLOW/DENY/APPROVAL arc."""
    from actenon_permit._demo import run_demo

    results = run_demo(auto_approve=True)
    captured = capsys.readouterr()

    # Expected sequence per SPEC:
    expected = [
        (1, "ALLOW"),
        (2, "ALLOW"),
        (3, "DENY"),
        (4, "ALLOW"),  # REQUIRE_APPROVAL -> auto-approved -> ALLOW
        (5, "DENY"),
        (7, "DENY"),  # step 6 is the kill switch, not a decision
    ]
    actual = [(r["step"], r["outcome"]) for r in results]
    assert actual == expected, f"demo sequence mismatch:\n  expected: {expected}\n  actual:   {actual}"

    # The captured stdout must contain the kill-switch line.
    assert "REVOKED" in captured.out

    # The captured stdout must contain the "agent never held the real key" line.
    assert "never held the real key" in captured.out.lower()


def test_demo_budget_arithmetic(fresh_env):
    """After step 1 ($20) and step 2 ($25), the budget remaining must be $5."""
    from actenon_permit._demo import run_demo
    from actenon_permit.state import get_default_store

    run_demo(auto_approve=True)

    store = get_default_store()
    grants = store.list_grants(agent_id="refund-bot")
    assert len(grants) >= 1
    g = grants[0]
    # Total ALLOWed = $20 + $25 = $45 (step 4 send_email has no cost, step 7
    # is denied before reserve). Remaining = 50 - 45 = 5.
    assert g.budget.remaining == 5.0
    assert g.status.value == "revoked"  # kill switch in step 6


def test_demo_ledger_intact(fresh_env):
    """After the demo runs, the ledger hash chain must verify."""
    from actenon_permit import Ledger
    from actenon_permit._demo import run_demo
    from actenon_permit.state import get_default_store

    run_demo(auto_approve=True)
    store = get_default_store()
    ledger = Ledger(store)
    assert ledger.verify() is True
