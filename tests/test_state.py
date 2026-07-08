"""Concurrency test: two parallel refunds that together exceed the budget
must not both clear. Exactly one must be DENIED.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from actenon_permit import (
    PDP,
    Budget,
    Grant,
    GrantStatus,
    Ledger,
    Rate,
    Scopes,
    SQLiteStore,
)
from actenon_permit.model import Action


def _make_grant(budget_limit: float = 50.0) -> Grant:
    g = Grant(
        agent_id="concurrent-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(currency="USD", limit=budget_limit, remaining=budget_limit),
        rate=Rate(max=0, per_seconds=60),
    )
    g.sign()
    return g


def test_concurrent_refunds_cannot_both_clear_budget(tmp_db):
    """Two $30 refunds against a $50 budget: exactly one ALLOW, one DENY."""
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(budget_limit=50.0)
    store.put_grant(g)

    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt(amount: float) -> str:
        a = Action(
            grant_id=g.id,
            type="payment.refund",
            target="stripe",
            params={"amount": amount},
            est_cost=amount,
        )
        d = pdp.decide(g, a)
        with lock:
            outcomes.append(d.outcome.value)
        return d.outcome.value

    # Fire two parallel $30 refunds. Together they total $60 against a $50
    # budget — only one can possibly clear.
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(attempt, 30.0)
        f2 = ex.submit(attempt, 30.0)
        f1.result()
        f2.result()

    assert len(outcomes) == 2
    allow_count = outcomes.count("ALLOW")
    deny_count = outcomes.count("DENY")
    assert allow_count == 1, f"expected exactly 1 ALLOW, got {outcomes}"
    assert deny_count == 1, f"expected exactly 1 DENY, got {outcomes}"

    # The grant's remaining budget must be exactly 20 (50 - 30), not negative.
    stored = store.get_grant(g.id)
    assert stored is not None
    assert stored.budget.remaining == pytest.approx(20.0)


def test_concurrent_high_parallelism_does_not_overspend(tmp_db):
    """Fire 10 parallel $10 refunds against a $50 budget. The sum of ALLOWs
    must not exceed $50; the budget must never go negative.
    """
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(budget_limit=50.0)
    store.put_grant(g)

    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt():
        a = Action(
            grant_id=g.id,
            type="payment.refund",
            target="stripe",
            params={"amount": 10.0},
            est_cost=10.0,
        )
        d = pdp.decide(g, a)
        with lock:
            outcomes.append(d.outcome.value)
        return d.outcome.value

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda _: attempt(), range(10)))

    allow_count = outcomes.count("ALLOW")
    assert allow_count == 5, f"expected 5 ALLOWs (50/10), got {allow_count}: {outcomes}"
    assert outcomes.count("DENY") == 5

    stored = store.get_grant(g.id)
    assert stored is not None
    assert stored.budget.remaining == pytest.approx(0.0)
    assert stored.status == GrantStatus.EXHAUSTED
