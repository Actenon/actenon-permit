"""Tests for the PDP decision engine: allow, deny-scope, deny-budget,
deny-rate, deny-expired, and fail-closed on injected error.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from actenon_permit import (
    PDP,
    Budget,
    DecisionOutcome,
    Grant,
    GrantStatus,
    Ledger,
    Rate,
    Scopes,
    SQLiteStore,
)
from actenon_permit.model import Action


def _make_grant(
    *,
    budget_limit: float = 50.0,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    rate_max: int = 0,
    rate_per: int = 60,
    approval_rules: list[str] | None = None,
    expires_in_seconds: int = 3600,
    status: GrantStatus = GrantStatus.ACTIVE,
) -> Grant:
    g = Grant(
        agent_id="test-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_seconds),
        scopes=Scopes(allow=allow or [], deny=deny or []),
        budget=Budget(currency="USD", limit=budget_limit, remaining=budget_limit),
        rate=Rate(max=rate_max, per_seconds=rate_per),
        approval_rules=approval_rules or [],
        status=status,
    )
    g.sign()
    return g


def _make_action(grant: Grant, *, type: str, amount: float | None = None, **params) -> Action:
    p = dict(params)
    if amount is not None:
        p["amount"] = amount
    return Action(
        grant_id=grant.id,
        type=type,
        target=type,
        params=p,
        est_cost=amount,
    )


# ---------------------------------------------------------------------------
# ALLOW
# ---------------------------------------------------------------------------


def test_allow_basic(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], budget_limit=100)
    store.put_grant(g)
    a = _make_action(g, type="payment.refund", amount=20)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.ALLOW
    assert d.reason == "allowed"


# ---------------------------------------------------------------------------
# DENY: scope (deny rule)
# ---------------------------------------------------------------------------


def test_deny_scope_deny(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.*"], deny=["payment.charge", "shell.*"])
    store.put_grant(g)
    a = _make_action(g, type="payment.charge", amount=10)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY
    assert "scope denied" in d.reason


def test_deny_scope_glob(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["*"], deny=["shell.*"])
    store.put_grant(g)
    a = _make_action(g, type="shell.exec")
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY


def test_deny_out_of_scope(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    # allow list non-empty but action type not in it
    g = _make_grant(allow=["payment.refund"])
    store.put_grant(g)
    a = _make_action(g, type="payment.charge", amount=10)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY
    assert d.reason == "out of scope"


# ---------------------------------------------------------------------------
# DENY: budget
# ---------------------------------------------------------------------------


def test_deny_budget(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], budget_limit=50)
    store.put_grant(g)
    # First $30 OK
    a1 = _make_action(g, type="payment.refund", amount=30)
    assert pdp.decide(g, a1).outcome == DecisionOutcome.ALLOW
    # Now $30 more should DENY (only $20 left)
    a2 = _make_action(g, type="payment.refund", amount=30)
    d = pdp.decide(g, a2)
    assert d.outcome == DecisionOutcome.DENY
    assert "budget" in d.reason


# ---------------------------------------------------------------------------
# DENY: rate limit
# ---------------------------------------------------------------------------


def test_deny_rate(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], budget_limit=1000, rate_max=2, rate_per=60)
    store.put_grant(g)
    a1 = _make_action(g, type="payment.refund", amount=10)
    a2 = _make_action(g, type="payment.refund", amount=10)
    a3 = _make_action(g, type="payment.refund", amount=10)
    assert pdp.decide(g, a1).outcome == DecisionOutcome.ALLOW
    assert pdp.decide(g, a2).outcome == DecisionOutcome.ALLOW
    d = pdp.decide(g, a3)
    assert d.outcome == DecisionOutcome.DENY
    assert d.reason == "rate limit"


# ---------------------------------------------------------------------------
# DENY: expired
# ---------------------------------------------------------------------------


def test_deny_expired(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], expires_in_seconds=-10)  # already expired
    store.put_grant(g)
    a = _make_action(g, type="payment.refund", amount=10)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY
    assert d.reason == "expired"
    # The grant should have been transitioned to expired in the store.
    stored = store.get_grant(g.id)
    assert stored is not None
    assert stored.status == GrantStatus.EXPIRED


# ---------------------------------------------------------------------------
# DENY: status != active
# ---------------------------------------------------------------------------


def test_deny_revoked(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], status=GrantStatus.REVOKED)
    store.put_grant(g)
    a = _make_action(g, type="payment.refund", amount=10)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY
    assert "revoked" in d.reason


# ---------------------------------------------------------------------------
# REQUIRE_APPROVAL
# ---------------------------------------------------------------------------


def test_require_approval_type_match(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["email.send"], approval_rules=["email.send"])
    store.put_grant(g)
    a = _make_action(g, type="email.send")
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.REQUIRE_APPROVAL
    assert "approval required" in d.reason


def test_require_approval_threshold(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], approval_rules=["payment.refund > 20"])
    store.put_grant(g)
    # $20 should NOT trigger approval (threshold is strict >)
    a1 = _make_action(g, type="payment.refund", amount=20)
    assert pdp.decide(g, a1).outcome == DecisionOutcome.ALLOW
    # $25 should
    a2 = _make_action(g, type="payment.refund", amount=25)
    d2 = pdp.decide(g, a2)
    assert d2.outcome == DecisionOutcome.REQUIRE_APPROVAL


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def test_fail_closed_on_engine_error(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"])
    store.put_grant(g)

    # Monkey-patch the inner decision to raise.
    def boom(*_a, **_kw):
        raise RuntimeError("simulated engine fault")

    pdp._decide_inner = boom  # type: ignore[method-assign]
    a = _make_action(g, type="payment.refund", amount=10)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY
    assert "engine error" in d.reason
    assert "failing closed" in d.reason


def test_fail_closed_on_reserve_error(tmp_db):
    """If state.reserve raises, the engine must DENY (fail-closed), not ALLOW."""
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant(allow=["payment.refund"], budget_limit=100)
    store.put_grant(g)

    def boom(*_a, **_kw):
        raise RuntimeError("simulated db fault")

    store.reserve = boom  # type: ignore[method-assign]
    a = _make_action(g, type="payment.refund", amount=10)
    d = pdp.decide(g, a)
    assert d.outcome == DecisionOutcome.DENY
    assert "engine error" in d.reason


# ---------------------------------------------------------------------------
# Attenuation
# ---------------------------------------------------------------------------


def test_attenuation_cannot_widen(tmp_db):
    g = _make_grant(allow=["payment.refund", "email.send"], budget_limit=100)
    g.sign()
    # Subset scopes + smaller budget is fine
    child = g.attenuate(scopes_allow=["payment.refund"], budget_limit=50)
    assert child.scopes.allow == ["payment.refund"]
    assert child.budget.limit == 50
    assert child.verify()
    # Widening scopes must raise
    with pytest.raises(ValueError):
        g.attenuate(scopes_allow=["payment.refund", "email.send", "shell.exec"])
    # Increasing budget must raise
    with pytest.raises(ValueError):
        g.attenuate(budget_limit=200)
    # Extending expiry must raise
    from datetime import timedelta

    with pytest.raises(ValueError):
        g.attenuate(expires_at=g.expires_at + timedelta(hours=1))


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def test_grant_signature_roundtrip(tmp_db):
    g = _make_grant(allow=["payment.refund"])
    g.sign()
    assert g.verify()
    # Tamper
    g.budget.remaining = 9999
    assert not g.verify()
