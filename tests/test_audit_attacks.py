"""Adversarial regression tests from the 2026-09 ecosystem audit.

Each test is an attack that SUCCEEDED against main before the matching fix.
A test passes when the attack is blocked (fail closed).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from actenon_permit import PDP, Ledger, SQLiteStore
from actenon_permit.model import Action, Budget, DecisionOutcome, Grant, Rate, Scopes


def _grant(**overrides) -> Grant:
    fields = {
        "agent_id": "audit-agent",
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
        "scopes": Scopes(allow=["payment.refund"], deny=["shell.*"]),
        "budget": Budget(currency="USD", limit=50, remaining=50),
        "rate": Rate(max=5, per_seconds=60),
    }
    fields.update(overrides)
    return Grant(**fields).sign()


@pytest.fixture
def stack(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    return store, PDP(store, ledger)


# ---------------------------------------------------------------------------
# Attenuation must never widen (SPEC §6: "strictly weaker on every dimension")
# ---------------------------------------------------------------------------


class TestAttenuationCannotWiden:
    def test_empty_allow_list_is_not_a_subset(self, stack):
        """scopes_allow=[] means "allow everything not denied" (SPEC §4), so
        an empty child allow-list of a scoped parent is a widening."""
        store, pdp = stack
        parent = _grant()
        with pytest.raises(ValueError):
            child = parent.attenuate(scopes_allow=[])
            # Before the fix the child was accepted and could do anything:
            store.put_grant(child)
            action = Action(
                grant_id=child.id, type="payment.charge", params={"amount": 5}, est_cost=5
            )
            assert pdp.decide(child, action).outcome != DecisionOutcome.ALLOW

    def test_rate_max_zero_does_not_remove_rate_limit(self):
        """rate.max=0 disables rate limiting (SPEC §2), so it is the widest
        possible value, not the narrowest."""
        parent = _grant(rate=Rate(max=5, per_seconds=60))
        with pytest.raises(ValueError):
            parent.attenuate(rate_max=0)

    def test_negative_rate_max_rejected(self):
        parent = _grant(rate=Rate(max=5, per_seconds=60))
        with pytest.raises(ValueError):
            parent.attenuate(rate_max=-1)

    def test_legitimate_narrowing_still_allowed(self):
        parent = _grant(scopes=Scopes(allow=["payment.refund", "email.send"], deny=[]))
        child = parent.attenuate(scopes_allow=["payment.refund"], rate_max=2, budget_limit=10)
        assert child.scopes.allow == ["payment.refund"]
        assert child.rate.max == 2
        assert child.verify()

    def test_unlimited_parent_may_add_a_rate_limit(self):
        parent = _grant(rate=Rate(max=0, per_seconds=60))
        child = parent.attenuate(rate_max=3)
        assert child.rate.max == 3
