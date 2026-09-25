"""Adversarial regression tests from the 2026-09 ecosystem audit.

Each test is an attack that SUCCEEDED against main before the matching fix.
A test passes when the attack is blocked (fail closed).
"""

from __future__ import annotations

import contextlib
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


# ---------------------------------------------------------------------------
# Revocation must reach every descendant of a revoked grant
# ---------------------------------------------------------------------------


def _gateway_with_refund_tool(store):
    from actenon_permit import AutoApproveGate, Broker, Gateway, ToolRegistry
    from actenon_permit._mock_providers import mock_stripe_refund

    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    tools = ToolRegistry()
    tools.register(
        "refund",
        action_type="payment.refund",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="r": mock_stripe_refund(secret, amount, reason),
    )
    gw = Gateway(
        state=store,
        ledger=ledger,
        pdp=pdp,
        broker=Broker(pdp),
        tools=tools,
        approval_gate=AutoApproveGate(),
    )
    return gw, ledger, pdp


class TestRevocationCascade:
    def test_http_revoke_reaches_grandchildren(self, tmp_db):
        from fastapi.testclient import TestClient

        from actenon_permit.control import create_app
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, ledger, pdp = _gateway_with_refund_tool(store)
        client = TestClient(
            create_app(
                state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False
            )
        )
        root = _grant(budget=Budget(currency="USD", limit=100, remaining=100))
        store.put_grant(root)
        child = client.post(f"/grants/{root.id}/attenuate", json={"budget_limit": 50}).json()
        grandchild = client.post(
            f"/grants/{child['id']}/attenuate", json={"budget_limit": 20}
        ).json()
        gc_token = grant_to_token(store.get_grant(grandchild["id"]))
        assert gw.call_tool("refund", {"amount": 1}, gc_token)["outcome"] == "ALLOW"

        assert client.post(f"/grants/{root.id}/revoke").status_code == 200

        result = gw.call_tool("refund", {"amount": 1}, gc_token)
        assert result["outcome"] == "DENY", result
        assert store.get_grant(grandchild["id"]).status.value == "revoked"

    def test_kill_switch_by_agent_reaches_delegated_children(self, tmp_db):
        """`permit revoke <agent>` only flips the agent's own grants; a child
        attenuated to another agent id must still stop working."""
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        root = _grant()
        store.put_grant(root)
        child = root.attenuate(agent_id="sub-agent", budget_limit=10)
        store.put_grant(child)
        token = grant_to_token(child)
        assert gw.call_tool("refund", {"amount": 1}, token)["outcome"] == "ALLOW"

        from actenon_permit.model import GrantStatus

        store.set_status(root.id, GrantStatus.REVOKED)  # what `permit revoke` does

        result = gw.call_tool("refund", {"amount": 1}, token)
        assert result["outcome"] == "DENY", result


# ---------------------------------------------------------------------------
# A cost field that is not a plain number must not reserve $0
# ---------------------------------------------------------------------------


class TestCostTypeConfusion:
    @pytest.mark.parametrize("amount", ["40", "4e1", None, [40], {"value": 40}, True])
    def test_gateway_non_numeric_amount_is_refused(self, tmp_db, amount):
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        token = grant_to_token(grant)
        result = gw.call_tool("refund", {"amount": amount}, token)
        assert result["outcome"] == "DENY", result
        assert store.get_grant(grant.id).budget.remaining == 50

    def test_gateway_string_amounts_cannot_exceed_budget(self, tmp_db):
        """Before the fix: three $40 refunds against a $50 budget, all
        ALLOWed, budget still $50."""
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        token = grant_to_token(grant)
        outcomes = [gw.call_tool("refund", {"amount": "40"}, token)["outcome"] for _ in range(3)]
        assert outcomes.count("ALLOW") == 0, outcomes

    @pytest.mark.parametrize("amount", [float("nan"), float("inf")])
    def test_gateway_non_finite_amount_is_refused(self, tmp_db, amount):
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        result = gw.call_tool("refund", {"amount": amount}, grant_to_token(grant))
        assert result["outcome"] == "DENY", result

    def test_guard_decimal_amount_is_charged_not_ignored(self, tmp_db, monkeypatch):
        from decimal import Decimal

        from actenon_permit import Broker
        from actenon_permit.enforce import GuardRegistry, guard

        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        store = SQLiteStore()
        pdp = PDP(store, Ledger(store))
        reg = GuardRegistry(store, pdp, Broker(pdp))
        grant = _grant()
        store.put_grant(grant)
        reg.set_grant(grant.id)
        paid = []

        @guard(
            "payment.refund", cost_from="amount", credential_name="MOCK_STRIPE_KEY", registry=reg
        )
        def refund(secret, amount):
            paid.append(amount)
            return {"status": "ok"}

        from actenon_permit.pdp import PermitDenied

        for _ in range(3):
            with contextlib.suppress(PermitDenied):
                refund(amount=Decimal("40"))
        assert sum(paid) <= 50, paid

    def test_guard_string_amount_is_refused(self, tmp_db, monkeypatch):
        from actenon_permit import Broker
        from actenon_permit.enforce import GuardRegistry, guard
        from actenon_permit.pdp import PermitDenied

        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        store = SQLiteStore()
        pdp = PDP(store, Ledger(store))
        reg = GuardRegistry(store, pdp, Broker(pdp))
        grant = _grant()
        store.put_grant(grant)
        reg.set_grant(grant.id)

        @guard(
            "payment.refund", cost_from="amount", credential_name="MOCK_STRIPE_KEY", registry=reg
        )
        def refund(secret, amount):
            return {"status": "ok"}

        with pytest.raises(PermitDenied):
            refund(amount="40")
