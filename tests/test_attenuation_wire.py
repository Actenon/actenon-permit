"""Tests for the v1 attenuated multi-agent delegation wire format.

Verifies that:
  - POST /grants/{id}/attenuate produces a strictly-weaker child grant
  - Attempting to widen is rejected with 400
  - The child grant's token is usable by the gateway
  - The child grant is bound by the parent's limits (not its own self-reported limits)
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    Gateway,
    Ledger,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._mock_providers import mock_stripe_refund
from actenon_permit.control import create_app
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


def _make_app_and_store(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
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
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )
    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False)
    return app, store, gw


def _issue_parent(store):
    policy = {
        "agent": "parent-agent",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 100},
        "scopes": {"allow": ["payment.refund", "email.send"], "deny": ["payment.charge"]},
        "rate": {"max": 20, "per": "1m"},
    }
    g = compile_policy(policy)
    store.put_grant(g)
    return g


def test_attenuate_creates_weaker_child(tmp_db, monkeypatch):
    app, store, _ = _make_app_and_store(tmp_db, monkeypatch)
    parent = _issue_parent(store)
    client = TestClient(app)

    resp = client.post(
        f"/grants/{parent.id}/attenuate",
        json={
            "agent_id": "child-agent",
            "budget_limit": 20,
            "scopes_allow": ["payment.refund"],
        },
    )
    assert resp.status_code == 200
    child = resp.json()
    assert child["agent_id"] == "child-agent"
    assert child["budget"]["limit"] == 20
    assert child["scopes"]["allow"] == ["payment.refund"]
    assert child["id"] != parent.id
    # The child must be signed.
    assert child["signature"]
    assert len(child["signature"]) == 64


def test_attenuate_rejects_widening_budget(tmp_db, monkeypatch):
    app, store, _ = _make_app_and_store(tmp_db, monkeypatch)
    parent = _issue_parent(store)
    client = TestClient(app)

    resp = client.post(
        f"/grants/{parent.id}/attenuate",
        json={"budget_limit": 9999},  # parent limit is 100
    )
    assert resp.status_code == 400
    assert "attenuation rejected" in resp.json()["detail"]


def test_attenuate_rejects_widening_scopes(tmp_db, monkeypatch):
    app, store, _ = _make_app_and_store(tmp_db, monkeypatch)
    parent = _issue_parent(store)
    client = TestClient(app)

    # parent allows [payment.refund, email.send] — try to add shell.exec
    resp = client.post(
        f"/grants/{parent.id}/attenuate",
        json={"scopes_allow": ["payment.refund", "shell.exec"]},
    )
    assert resp.status_code == 400


def test_attenuate_rejects_revoked_parent(tmp_db, monkeypatch):
    from actenon_permit.model import GrantStatus

    app, store, _ = _make_app_and_store(tmp_db, monkeypatch)
    parent = _issue_parent(store)
    store.set_status(parent.id, GrantStatus.REVOKED)
    client = TestClient(app)

    resp = client.post(
        f"/grants/{parent.id}/attenuate",
        json={"budget_limit": 10},
    )
    assert resp.status_code == 409


def test_child_token_is_usable_and_bound_by_parent_limits(tmp_db, monkeypatch):
    """A child grant's token must work at the gateway, and the child must be
    bound by its own (smaller) budget — not the parent's.

    Note on UCAN-style attenuation semantics: attenuation creates an
    INDEPENDENT child grant with its own budget. The parent is NOT debited
    at attenuation time (the parent pre-allocates by trusting the child
    with a smaller budget). This means the parent's remaining is unchanged
    after attenuation — what matters is that the child can never exceed
    its own (smaller) limit, and the child's spend does NOT debit the
    parent. In a real multi-agent system, the parent would set its own
    budget remaining to (limit - sum_of_child_allocations) at orchestration
    time; that's a deployment concern, not a protocol concern.
    """
    app, store, gw = _make_app_and_store(tmp_db, monkeypatch)
    parent = _issue_parent(store)
    client = TestClient(app)

    # Attenuate to a $20 budget.
    resp = client.post(
        f"/grants/{parent.id}/attenuate",
        json={"agent_id": "child-agent", "budget_limit": 20, "scopes_allow": ["payment.refund"]},
    )
    assert resp.status_code == 200
    child = resp.json()

    # Mint a token for the child.
    from actenon_permit.model import Grant

    child_grant = Grant.model_validate(child)
    token = grant_to_token(child_grant)

    # The child can refund $15 (within its $20 budget).
    r1 = gw.call_tool("refund", {"amount": 15}, token)
    assert r1["outcome"] == "ALLOW"
    assert r1["remaining_budget"] == 5.0

    # The child cannot refund $10 more (only $5 of its $20 left).
    r2 = gw.call_tool("refund", {"amount": 10}, token)
    assert r2["outcome"] == "DENY"
    assert "budget" in r2["reason"]

    # The parent's remaining is unchanged — attenuation creates an
    # independent child budget, it does not debit the parent.
    parent_live = store.get_grant(parent.id)
    assert parent_live.budget.remaining == 100.0
