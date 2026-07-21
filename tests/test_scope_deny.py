"""Tests that the scope-DENY rule is actually exercised — not bypassed
by the tool-registry "unknown tool" check.

This test exists because the Phase 5 pilot had a bug: it claimed to test
scope injection (refund → charge) but the charge tool wasn't registered,
so the denial was "unknown tool" — the scope-deny rule was never reached.
This test registers the denied tool and asserts the right denial reason.
"""

from __future__ import annotations

import pytest

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    Gateway,
    Ledger,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._mock_providers import mock_stripe_charge, mock_stripe_refund
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


@pytest.fixture
def gateway_with_charge_tool(tmp_db, monkeypatch):
    """A gateway with BOTH refund and charge tools registered.

    The grant denies payment.charge by scope. This means a charge call
    must be denied by the PDP's scope-DENY rule (reason="scope denied"),
    NOT by the tool-registry check (reason="unknown tool").
    """
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "scope-deny-test-key")

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
        real_call=lambda secret, amount, reason="": mock_stripe_refund(secret, amount, reason),
    )
    tools.register(
        "charge",
        action_type="payment.charge",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description),
    )
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )

    # Grant: allow refund, DENY charge
    grant = compile_policy({
        "agent": "scope-deny-test-agent",
        "ttl": "15m",
        "budget": {"currency": "USD", "limit": 500},
        "scopes": {"allow": ["payment.refund"], "deny": ["payment.charge"]},
    })
    store.put_grant(grant)
    token = grant_to_token(grant)
    return gw, grant, token


def test_denied_scope_rejected_by_scope_rule_not_unknown_tool(gateway_with_charge_tool):
    """A charge call on a grant that denies payment.charge must be denied
    with reason 'scope denied', NOT 'unknown tool'.

    This is the test that catches the Phase 5 pilot bug: if the charge
    tool isn't registered, the denial is 'unknown tool' and the scope-deny
    rule is never exercised. With the tool registered, the PDP's deny-scope
    check must fire.
    """
    gw, grant, token = gateway_with_charge_tool
    result = gw.call_tool("charge", {"amount": 100}, token)

    assert result["outcome"] == "DENY", f"charge must be denied, got {result['outcome']}"
    assert "scope denied" in result["reason"], (
        f"charge must be denied by the scope-DENY rule, not 'unknown tool'. "
        f"got reason: {result['reason']!r}"
    )
    assert result.get("rule_matched", "").startswith("deny:"), (
        f"rule_matched should be 'deny:payment.charge', got {result.get('rule_matched')!r}"
    )


def test_allowed_scope_still_works(gateway_with_charge_tool):
    """The refund tool (allowed scope) still works — the deny rule only
    blocks charge, not everything."""
    gw, grant, token = gateway_with_charge_tool
    result = gw.call_tool("refund", {"amount": 50}, token)
    assert result["outcome"] == "ALLOW"


def test_unknown_tool_still_denied_separately(gateway_with_charge_tool):
    """An actually-unknown tool (not registered) is still denied — but
    with 'unknown tool', not 'scope denied'. This proves the two checks
    are distinct and both work."""
    gw, grant, token = gateway_with_charge_tool
    result = gw.call_tool("delete_database", {}, token)
    assert result["outcome"] == "DENY"
    assert "unknown tool" in result["reason"]
