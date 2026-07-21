"""Tests for the v1 out-of-process PEP gateway.

These tests exercise the gateway directly (no HTTP) and via the FastAPI
proxy (with TestClient). The end-to-end HTTP test using the remote PEP
client is in test_remote_pep.py.
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
from actenon_permit._mock_providers import mock_send_email, mock_stripe_charge, mock_stripe_refund
from actenon_permit.control import create_app
from actenon_permit.model import Grant, GrantStatus
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


def _make_grant() -> Grant:
    policy = {
        "agent": "gw-test-agent",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 50},
        "scopes": {
            "allow": ["payment.refund", "email.send"],
            "deny": ["payment.charge", "shell.*"],
        },
        "rate": {"max": 20, "per": "1m"},
        "approval": {"require_human": ["email.send"]},
    }
    return compile_policy(policy)


def _make_gateway(store: SQLiteStore, ledger: Ledger, pdp: PDP) -> Gateway:
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
    return Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )


# ---------------------------------------------------------------------------
# Direct (no HTTP) gateway tests
# ---------------------------------------------------------------------------


def test_gateway_allow(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    result = gw.call_tool("refund", {"amount": 20, "reason": "customer"}, token)
    assert result["outcome"] == "ALLOW"
    assert result["result"]["amount"] == 20
    assert result["remaining_budget"] == 30.0


def test_gateway_deny_budget(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    # $30 OK
    r1 = gw.call_tool("refund", {"amount": 30}, token)
    assert r1["outcome"] == "ALLOW"
    # $30 more -> DENY (only $20 left)
    r2 = gw.call_tool("refund", {"amount": 30}, token)
    assert r2["outcome"] == "DENY"
    assert "budget" in r2["reason"]


def test_gateway_deny_scope(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    r = gw.call_tool("charge", {"amount": 100}, token)
    assert r["outcome"] == "DENY"
    assert "scope denied" in r["reason"]


def test_gateway_approval_then_allow(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    # send_email -> REQUIRE_APPROVAL -> (auto-approve) -> ALLOW
    r = gw.call_tool("send_email", {"to": "x@y.com", "subject": "hi"}, token)
    assert r["outcome"] == "ALLOW"
    assert "sent" in str(r["result"])


def test_gateway_unknown_tool(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    r = gw.call_tool("no_such_tool", {}, token)
    assert r["outcome"] == "DENY"
    assert "unknown tool" in r["reason"]


def test_gateway_invalid_token(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)

    r = gw.call_tool("refund", {"amount": 20}, "v1.not-a-valid-token")
    assert r["outcome"] == "DENY"
    assert "invalid grant token" in r["reason"]


def test_gateway_revoked_grant(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    # Revoke, then try to call.
    store.set_status(grant.id, GrantStatus.REVOKED)
    r = gw.call_tool("refund", {"amount": 1}, token)
    assert r["outcome"] == "DENY"
    assert "revoked" in r["reason"]


# ---------------------------------------------------------------------------
# HTTP proxy tests (FastAPI TestClient)
# ---------------------------------------------------------------------------


def test_http_proxy_allow(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False)
    client = TestClient(app)

    resp = client.post(
        "/proxy/refund",
        json={"amount": 20, "reason": "customer"},
        headers={"X-Actenon-Grant": token},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["outcome"] == "ALLOW"
    assert payload["result"]["amount"] == 20


def test_http_proxy_deny_403(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False)
    client = TestClient(app)

    # charge -> DENY (scope)
    resp = client.post(
        "/proxy/charge",
        json={"amount": 100},
        headers={"X-Actenon-Grant": token},
    )
    assert resp.status_code == 403
    payload = resp.json()
    assert payload["outcome"] == "DENY"


def test_http_proxy_missing_grant_header(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)

    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False)
    client = TestClient(app)

    resp = client.post("/proxy/refund", json={"amount": 20})
    assert resp.status_code == 401  # missing header -> 401, not 403


def test_http_proxy_list_tools(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)

    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False)
    client = TestClient(app)

    resp = client.get("/proxy/tools")
    assert resp.status_code == 200
    tools = resp.json()["tools"]
    assert "refund" in tools
    assert "charge" in tools
    assert "send_email" in tools


# ---------------------------------------------------------------------------
# MCP stdio tests
# ---------------------------------------------------------------------------


def test_mcp_stdio_tools_list(tmp_db, monkeypatch):
    import io
    import json as json_mod

    from actenon_permit.gateway import mcp_serve

    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)

    infile = io.StringIO(json_mod.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
    outfile = io.StringIO()
    mcp_serve(gw, infile=infile, outfile=outfile)

    outfile.seek(0)
    response = json_mod.loads(outfile.readline())
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    tool_names = [t["name"] for t in response["result"]["tools"]]
    assert "refund" in tool_names
    assert "charge" in tool_names


def test_mcp_stdio_tools_call_allow(tmp_db, monkeypatch):
    import io
    import json as json_mod

    from actenon_permit.gateway import mcp_serve

    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "refund",
            "arguments": {"amount": 20},
            "_meta": {"actenon_grant": token},
        },
    }
    infile = io.StringIO(json_mod.dumps(req) + "\n")
    outfile = io.StringIO()
    mcp_serve(gw, infile=infile, outfile=outfile)

    outfile.seek(0)
    response = json_mod.loads(outfile.readline())
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    assert response["result"]["isError"] is False
    # The result content is a list of {type: text, text: json-string}
    text = response["result"]["content"][0]["text"]
    parsed = json_mod.loads(text)
    assert parsed["amount"] == 20


def test_mcp_stdio_tools_call_deny(tmp_db, monkeypatch):
    import io
    import json as json_mod

    from actenon_permit.gateway import mcp_serve

    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)
    grant = _make_grant()
    store.put_grant(grant)
    token = grant_to_token(grant)

    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "charge",
            "arguments": {"amount": 100},
            "_meta": {"actenon_grant": token},
        },
    }
    infile = io.StringIO(json_mod.dumps(req) + "\n")
    outfile = io.StringIO()
    mcp_serve(gw, infile=infile, outfile=outfile)

    outfile.seek(0)
    response = json_mod.loads(outfile.readline())
    assert response["result"]["isError"] is True
    assert "DENY" in response["result"]["content"][0]["text"]


def test_mcp_stdio_missing_grant_meta(tmp_db, monkeypatch):
    import io
    import json as json_mod

    from actenon_permit.gateway import mcp_serve

    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = _make_gateway(store, ledger, pdp)

    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "refund", "arguments": {"amount": 20}},
    }
    infile = io.StringIO(json_mod.dumps(req) + "\n")
    outfile = io.StringIO()
    mcp_serve(gw, infile=infile, outfile=outfile)

    outfile.seek(0)
    response = json_mod.loads(outfile.readline())
    assert "error" in response
    assert "actenon_grant" in response["error"]["message"]
