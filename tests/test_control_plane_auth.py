"""The control plane requires the admin token; the agent-facing gateway does not.

Before this, every control-plane route was unauthenticated and served on the
same port as /proxy and /intents, so an agent holding only its grant token
could issue itself a new unlimited grant (POST /grants), mint bearer tokens
for any grant, approve its own pending approvals, and read every grant's
signature (GET /grants), which is all a bearer token contains.
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from fastapi.testclient import TestClient

from actenon_permit import PDP, AutoApproveGate, Broker, Gateway, Ledger, SQLiteStore, ToolRegistry
from actenon_permit._mock_providers import mock_stripe_refund
from actenon_permit.control import create_app
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token

ADMIN = "test-admin-token-0123456789abcdef"

# Every route the app serves, classified. A new route fails this test until
# it is classified here.
ADMIN_ROUTES = {
    ("POST", "/grants"),
    ("GET", "/grants"),
    ("GET", "/grants/{grant_id}"),
    ("POST", "/grants/{grant_id}/revoke"),
    ("POST", "/grants/{grant_id}/attenuate"),
    ("POST", "/grants/{grant_id}/token"),
    ("GET", "/approvals"),
    ("POST", "/approvals/{action_id}/approve"),
    ("POST", "/approvals/{action_id}/deny"),
    ("GET", "/approvals/stream"),
    ("GET", "/ledger"),
    ("GET", "/ledger/verify"),
}
AGENT_ROUTES = {  # authenticated by the grant token (or the proof) per call
    ("GET", "/proxy/tools"),
    ("POST", "/proxy/{tool_name}"),
    ("POST", "/intents"),
    ("GET", "/intents"),
    ("GET", "/intents/{intent_id}"),
    ("POST", "/intents/{intent_id}/execute"),
    ("POST", "/intents/{intent_id}/submit"),
}
PUBLIC_ROUTES = {("GET", "/health")}
FRAMEWORK_ROUTES = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

POLICY = {
    "agent": "refund-bot",
    "ttl": "1h",
    "budget": {"currency": "USD", "limit": 50},
    "scopes": {"allow": ["payment.refund"], "deny": []},
    "approval": {"require_human": []},
}


@pytest.fixture
def stack(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
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
    grant = compile_policy(POLICY)
    store.put_grant(grant)
    return store, ledger, pdp, gw, grant


def _app(stack, admin_token=ADMIN):
    store, ledger, pdp, gw, _ = stack
    return create_app(
        state=store,
        ledger=ledger,
        pdp=pdp,
        gateway=gw,
        wire_gateway_approvals=False,
        admin_token=admin_token,
    )


def _concrete(path: str, grant_id: str) -> str:
    return (
        path.replace("{grant_id}", grant_id)
        .replace("{action_id}", "act_x")
        .replace("{tool_name}", "refund")
        .replace("{intent_id}", "intent_x")
    )


def test_every_route_is_classified(stack):
    app = _app(stack)
    served = {
        (method, route.path)
        for route in app.routes
        if route.path not in FRAMEWORK_ROUTES
        for method in getattr(route, "methods", ()) - {"HEAD"}
    }
    assert served == ADMIN_ROUTES | AGENT_ROUTES | PUBLIC_ROUTES


@pytest.mark.parametrize(("method", "path"), sorted(ADMIN_ROUTES))
def test_admin_routes_refuse_without_token(stack, method, path):
    grant = stack[4]
    client = TestClient(_app(stack))
    url = _concrete(path, grant.id)
    body = {"policy": POLICY} if path == "/grants" and method == "POST" else {}
    missing = client.request(method, url, json=body)
    assert missing.status_code == 401, missing.text
    wrong = client.request(method, url, json=body, headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 403, wrong.text
    basic = client.request(method, url, json=body, headers={"Authorization": f"Basic {ADMIN}"})
    assert basic.status_code == 401, basic.text


@pytest.mark.parametrize(("method", "path"), sorted(ADMIN_ROUTES))
def test_admin_routes_fail_closed_when_no_token_is_configured(stack, method, path):
    grant = stack[4]
    client = TestClient(_app(stack, admin_token=None))
    url = _concrete(path, grant.id)
    for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Bearer None"}):
        assert client.request(method, url, json={}, headers=headers).status_code in (401, 403)


def test_agent_without_admin_token_cannot_escalate(stack):
    """The attack: an agent with only its grant token talks to the same port."""
    store, _, _, _, grant = stack
    agent = TestClient(_app(stack), headers={"X-Actenon-Grant": grant_to_token(grant)})
    rich = {**POLICY, "agent": "attacker", "budget": {"currency": "USD", "limit": 10**9}}
    assert agent.post("/grants", json={"policy": rich}).status_code == 401
    assert agent.post(f"/grants/{grant.id}/token").status_code == 401
    assert agent.post("/approvals/act_x/approve").status_code == 401
    listing = agent.get("/grants")
    assert listing.status_code == 401
    assert grant.signature not in listing.text
    assert len(store.list_grants()) == 1
    # The legitimate agent path is unchanged.
    assert agent.post("/proxy/refund", json={"amount": 5}).status_code == 200


def test_operator_with_admin_token_can_do_everything(stack):
    grant = stack[4]
    admin = TestClient(_app(stack), headers={"Authorization": f"Bearer {ADMIN}"})
    issued = admin.post("/grants", json={"policy": POLICY})
    assert issued.status_code == 200
    assert admin.get("/grants").status_code == 200
    assert admin.post(f"/grants/{grant.id}/token").json()["token"].startswith("v1.")
    child = admin.post(f"/grants/{grant.id}/attenuate", json={"budget_limit": 5})
    assert child.status_code == 200
    assert admin.post(f"/grants/{grant.id}/revoke").status_code == 200
    assert admin.get("/ledger/verify").json() == {"ok": True}
    assert admin.get("/health").status_code == 200


def test_token_comparison_is_constant_time(stack, monkeypatch):
    import hmac as hmac_module

    from actenon_permit import control

    calls = []
    real = hmac_module.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(control.hmac, "compare_digest", spy)
    client = TestClient(_app(stack))
    client.get("/grants", headers={"Authorization": "Bearer wrong"})
    assert calls


def test_generated_admin_token_file_is_private(tmp_path, monkeypatch):
    from actenon_permit.control import load_or_create_admin_token, read_admin_token

    monkeypatch.delenv("ACTENON_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("ACTENON_ADMIN_TOKEN_FILE", raising=False)
    token, path = load_or_create_admin_token(state_dir=tmp_path)
    assert path == tmp_path / "admin-token"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert len(bytes.fromhex(token)) == 32
    assert path.read_text().strip() == token
    # Clients find it without being told the token.
    assert read_admin_token(state_dir=tmp_path) == token
    # A second start rotates it; the file stays 0600.
    token2, _ = load_or_create_admin_token(state_dir=tmp_path)
    assert token2 != token and stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_admin_token_sources_in_order(tmp_path, monkeypatch):
    from actenon_permit.control import load_or_create_admin_token

    f = tmp_path / "given"
    f.write_text("from-file\n")
    monkeypatch.setenv("ACTENON_ADMIN_TOKEN", "from-env")
    assert load_or_create_admin_token(token_file=f, state_dir=tmp_path) == ("from-file", f)
    monkeypatch.setenv("ACTENON_ADMIN_TOKEN_FILE", str(f))
    assert load_or_create_admin_token(state_dir=tmp_path)[0] == "from-file"
    monkeypatch.delenv("ACTENON_ADMIN_TOKEN_FILE")
    assert load_or_create_admin_token(state_dir=tmp_path) == ("from-env", None)
    (tmp_path / "empty").write_text("\n")
    with pytest.raises(ValueError):
        load_or_create_admin_token(token_file=tmp_path / "empty", state_dir=tmp_path)


def test_serve_never_prints_the_token(tmp_path, monkeypatch, capsys):
    from actenon_permit import cli

    monkeypatch.delenv("ACTENON_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("ACTENON_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    captured = {}
    monkeypatch.setattr(cli, "_run_uvicorn", lambda app, host, port: captured.update(app=app))
    cli.serve(host="127.0.0.1", port=0, with_gateway=False, admin_token_file=None)
    token = (tmp_path / ".actenon-permit" / "admin-token").read_text().strip()
    out = capsys.readouterr()
    assert token not in out.out + out.err
    assert "admin-token" in out.err
    client = TestClient(captured["app"])
    assert client.get("/grants").status_code == 401
    assert client.get("/grants", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert json.loads(client.get("/health").text) == {"status": "ok"}
