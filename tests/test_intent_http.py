"""End-to-end HTTP tests for the AEI developer surface (Prompt 10 follow-up).

Tests the full HTTP path: POST /intents -> GET /intents/{id} ->
POST /intents/{id}/execute. Uses FastAPI's TestClient against a
real Gateway with an adapter-backed GitHub tool registered.

Covers:
  1. POST /intents creates an intent in the 'created' lifecycle state.
  2. GET /intents/{id} returns the intent.
  3. GET /intents lists intents, optionally filtered by requester_subject.
  4. POST /intents/{id}/execute executes a brokered intent end-to-end
     and returns the Prompt-9 execution-mode fields.
  5. POST /intents/{id}/execute without X-Actenon-Grant returns 401.
  6. POST /intents/{id}/execute on a non-existent intent returns 404-equivalent.
  7. POST /intents with missing required fields returns 422.
  8. POST /intents with a forbidden metadata key (e.g. 'password') returns 400.
  9. POST /intents/{id}/execute on a denied grant transitions the intent
     to 'denied' and returns outcome=DENY.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    CredentialProviderRegistry,
    EphemeralIntentStore,
    Gateway,
    GitHubAdapter,
    IntentManager,
    Ledger,
    LocalDevSecretProvider,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit.control import create_app
from actenon_permit.model import (
    Budget,
    Grant,
    Rate,
    Scopes,
)
from actenon_permit.token import grant_to_token

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "intent_http.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield db_path
    reset_default_store()


def _make_grant(tmp_db, *, scopes_allow=("issue.create",), budget=10.0) -> Grant:
    store = SQLiteStore(str(tmp_db))
    grant = Grant(
        agent_id="intent-http-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=list(scopes_allow)),
        budget=Budget(currency="USD", limit=budget, remaining=budget),
        rate=Rate(max=10, per_seconds=60),
    )
    grant.sign()
    store.put_grant(grant)
    return grant


def _make_gateway(tmp_db) -> tuple[Gateway, str]:
    """Build a gateway with an adapter-backed GitHub tool + an intent
    manager backed by an EphemeralIntentStore. Returns (gateway, grant_token).
    """
    store = SQLiteStore(str(tmp_db))
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    cred_registry = CredentialProviderRegistry()
    cred_registry.register(
        "GITHUB_TOKEN",
        LocalDevSecretProvider({"GITHUB_TOKEN": "ghp_test_NOT_REAL_0123456789abcdef"}),
    )
    broker = Broker(pdp, credential_providers=cred_registry, production_mode=False)
    tools = ToolRegistry()
    tools.register_adapter_tool(
        "github_issue",
        action_type="issue.create",
        adapter=GitHubAdapter(test_mode=True),
        credential_ref="GITHUB_TOKEN",
        target="github",
    )
    intent_mgr = IntentManager(store=EphemeralIntentStore())
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
        intent_manager=intent_mgr,
    )
    grant = _make_grant(tmp_db)
    token = grant_to_token(grant)
    return gw, token


def _make_client(gateway: Gateway) -> TestClient:
    app = create_app(gateway=gateway)
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. POST /intents creates an intent
# ---------------------------------------------------------------------------


def test_post_intents_creates_intent_in_created_state(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)

    resp = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "actenon", "repo": "demo", "title": "via http"},
        "target_type": "github",
        "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["intent_id"].startswith("intent_")
    assert body["lifecycle_state"] == "created"
    assert body["action_type"] == "issue.create"
    assert body["requested_execution_mode"] == "brokered"
    assert body["requester_subject"] == "alice"


# ---------------------------------------------------------------------------
# 2. GET /intents/{id} returns the intent
# ---------------------------------------------------------------------------


def test_get_intent_returns_intent(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)

    create = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.get(f"/intents/{intent_id}")
    assert resp.status_code == 200
    assert resp.json()["intent_id"] == intent_id


def test_get_intent_404_for_unknown(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    resp = client.get("/intents/intent_doesnotexist")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 3. GET /intents lists intents, filtered by subject
# ---------------------------------------------------------------------------


def test_list_intents_returns_all(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t1"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t2"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "bob",
        "requester_agent_id": "bot",
    })
    resp = client.get("/intents")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert len(body["intents"]) == 2


def test_list_intents_filtered_by_subject(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t1"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t2"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "bob",
        "requester_agent_id": "bot",
    })
    resp = client.get("/intents?requester_subject=alice")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["intents"][0]["requester_subject"] == "alice"


# ---------------------------------------------------------------------------
# 4. POST /intents/{id}/execute executes a brokered intent
# ---------------------------------------------------------------------------


def test_execute_intent_succeeds_end_to_end(tmp_db):
    gw, token = _make_gateway(tmp_db)
    client = _make_client(gw)

    create = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "actenon", "repo": "demo", "title": "via http execute"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(
        f"/intents/{intent_id}/execute",
        headers={"X-Actenon-Grant": token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "ALLOW"
    assert body["execution_mode"] == "brokered"
    assert body["execution_state"] == "succeeded"
    assert body["finality"] == "final"
    assert body["provider_execution_observed"] is True
    assert body["receipt_received"] is True
    assert body["receipt_verified"] is True
    # The intent's lifecycle advanced to 'succeeded'.
    assert body["intent"]["lifecycle_state"] == "succeeded"
    # The result is the redacted provider evidence.
    assert "issue_url" in body["result"]


# ---------------------------------------------------------------------------
# 5. POST /intents/{id}/execute without X-Actenon-Grant returns 401
# ---------------------------------------------------------------------------


def test_execute_intent_without_grant_header_returns_401(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    create = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    intent_id = create.json()["intent_id"]
    resp = client.post(f"/intents/{intent_id}/execute")
    assert resp.status_code == 401
    body = resp.json()
    assert body["outcome"] == "DENY"
    assert "missing" in body["reason"].lower()


# ---------------------------------------------------------------------------
# 6. POST /intents/{id}/execute on a non-existent intent returns DENY
# ---------------------------------------------------------------------------


def test_execute_intent_unknown_returns_deny(tmp_db):
    gw, token = _make_gateway(tmp_db)
    client = _make_client(gw)
    resp = client.post(
        "/intents/intent_doesnotexist/execute",
        headers={"X-Actenon-Grant": token},
    )
    # The handler maps the 'intent not found' to outcome=DENY -> 403.
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "DENY"
    assert "not found" in body["reason"]


# ---------------------------------------------------------------------------
# 7. POST /intents with missing required fields returns 422
# ---------------------------------------------------------------------------


def test_post_intents_missing_required_field_returns_422(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    resp = client.post("/intents", json={
        # missing action_type, action_params, target_*, etc.
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    assert resp.status_code == 422
    assert "missing required field" in resp.json()["error"]


# ---------------------------------------------------------------------------
# 8. POST /intents with a forbidden metadata key returns 422
# ---------------------------------------------------------------------------


def test_post_intents_with_forbidden_metadata_returns_422(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    resp = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
        "metadata": {"password": "secret-value"},
    })
    assert resp.status_code == 422
    assert "forbidden" in resp.json()["error"].lower() or "secret" in resp.json()["error"].lower()


def test_post_intents_with_secret_prefix_value_returns_422(tmp_db):
    gw, _token = _make_gateway(tmp_db)
    client = _make_client(gw)
    resp = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
        "metadata": {"correlation_id": "ghp_abc123"},
    })
    assert resp.status_code == 422
    assert "secret" in resp.json()["error"].lower()


# ---------------------------------------------------------------------------
# 9. POST /intents/{id}/execute on a denied grant transitions to 'denied'
# ---------------------------------------------------------------------------


def test_execute_intent_with_wrong_scope_transitions_to_denied(tmp_db):
    """If the grant's scopes don't include the intent's action_type,
    the PDP denies. The intent transitions to 'denied'."""
    # Build a grant that only allows payment.refund, not issue.create.
    store = SQLiteStore(str(tmp_db))
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    cred_registry = CredentialProviderRegistry()
    cred_registry.register(
        "GITHUB_TOKEN",
        LocalDevSecretProvider({"GITHUB_TOKEN": "ghp_test_NOT_REAL"}),
    )
    broker = Broker(pdp, credential_providers=cred_registry, production_mode=False)
    tools = ToolRegistry()
    tools.register_adapter_tool(
        "github_issue",
        action_type="issue.create",
        adapter=GitHubAdapter(test_mode=True),
        credential_ref="GITHUB_TOKEN",
        target="github",
    )
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
        intent_manager=IntentManager(store=EphemeralIntentStore()),
    )
    # Grant only allows payment.refund.
    grant = Grant(
        agent_id="intent-http-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(currency="USD", limit=10.0, remaining=10.0),
        rate=Rate(max=10, per_seconds=60),
    )
    grant.sign()
    store.put_grant(grant)
    token = grant_to_token(grant)

    client = _make_client(gw)
    create = client.post("/intents", json={
        "action_type": "issue.create",  # not in grant's scopes
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    intent_id = create.json()["intent_id"]
    resp = client.post(
        f"/intents/{intent_id}/execute",
        headers={"X-Actenon-Grant": token},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "DENY"
    # The intent transitions to 'denied'.
    assert body["intent"]["lifecycle_state"] == "denied"


# ---------------------------------------------------------------------------
# 10. execute_intent with no matching adapter tool returns DENY
# ---------------------------------------------------------------------------


def test_execute_intent_no_matching_adapter_returns_deny(tmp_db):
    """If no adapter tool is registered for the intent's action_type,
    the gateway returns DENY with rule_matched='intent:no_adapter'."""
    # Build a gateway with NO tools registered.
    store = SQLiteStore(str(tmp_db))
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker,
        approval_gate=AutoApproveGate(),
        intent_manager=IntentManager(store=EphemeralIntentStore()),
    )
    grant = Grant(
        agent_id="intent-http-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["issue.create"]),
        budget=Budget(currency="USD", limit=10.0, remaining=10.0),
        rate=Rate(max=10, per_seconds=60),
    )
    grant.sign()
    store.put_grant(grant)
    token = grant_to_token(grant)

    client = _make_client(gw)
    create = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github", "target_id": "github",
        "requested_execution_mode": "brokered",
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    intent_id = create.json()["intent_id"]
    resp = client.post(
        f"/intents/{intent_id}/execute",
        headers={"X-Actenon-Grant": token},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "DENY"
    assert body["rule_matched"] == "intent:no_adapter"
