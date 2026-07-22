"""HTTP tests for POST /intents/{id}/submit (resource-owned path).

These tests prove the resource-owned submission path works end-to-end
over HTTP. The IAM stub server (Prompt 9 follow-up) is used as the
real resource boundary, so the tests exercise a real HTTP round-trip
to a resource that issues signed receipts.
"""

from __future__ import annotations

import json

import pytest
from actenon.execution import ResourceReceiptVerifier, ResourceSigningKey
from fastapi.testclient import TestClient

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    EphemeralIntentStore,
    Gateway,
    IntentManager,
    Ledger,
    ResourceOwnedSubmissionClient,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._iam_stub import IAMStubServer
from actenon_permit.control import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "submit_http.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield db_path
    reset_default_store()


@pytest.fixture
def iam_stub() -> IAMStubServer:
    stub = IAMStubServer()
    stub.start()
    yield stub
    stub.stop()


def _make_gateway_with_resource_client(tmp_db, iam_stub: IAMStubServer) -> Gateway:
    """Build a gateway with an IAM resource client registered."""
    store = SQLiteStore(str(tmp_db))
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    intent_mgr = IntentManager(store=EphemeralIntentStore())
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
        intent_manager=intent_mgr,
    )
    # Build a ResourceOwnedSubmissionClient for the IAM stub.
    verifier = ResourceReceiptVerifier()
    verifier.register_key(ResourceSigningKey(
        resource_id=iam_stub.config.resource_id,
        key_id=iam_stub.config.signing_key_id,
        secret=iam_stub.config.signing_key_secret,
    ))
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    gw.register_resource_client(iam_stub.config.resource_id, r_client)
    return gw


def _make_client(gateway: Gateway) -> TestClient:
    app = create_app(gateway=gateway)
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. POST /intents/{id}/submit succeeds with a verified receipt
# ---------------------------------------------------------------------------


def test_submit_intent_succeeded_with_verified_receipt(tmp_db, iam_stub):
    """End-to-end: create a resource-owned intent, submit it, the IAM
    stub returns a verified receipt, the response carries
    execution_state=succeeded with resource_receipt_verified=True."""
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)

    # Create the intent.
    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": iam_stub.config.resource_id,
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    assert create.status_code == 201
    intent_id = create.json()["intent_id"]

    # Submit it.
    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "proof_1", "execution_mode": "resource_owned"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "ALLOW"
    assert body["execution_mode"] == "resource_owned"
    assert body["execution_state"] == "succeeded"
    assert body["finality"] == "final"
    assert body["provider_execution_observed"] is True
    assert body["resource_receipt_received"] is True
    assert body["resource_receipt_verified"] is True
    assert body["submission_reference"] is not None
    # The intent's lifecycle advanced to 'succeeded'.
    assert body["intent"]["lifecycle_state"] == "succeeded"

    # Verify the IAM stub actually granted the role.
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{iam_stub._port}/iam/roles") as r:
        roles_data = json.loads(r.read().decode("utf-8"))
    assert any(r["subject"] == "alice" and r["role"] == "viewer" for r in roles_data["roles"])


# ---------------------------------------------------------------------------
# 2. POST /intents/{id}/submit with forged receipt -> outcome_unknown (202)
# ---------------------------------------------------------------------------


def test_submit_intent_forged_receipt_returns_outcome_unknown(tmp_db, iam_stub):
    """When the IAM stub forges its receipt, the response carries
    execution_state=outcome_unknown and status 202 (non-final)."""
    iam_stub.config.forge_receipt = True
    iam_stub.reset()
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)

    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": iam_stub.config.resource_id,
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "proof_2", "execution_mode": "resource_owned"},
    })
    # outcome_unknown -> 202 (non-final).
    assert resp.status_code == 202
    body = resp.json()
    assert body["execution_state"] == "outcome_unknown"
    assert body["resource_receipt_verified"] is False
    assert body["finality"] == "non_final"
    assert body["intent"]["lifecycle_state"] == "outcome_unknown"


# ---------------------------------------------------------------------------
# 3. POST /intents/{id}/submit with missing receipt -> 202 (non-final)
# ---------------------------------------------------------------------------


def test_submit_intent_missing_receipt_returns_outcome_unknown(tmp_db, iam_stub):
    """When the IAM stub returns succeeded but omits the receipt,
    the response is outcome_unknown (non-final, 202)."""
    iam_stub.config.omit_receipt = True
    iam_stub.reset()
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)

    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": iam_stub.config.resource_id,
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "proof_3", "execution_mode": "resource_owned"},
    })
    assert resp.status_code == 202
    body = resp.json()
    assert body["execution_state"] == "outcome_unknown"
    assert body["resource_receipt_received"] is False
    assert body["finality"] == "non_final"


# ---------------------------------------------------------------------------
# 4. POST /intents/{id}/submit on a refused resource -> 403
# ---------------------------------------------------------------------------


def test_submit_intent_refused_returns_403(tmp_db, iam_stub):
    """When the IAM stub refuses (refuse_all=True), the response is
    execution_state=refused with status 403."""
    iam_stub.config.refuse_all = True
    iam_stub.reset()
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)

    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": iam_stub.config.resource_id,
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "proof_4", "execution_mode": "resource_owned"},
    })
    assert resp.status_code == 403
    body = resp.json()
    assert body["execution_state"] == "refused"
    assert body["finality"] == "final"


# ---------------------------------------------------------------------------
# 5. POST /intents/{id}/submit with no proof -> 422
# ---------------------------------------------------------------------------


def test_submit_intent_missing_proof_returns_422(tmp_db, iam_stub):
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)
    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": iam_stub.config.resource_id,
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(f"/intents/{intent_id}/submit", json={})
    assert resp.status_code == 422
    assert "proof" in resp.json()["error"]


# ---------------------------------------------------------------------------
# 6. POST /intents/{id}/submit on unknown intent -> DENY
# ---------------------------------------------------------------------------


def test_submit_intent_unknown_returns_deny(tmp_db, iam_stub):
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)
    resp = client.post("/intents/intent_unknown/submit", json={
        "proof": {"proof_id": "p", "execution_mode": "resource_owned"},
    })
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "DENY"
    assert "not found" in body["reason"]


# ---------------------------------------------------------------------------
# 7. POST /intents/{id}/submit on a brokered intent -> DENY (mode_mismatch)
# ---------------------------------------------------------------------------


def test_submit_intent_brokered_mode_returns_mode_mismatch(tmp_db, iam_stub):
    """Submitting a brokered intent via /submit returns DENY with
    rule_matched='intent:mode_mismatch'."""
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)
    create = client.post("/intents", json={
        "action_type": "issue.create",
        "action_params": {"owner": "a", "repo": "b", "title": "t"},
        "target_type": "github",
        "target_id": "github",
        "requested_execution_mode": "brokered",  # not resource_owned
        "requester_subject": "alice",
        "requester_agent_id": "bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "p", "execution_mode": "resource_owned"},
    })
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "DENY"
    assert body["rule_matched"] == "intent:mode_mismatch"


# ---------------------------------------------------------------------------
# 8. POST /intents/{id}/submit with no resource client registered -> DENY
# ---------------------------------------------------------------------------


def test_submit_intent_no_resource_client_returns_deny(tmp_db, iam_stub):
    """When no ResourceOwnedSubmissionClient is registered for the
    intent's target_id, the response is DENY with
    rule_matched='intent:no_resource_client'."""
    # Build a gateway with NO resource clients.
    store = SQLiteStore(str(tmp_db))
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker,
        approval_gate=AutoApproveGate(),
        intent_manager=IntentManager(store=EphemeralIntentStore()),
    )
    client = _make_client(gw)

    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": "iam-control-plane-not-registered",
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    intent_id = create.json()["intent_id"]

    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "p", "execution_mode": "resource_owned"},
    })
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "DENY"
    assert body["rule_matched"] == "intent:no_resource_client"


# ---------------------------------------------------------------------------
# 9. No X-Actenon-Grant required for /submit
# ---------------------------------------------------------------------------


def test_submit_intent_does_not_require_grant_header(tmp_db, iam_stub):
    """The /submit endpoint does NOT require an X-Actenon-Grant header.
    Resource-owned mode uses the proof as authority, not a Permit grant."""
    gw = _make_gateway_with_resource_client(tmp_db, iam_stub)
    client = _make_client(gw)
    create = client.post("/intents", json={
        "action_type": "iam.grant_role",
        "action_params": {"subject": "alice", "role": "viewer"},
        "target_type": "iam",
        "target_id": iam_stub.config.resource_id,
        "requested_execution_mode": "resource_owned",
        "requester_subject": "bob",
        "requester_agent_id": "admin-bot",
    })
    intent_id = create.json()["intent_id"]

    # Note: no X-Actenon-Grant header.
    resp = client.post(f"/intents/{intent_id}/submit", json={
        "proof": {"proof_id": "p", "execution_mode": "resource_owned"},
    })
    # Should NOT return 401.
    assert resp.status_code != 401
    # Should be 200 (succeeded) since the IAM stub returns a valid receipt.
    assert resp.status_code == 200
