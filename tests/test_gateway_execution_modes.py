"""End-to-end tests for the gateway adapter-backed path + IAM
resource-owned reference (Prompt 9 follow-up).

These tests prove:

  1. The gateway's adapter-backed tool path produces a
     ModeAwareExecutionResult with the full Prompt-9 receipt fields
     when invoked via ``Gateway.call_tool``.
  2. The IAM stub server (a real, non-trivial resource boundary)
     correctly issues signed receipts that the Permit-side
     ResourceOwnedSubmissionClient cryptographically verifies.
  3. Forged receipts from the IAM stub are forced to outcome_unknown.
  4. Missing receipts from the IAM stub remain non-final.
  5. A refused IAM submission maps to state=refused.

These tests are the integration layer above the unit tests in
``test_execution_modes.py``: they exercise the full HTTP path
through the IAM stub server, not a monkeypatched urllib.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from actenon.execution import ResourceReceiptVerifier, ResourceSigningKey

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    CredentialProviderRegistry,
    Gateway,
    GitHubAdapter,
    Ledger,
    LocalDevSecretProvider,
    ResourceOwnedSubmissionClient,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._iam_stub import IAMStubServer
from actenon_permit.model import (
    Action,
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
    db_path = tmp_path / "gateway_modes.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield db_path
    reset_default_store()


def _make_grant(tmp_db, *, scopes_allow=("issue.create",), budget=10.0) -> Grant:
    store = SQLiteStore(str(tmp_db))
    grant = Grant(
        agent_id="gateway-modes-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=list(scopes_allow)),
        budget=Budget(currency="USD", limit=budget, remaining=budget),
        rate=Rate(max=10, per_seconds=60),
    )
    grant.sign()
    store.put_grant(grant)
    return grant


def _make_pdp(tmp_db) -> PDP:
    store = SQLiteStore(str(tmp_db))
    ledger = Ledger(store)
    return PDP(store, ledger)


def _make_gateway_with_adapter_tool(
    tmp_db,
    *,
    credential_value: str = "ghp_test_secret_NOT_REAL_0123456789abcdef",
    credential_ref: str = "GITHUB_TOKEN",
    action_type: str = "issue.create",
) -> tuple[Gateway, str, str]:
    """Build a gateway with an adapter-backed GitHub tool. Returns
    (gateway, tool_name, grant_token)."""
    pdp = _make_pdp(tmp_db)
    registry = CredentialProviderRegistry()
    registry.register(credential_ref, LocalDevSecretProvider({credential_ref: credential_value}))
    broker = Broker(pdp, credential_providers=registry, production_mode=False)
    tools = ToolRegistry()
    adapter = GitHubAdapter(test_mode=True)
    tools.register_adapter_tool(
        "github_issue",
        action_type=action_type,
        adapter=adapter,
        credential_ref=credential_ref,
        target="github",
    )
    gw = Gateway(
        state=SQLiteStore(str(tmp_db)),
        ledger=Ledger(SQLiteStore(str(tmp_db))),
        pdp=pdp,
        broker=broker,
        tools=tools,
        approval_gate=AutoApproveGate(),
    )
    grant = _make_grant(tmp_db, scopes_allow=[action_type])
    token = grant_to_token(grant)
    return gw, "github_issue", token


# ---------------------------------------------------------------------------
# 1. Gateway adapter-backed tool produces full Prompt-9 receipt fields
# ---------------------------------------------------------------------------


def test_gateway_adapter_tool_succeeded_carries_execution_mode_fields(tmp_db):
    """When an adapter-backed tool succeeds via the gateway, the
    response dict carries the Prompt-9 fields:
    execution_mode, execution_state, finality,
    provider_execution_observed, receipt_received, receipt_verified.
    """
    gw, tool_name, token = _make_gateway_with_adapter_tool(tmp_db)
    response = gw.call_tool(
        tool_name,
        {"owner": "actenon", "repo": "demo", "title": "via gateway"},
        token,
    )
    assert response["outcome"] == "ALLOW"
    assert response["execution_mode"] == "brokered"
    assert response["execution_state"] == "succeeded"
    assert response["finality"] == "final"
    assert response["provider_execution_observed"] is True
    assert response["receipt_received"] is True
    assert response["receipt_verified"] is True
    # The result/evidence is the redacted provider evidence
    assert "issue_url" in response["result"]


def test_gateway_adapter_tool_refused_carries_execution_mode_fields(tmp_db):
    """When an adapter-backed tool is refused (invalid params), the
    response carries execution_state=refused, finality=final,
    provider_execution_observed=False."""
    gw, tool_name, token = _make_gateway_with_adapter_tool(tmp_db)
    response = gw.call_tool(
        tool_name,
        {"owner": "actenon", "repo": "demo", "title": "t", "malicious": "x"},
        token,
    )
    assert response["outcome"] == "DENY"  # refused surfaces as DENY
    assert response["execution_mode"] == "brokered"
    assert response["execution_state"] == "refused"
    assert response["finality"] == "final"
    assert response["provider_execution_observed"] is False


def test_gateway_adapter_tool_wrong_action_type_is_refused(tmp_db):
    """If the grant scopes don't include the action_type, the PDP
    denies before the coordinator runs. The response is the standard
    DENY shape (no execution_mode fields, because the coordinator
    was never invoked)."""
    # Build gateway with action_type the grant doesn't allow.
    pdp = _make_pdp(tmp_db)
    registry = CredentialProviderRegistry()
    registry.register("GITHUB_TOKEN", LocalDevSecretProvider({"GITHUB_TOKEN": "v"}))
    broker = Broker(pdp, credential_providers=registry, production_mode=False)
    tools = ToolRegistry()
    adapter = GitHubAdapter(test_mode=True)
    tools.register_adapter_tool(
        "github_pr",
        action_type="pr.open",  # grant below only allows issue.create
        adapter=adapter,
        credential_ref="GITHUB_TOKEN",
    )
    gw = Gateway(
        state=SQLiteStore(str(tmp_db)),
        ledger=Ledger(SQLiteStore(str(tmp_db))),
        pdp=pdp,
        broker=broker,
        tools=tools,
        approval_gate=AutoApproveGate(),
    )
    grant = _make_grant(tmp_db, scopes_allow=["issue.create"])
    token = grant_to_token(grant)
    response = gw.call_tool(
        "github_pr",
        {"owner": "actenon", "repo": "demo", "title": "t", "head": "h", "base": "main"},
        token,
    )
    assert response["outcome"] == "DENY"
    # No execution_mode fields — the PDP denied before the coordinator ran.
    assert "execution_mode" not in response


def test_gateway_legacy_tool_still_works_without_execution_mode_fields(tmp_db):
    """Legacy v1 real_call tools continue to work and do NOT carry
    execution_mode fields. This proves backward compatibility."""
    from actenon_permit._mock_providers import mock_stripe_refund

    pdp = _make_pdp(tmp_db)
    import os
    os.environ["MOCK_STRIPE_KEY"] = "sk_mock_123"
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
        state=SQLiteStore(str(tmp_db)),
        ledger=Ledger(SQLiteStore(str(tmp_db))),
        pdp=pdp,
        broker=broker,
        tools=tools,
        approval_gate=AutoApproveGate(),
    )
    grant = _make_grant(tmp_db, scopes_allow=["payment.refund"], budget=50.0)
    token = grant_to_token(grant)
    response = gw.call_tool("refund", {"amount": 20, "reason": "test"}, token)
    assert response["outcome"] == "ALLOW"
    # Legacy path: no execution_mode fields.
    assert "execution_mode" not in response
    assert "execution_state" not in response


# ---------------------------------------------------------------------------
# 2. IAM resource-owned reference end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture
def iam_stub() -> IAMStubServer:
    """Start the IAM stub server on an ephemeral port."""
    stub = IAMStubServer()
    stub.start()
    yield stub
    stub.stop()


def _make_iam_verifier(stub: IAMStubServer) -> ResourceReceiptVerifier:
    """Build a ResourceReceiptVerifier with the stub's signing key."""
    v = ResourceReceiptVerifier()
    v.register_key(ResourceSigningKey(
        resource_id=stub.config.resource_id,
        key_id=stub.config.signing_key_id,
        secret=stub.config.signing_key_secret,
    ))
    return v


def _make_iam_action(subject: str = "user-alice", role: str = "viewer") -> Action:
    return Action(
        grant_id="grant_iam_test",
        type="iam.grant_role",
        target="iam-control-plane",
        params={"subject": subject, "role": role},
        est_cost=0.0,
    )


def test_iam_stub_succeeded_path_produces_verified_receipt(iam_stub):
    """End-to-end: the IAM stub returns a succeeded response with a
    cryptographically verified receipt. The Permit-side client
    produces state=succeeded, finality=final."""
    verifier = _make_iam_verifier(iam_stub)
    client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    action = _make_iam_action()
    proof = {"proof_id": "proof_iam_1", "execution_mode": "resource_owned"}
    result = client.submit(action, proof, pccb_id="pccb_iam_1", action_hash="ah_1")

    assert result.mode == "resource_owned"
    assert result.state == "succeeded"
    assert result.finality.value == "final"
    assert result.protocol_result.provider_execution_observed is True
    assert result.protocol_result.resource_receipt_received is True
    assert result.protocol_result.resource_receipt_verified is True
    assert result.resource_signing_key_id == iam_stub.config.signing_key_id

    # Confirm the stub actually granted the role.
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{iam_stub._port}/iam/roles") as resp:
        roles_data = __import__("json").loads(resp.read().decode("utf-8"))
    assert any(r["subject"] == "user-alice" and r["role"] == "viewer" for r in roles_data["roles"])


def test_iam_stub_forged_receipt_forced_to_outcome_unknown(iam_stub):
    """When the IAM stub forges its receipt (signs with the wrong key),
    the Permit-side client forces state=outcome_unknown (NOT succeeded).

    This is the cryptographic boundary: a forged receipt cannot
    elevate the state.
    """
    iam_stub.config.forge_receipt = True
    iam_stub.reset()
    verifier = _make_iam_verifier(iam_stub)
    client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    action = _make_iam_action()
    proof = {"proof_id": "proof_iam_2", "execution_mode": "resource_owned"}
    result = client.submit(action, proof, pccb_id="pccb_iam_2", action_hash="ah_2")

    assert result.state == "outcome_unknown"
    assert result.protocol_result.resource_receipt_verified is False
    assert result.finality.value == "non_final"


def test_iam_stub_missing_receipt_remains_non_final(iam_stub):
    """When the IAM stub returns succeeded but omits the receipt,
    the client forces state=outcome_unknown (non_final)."""
    iam_stub.config.omit_receipt = True
    iam_stub.reset()
    verifier = _make_iam_verifier(iam_stub)
    client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    action = _make_iam_action()
    proof = {"proof_id": "proof_iam_3", "execution_mode": "resource_owned"}
    result = client.submit(action, proof, pccb_id="pccb_iam_3", action_hash="ah_3")

    assert result.state == "outcome_unknown"
    assert result.protocol_result.resource_receipt_received is False
    assert result.finality.value == "non_final"


def test_iam_stub_refused_maps_to_refused(iam_stub):
    """When the IAM stub refuses (refuse_all=True), the client
    produces state=refused."""
    iam_stub.config.refuse_all = True
    iam_stub.reset()
    verifier = _make_iam_verifier(iam_stub)
    client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    action = _make_iam_action()
    proof = {"proof_id": "proof_iam_4", "execution_mode": "resource_owned"}
    result = client.submit(action, proof, pccb_id="pccb_iam_4", action_hash="ah_4")

    assert result.state == "refused"
    assert result.finality.value == "final"


def test_iam_stub_malformed_proof_is_refused(iam_stub):
    """When the proof is malformed (missing proof_id), the IAM stub
    refuses. The client produces state=refused."""
    verifier = _make_iam_verifier(iam_stub)
    client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    action = _make_iam_action()
    proof = {"execution_mode": "resource_owned"}  # no proof_id
    result = client.submit(action, proof, pccb_id="pccb_iam_5", action_hash="ah_5")

    assert result.state == "refused"


def test_iam_stub_unsupported_action_is_refused(iam_stub):
    """When the action type is not iam.grant_role, the IAM stub
    refuses. The client produces state=refused."""
    verifier = _make_iam_verifier(iam_stub)
    client = ResourceOwnedSubmissionClient(
        resource_endpoint=iam_stub.endpoint_url,
        resource_id=iam_stub.config.resource_id,
        receipt_verifier=verifier,
    )
    action = Action(
        grant_id="g",
        type="iam.delete_user",  # not supported by the stub
        target="iam-control-plane",
        params={"subject": "x"},
        est_cost=0.0,
    )
    proof = {"proof_id": "proof_iam_6", "execution_mode": "resource_owned"}
    result = client.submit(action, proof, pccb_id="pccb_iam_6", action_hash="ah_6")

    assert result.state == "refused"
