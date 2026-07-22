"""Prompt 9 security tests: brokered vs resource-owned execution modes.

These tests cover the 7 cases from the Prompt 9 spec:

  1. modes cannot be confused
  2. receipt mode is mandatory
  3. brokered success requires observed provider success
  4. resource-owned submission does not imply execution
  5. forged resource receipts are rejected
  6. missing resource receipts remain non-final
  7. UI/API serialisation preserves the distinction

Each test is named ``test_<n>_<slug>`` to make the spec mapping explicit.

These tests live in the Permit repo (not Protocol or Kernel) because
they exercise the full Permit-side coordinator path: the BrokeredExecutionCoordinator
wraps Broker.execute_via_adapter, and the ResourceOwnedSubmissionClient
submits to a stubbed HTTP resource boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError

import pytest
from actenon.execution import ResourceReceiptVerifier, ResourceSigningKey
from actenon_protocol.execution_results import (
    ExecutionResultValidationError,
    FinalityStatus,
    ResourceOwnedExecutionState,
)

from actenon_permit import (
    PDP,
    Broker,
    BrokeredExecutionCoordinator,
    CredentialProviderRegistry,
    GitHubAdapter,
    Ledger,
    LocalDevSecretProvider,
    ResourceOwnedSubmissionClient,
    SQLiteStore,
)
from actenon_permit.model import (
    Action,
    Budget,
    Decision,
    DecisionOutcome,
    Grant,
    Rate,
    Scopes,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(monkeypatch, tmp_path):
    db_path = tmp_path / "modes.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield db_path
    reset_default_store()


def _make_grant(tmp_db, *, scopes_allow=("issue.create",), budget=10.0) -> Grant:
    store = SQLiteStore(str(tmp_db))
    grant = Grant(
        agent_id="modes-test-agent",
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


def _make_decision_allow() -> Decision:
    return Decision(outcome=DecisionOutcome.ALLOW, reason="test allow", rule_matched="test:allow")


def _make_action(action_type: str = "issue.create", params: dict[str, Any] | None = None) -> Action:
    return Action(
        grant_id="grant_test",
        type=action_type,
        target="github",
        params=params or {"owner": "actenon", "repo": "demo", "title": "test"},
        est_cost=0.0,
    )


def _make_broker_and_adapter(
    tmp_db,
    *,
    credential_value: str = "ghp_test_secret_NOT_REAL_0123456789abcdef",
    credential_ref: str = "GITHUB_TOKEN",
) -> tuple[Broker, GitHubAdapter, CredentialProviderRegistry]:
    pdp = _make_pdp(tmp_db)
    registry = CredentialProviderRegistry()
    registry.register(credential_ref, LocalDevSecretProvider({credential_ref: credential_value}))
    broker = Broker(pdp, credential_providers=registry, production_mode=False)
    adapter = GitHubAdapter(test_mode=True)
    return broker, adapter, registry


def _sign_receipt(body: dict, secret: bytes) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# 1. Modes cannot be confused
# ---------------------------------------------------------------------------


def test_1_modes_cannot_be_confused(tmp_db):
    """A brokered result and a resource_owned result MUST NOT be
    interchangeable. Their serialised dicts carry different mode
    discriminators and disjoint mode-specific field sets.
    """
    grant = _make_grant(tmp_db)
    broker, adapter, _ = _make_broker_and_adapter(tmp_db)
    coord = BrokeredExecutionCoordinator(broker=broker)
    action = _make_action()
    decision = _make_decision_allow()

    brokered_result = coord.coordinate(
        grant, action, decision, adapter,
        credential_ref="GITHUB_TOKEN",
        idempotency_key="mode-test-1",
        pccb_id="pccb_1",
        action_hash="ah_1",
    )

    # Build a resource_owned submitted result for comparison.
    # Stub the resource boundary with a fake client (no HTTP).
    verifier = ResourceReceiptVerifier()
    _r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )
    # Direct construction via the kernel helper (skip HTTP):
    from actenon.execution import build_resource_owned_result

    resource_result = build_resource_owned_result(
        state=ResourceOwnedExecutionState.SUBMITTED,
        verified_by="example-resource-boundary",
        executed_by="example-resource",
        attempt_id="exec_res_1",
        occurred_at=datetime.now(UTC).isoformat(),
        submission_reference="sub_1",
    )

    b_dict = brokered_result.to_dict()
    r_dict = resource_result.to_dict()

    assert b_dict["mode"] == "brokered"
    assert r_dict["mode"] == "resource_owned"
    assert b_dict["mode"] != r_dict["mode"]

    # Disjoint mode-specific fields
    brokered_only = {"receipt_received", "receipt_verified", "provider_evidence", "reconciliation_status"}
    resource_only = {"resource_receipt_received", "resource_receipt_verified", "resource_receipt", "submission_reference"}
    assert brokered_only.isdisjoint(r_dict.keys()), (
        f"resource_owned dict carries brokered-only keys: {brokered_only & set(r_dict.keys())}"
    )
    assert resource_only.isdisjoint(b_dict.keys()), (
        f"brokered dict carries resource_owned-only keys: {resource_only & set(b_dict.keys())}"
    )


# ---------------------------------------------------------------------------
# 2. Receipt mode is mandatory
# ---------------------------------------------------------------------------


def test_2_receipt_mode_is_mandatory(tmp_db):
    """Every ModeAwareExecutionResult MUST carry a mode field. The
    serialised dict MUST include 'mode' as the discriminator."""
    grant = _make_grant(tmp_db)
    broker, adapter, _ = _make_broker_and_adapter(tmp_db)
    coord = BrokeredExecutionCoordinator(broker=broker)
    action = _make_action()
    decision = _make_decision_allow()

    result = coord.coordinate(
        grant, action, decision, adapter,
        credential_ref="GITHUB_TOKEN",
        idempotency_key="mode-test-2",
    )

    d = result.to_dict()
    assert "mode" in d, "serialised result missing 'mode' field"
    assert d["mode"] in ("brokered", "resource_owned")
    # Mode-specific receipt fields must also be present
    if d["mode"] == "brokered":
        assert "receipt_received" in d
        assert "receipt_verified" in d
    else:
        assert "resource_receipt_received" in d
        assert "resource_receipt_verified" in d


# ---------------------------------------------------------------------------
# 3. Brokered success requires observed provider success
# ---------------------------------------------------------------------------


def test_3_brokered_success_requires_observed_provider_success(tmp_db):
    """A brokered coordinator that observes the provider's success
    response produces state=succeeded with provider_execution_observed=True.

    A brokered coordinator that does NOT observe the provider (timeout,
    crash) produces state=outcome_unknown (NOT succeeded).

    This is what prevents a credential-resolution success from being
    reported as an execution success.
    """
    grant = _make_grant(tmp_db)
    broker, adapter, _ = _make_broker_and_adapter(tmp_db)
    coord = BrokeredExecutionCoordinator(broker=broker)
    decision = _make_decision_allow()

    # Path A: adapter succeeds, broker observes.
    action_ok = _make_action(params={"owner": "actenon", "repo": "demo", "title": "ok"})
    result_ok = coord.coordinate(
        grant, action_ok, decision, adapter,
        credential_ref="GITHUB_TOKEN",
        idempotency_key="mode-test-3a",
    )
    assert result_ok.state == "succeeded"
    assert result_ok.protocol_result.provider_execution_observed is True
    assert result_ok.finality == FinalityStatus.FINAL

    # Path B: adapter refuses (wrong action type for adapter) ->
    # state=refused, NOT succeeded.
    action_bad = _make_action(action_type="repo.delete", params={"owner": "x", "repo": "y"})
    result_refused = coord.coordinate(
        grant, action_bad, decision, adapter,
        credential_ref="GITHUB_TOKEN",
        idempotency_key="mode-test-3b",
    )
    assert result_refused.state == "refused"
    assert result_refused.protocol_result.provider_execution_observed is False
    assert result_refused.finality == FinalityStatus.FINAL

    # Path C: invalid params -> refused (no provider call attempted)
    action_invalid = _make_action(
        params={"owner": "actenon", "repo": "demo", "title": "t", "malicious": "x"},
    )
    result_invalid = coord.coordinate(
        grant, action_invalid, decision, adapter,
        credential_ref="GITHUB_TOKEN",
        idempotency_key="mode-test-3c",
    )
    assert result_invalid.state == "refused"
    assert result_invalid.protocol_result.provider_execution_observed is False


# ---------------------------------------------------------------------------
# 4. Resource-owned submission does not imply execution
# ---------------------------------------------------------------------------


def test_4_resource_owned_submission_does_not_imply_execution(tmp_db, monkeypatch):
    """A resource_owned submission that returns status=accepted MUST
    produce state=accepted (NOT succeeded), with finality=non_final
    and provider_execution_observed=False.

    Submission is not execution.
    """
    _grant = _make_grant(tmp_db)  # DB init; grant object unused
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    # Stub urllib.request.urlopen to return an "accepted" response.
    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = json.dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        return _FakeResponse(202, {"status": "accepted", "submission_reference": "sub_abc"})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action = _make_action()
    proof = {"proof_id": "proof_abc", "execution_mode": "resource_owned"}
    result = r_client.submit(action, proof, pccb_id="pccb_4", action_hash="ah_4")

    assert result.state == "accepted"
    assert result.protocol_result.provider_execution_observed is False
    assert result.protocol_result.resource_receipt_received is False
    assert result.protocol_result.resource_receipt_verified is False
    assert result.finality == FinalityStatus.NON_FINAL
    assert result.is_final is False


# ---------------------------------------------------------------------------
# 5. Forged resource receipts are rejected
# ---------------------------------------------------------------------------


def test_5_forged_resource_receipts_are_rejected(tmp_db, monkeypatch):
    """When the resource boundary returns a 'succeeded' status with a
    receipt whose signature does NOT verify, the result MUST be
    outcome_unknown (NOT succeeded).

    The cryptographic boundary: a forged receipt cannot elevate the
    state.
    """
    _grant = _make_grant(tmp_db)  # DB init; grant object unused
    # Register a real key with the verifier.
    real_key = ResourceSigningKey(
        resource_id="example-resource",
        key_id="rk_1",
        secret=b"real-secret-not-shared",
    )
    verifier = ResourceReceiptVerifier()
    verifier.register_key(real_key)

    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    # Build a forged receipt: signed with the WRONG secret but
    # claiming the real key_id.
    body = {
        "resource_id": "example-resource",
        "result": "ok",
        "signing_key_id": real_key.key_id,
    }
    forged_receipt = dict(body)
    forged_receipt["signature"] = _sign_receipt(body, b"wrong-secret")

    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = json.dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        return _FakeResponse(200, {"status": "succeeded", "receipt": forged_receipt})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action = _make_action()
    proof = {"proof_id": "proof_def", "execution_mode": "resource_owned"}
    result = r_client.submit(action, proof, pccb_id="pccb_5", action_hash="ah_5")

    # The forged receipt MUST NOT elevate the state to succeeded.
    assert result.state != "succeeded"
    assert result.state == "outcome_unknown"
    assert result.protocol_result.resource_receipt_verified is False
    assert result.finality == FinalityStatus.NON_FINAL


# ---------------------------------------------------------------------------
# 6. Missing resource receipts remain non-final
# ---------------------------------------------------------------------------


def test_6_missing_resource_receipts_remain_non_final(tmp_db, monkeypatch):
    """When the resource boundary claims 'succeeded' but provides NO
    receipt, the result MUST be outcome_unknown (NOT succeeded) and
    non_final.

    A missing receipt cannot be verified, so we cannot confirm
    execution.
    """
    _grant = _make_grant(tmp_db)  # DB init; grant object unused
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = json.dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        # 'succeeded' but no receipt field.
        return _FakeResponse(200, {"status": "succeeded"})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action = _make_action()
    proof = {"proof_id": "proof_ghi", "execution_mode": "resource_owned"}
    result = r_client.submit(action, proof, pccb_id="pccb_6", action_hash="ah_6")

    assert result.state == "outcome_unknown"
    assert result.protocol_result.resource_receipt_received is False
    assert result.protocol_result.resource_receipt_verified is False
    assert result.finality == FinalityStatus.NON_FINAL
    assert result.is_final is False


# ---------------------------------------------------------------------------
# 7. UI/API serialisation preserves the distinction
# ---------------------------------------------------------------------------


def test_7_serialisation_preserves_mode_distinction(tmp_db, monkeypatch):
    """Round-trip a brokered and a resource_owned result through
    JSON serialisation. The deserialised dicts MUST preserve:

      * the 'mode' discriminator
      * the mode-specific field sets (no leaking)
      * the finality-vs-state invariants
    """
    grant = _make_grant(tmp_db)
    broker, adapter, _ = _make_broker_and_adapter(tmp_db)
    coord = BrokeredExecutionCoordinator(broker=broker)
    decision = _make_decision_allow()

    # Brokered
    action_b = _make_action(params={"owner": "actenon", "repo": "demo", "title": "brokered"})
    brokered = coord.coordinate(
        grant, action_b, decision, adapter,
        credential_ref="GITHUB_TOKEN",
        idempotency_key="mode-test-7b",
    )
    b_dict = brokered.to_dict()
    b_json = json.dumps(b_dict, sort_keys=True)
    b_parsed = json.loads(b_json)
    assert b_parsed["mode"] == "brokered"
    assert b_parsed["state"] == "succeeded"
    assert b_parsed["finality"] == "final"
    assert b_parsed["provider_execution_observed"] is True

    # Resource-owned (succeeded with verified receipt)
    real_key = ResourceSigningKey(
        resource_id="example-resource",
        key_id="rk_7",
        secret=b"real-secret-not-shared-7",
    )
    verifier = ResourceReceiptVerifier()
    verifier.register_key(real_key)
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    body = {
        "resource_id": "example-resource",
        "result": "ok",
        "signing_key_id": real_key.key_id,
    }
    valid_receipt = dict(body)
    valid_receipt["signature"] = _sign_receipt(body, real_key.secret)

    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = json.dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        return _FakeResponse(200, {"status": "succeeded", "receipt": valid_receipt})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action_r = _make_action()
    proof = {"proof_id": "proof_7", "execution_mode": "resource_owned"}
    resource = r_client.submit(action_r, proof, pccb_id="pccb_7", action_hash="ah_7")
    r_dict = resource.to_dict()
    r_json = json.dumps(r_dict, sort_keys=True)
    r_parsed = json.loads(r_json)
    assert r_parsed["mode"] == "resource_owned"
    assert r_parsed["state"] == "succeeded"
    assert r_parsed["finality"] == "final"
    assert r_parsed["provider_execution_observed"] is True
    assert r_parsed["resource_receipt_received"] is True
    assert r_parsed["resource_receipt_verified"] is True

    # The two JSON strings must NOT be equal (different mode discriminators).
    assert b_json != r_json
    # The mode-specific field sets must remain disjoint after round-trip.
    brokered_only = {"receipt_received", "receipt_verified", "provider_evidence", "reconciliation_status"}
    resource_only = {"resource_receipt_received", "resource_receipt_verified", "resource_receipt", "submission_reference"}
    assert brokered_only.isdisjoint(r_parsed.keys())
    assert resource_only.isdisjoint(b_parsed.keys())


# ---------------------------------------------------------------------------
# Extra: HTTP error from resource boundary maps to refused / outcome_unknown
# ---------------------------------------------------------------------------


def test_resource_owned_http_4xx_maps_to_refused(tmp_db, monkeypatch):
    """A 4xx response from the resource boundary maps to state=refused."""
    _grant = _make_grant(tmp_db)  # DB init; grant object unused
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    def _fake_urlopen(req, timeout=None):
        raise HTTPError(req.full_url, 403, "Forbidden", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action = _make_action()
    proof = {"proof_id": "proof_4xx", "execution_mode": "resource_owned"}
    result = r_client.submit(action, proof)
    assert result.state == "refused"
    assert result.finality == FinalityStatus.FINAL


def test_resource_owned_http_5xx_maps_to_outcome_unknown(tmp_db, monkeypatch):
    """A 5xx response from the resource boundary maps to state=outcome_unknown."""
    _grant = _make_grant(tmp_db)  # DB init; grant object unused
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    def _fake_urlopen(req, timeout=None):
        raise HTTPError(req.full_url, 503, "Service Unavailable", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action = _make_action()
    proof = {"proof_id": "proof_5xx", "execution_mode": "resource_owned"}
    result = r_client.submit(action, proof)
    assert result.state == "outcome_unknown"
    assert result.finality == FinalityStatus.NON_FINAL


def test_resource_owned_timeout_maps_to_outcome_unknown(tmp_db, monkeypatch):
    """A submission timeout maps to state=outcome_unknown (not refused —
    we don't know if the resource received the request)."""
    _grant = _make_grant(tmp_db)  # DB init; grant object unused
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example-resource",
        receipt_verifier=verifier,
    )

    def _fake_urlopen(req, timeout=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    action = _make_action()
    proof = {"proof_id": "proof_timeout", "execution_mode": "resource_owned"}
    result = r_client.submit(action, proof)
    assert result.state == "outcome_unknown"
    assert result.finality == FinalityStatus.NON_FINAL


# ---------------------------------------------------------------------------
# Extra: protocol dataclass rejects mode-mismatched hard rules
# ---------------------------------------------------------------------------


def test_protocol_rejects_brokered_succeeded_without_observation():
    """The Protocol dataclass layer rejects a brokered succeeded result
    without provider_execution_observed=True. This is the layered
    enforcement: even if the Permit coordinator had a bug, the
    Protocol layer would still catch it."""
    from actenon_protocol import BrokeredExecutionResult as BER
    from actenon_protocol import BrokeredExecutionState as BES

    with pytest.raises(ExecutionResultValidationError):
        BER(
            state=BES.SUCCEEDED,
            verified_by="x",
            executed_by="x",
            provider_execution_observed=False,
            attempt_id="exec_x",
            occurred_at="2026-07-22T10:00:00Z",
        )


def test_protocol_rejects_resource_owned_succeeded_without_verified_receipt():
    """The Protocol dataclass layer rejects a resource_owned succeeded
    result without resource_receipt_verified=True."""
    from actenon_protocol import (
        ExecutionResultValidationError as ERE,
    )
    from actenon_protocol import (
        ResourceOwnedExecutionResult as ROER,
    )
    from actenon_protocol import (
        ResourceOwnedExecutionState as ROES,
    )

    with pytest.raises(ERE):
        ROER(
            state=ROES.SUCCEEDED,
            verified_by="r",
            executed_by="r",
            attempt_id="exec_y",
            occurred_at="2026-07-22T10:00:00Z",
            provider_execution_observed=True,
            resource_receipt_received=True,
            resource_receipt_verified=False,
        )
