"""Tests for AuthorisedExecutionIntent (Prompt 10).

Covers:
  * Intent model: required fields, defaults, serialisation.
  * Lifecycle state machine: allowed transitions, illegal transitions rejected.
  * Metadata validation: size limit, forbidden keys, secret-prefix detection.
  * Durability profiles: ephemeral vs durable-local, capability info.
  * Execution APIs: execute() dispatches by mode; execute_brokered() and
    submit_to_resource() produce discriminated results.
  * Compatibility layer: from_grant() wraps an existing Grant.
  * Mode discrimination: brokered and resource_owned results are not
    interchangeable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from actenon.execution import ResourceReceiptVerifier, ResourceSigningKey
from actenon_protocol.execution_results import (
    FinalityStatus,
)

from actenon_permit import (
    INTENT_TRANSITIONS,
    MAX_METADATA_BYTES,
    PDP,
    AuthorisedExecutionIntent,
    Broker,
    CredentialProviderRegistry,
    EphemeralIntentStore,
    GitHubAdapter,
    IntentLifecycle,
    IntentManager,
    IntentTransitionError,
    Ledger,
    LocalDevSecretProvider,
    MetadataValidationError,
    ResourceOwnedSubmissionClient,
    SQLiteIntentStore,
    SQLiteStore,
    can_transition,
    store_capabilities,
    validate_metadata,
    validate_transition,
)
from actenon_permit.model import (
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
    db_path = tmp_path / "intent.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store
    reset_default_store()
    yield db_path
    reset_default_store()


def _make_grant(tmp_db, *, scopes_allow=("issue.create",), budget=10.0) -> Grant:
    store = SQLiteStore(str(tmp_db))
    grant = Grant(
        agent_id="intent-test-agent",
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


def _make_broker(tmp_db) -> Broker:
    pdp = _make_pdp(tmp_db)
    registry = CredentialProviderRegistry()
    registry.register("GITHUB_TOKEN", LocalDevSecretProvider({"GITHUB_TOKEN": "ghp_test_NOT_REAL_0123456789abcdef"}))
    return Broker(pdp, credential_providers=registry, production_mode=False)


# ---------------------------------------------------------------------------
# 1. Intent model
# ---------------------------------------------------------------------------


def test_intent_has_all_required_fields():
    """The AEI must carry every required field from the Prompt 10 spec."""
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="refund-bot",
    )
    # Required fields per Prompt 10 spec:
    assert intent.intent_id.startswith("intent_")
    assert intent.protocol_version  # not empty
    assert intent.action_type == "issue.create"
    assert intent.action_params == {"owner": "actenon", "repo": "demo", "title": "t"}
    assert intent.target_type == "github"
    assert intent.target_id == "github"
    assert intent.requested_execution_mode == "brokered"
    assert intent.requester_subject == "alice"
    assert intent.requester_agent_id == "refund-bot"
    assert intent.idempotency_key.startswith("op_")
    assert intent.created_at
    assert intent.expiry  # default 3600s
    assert intent.metadata == {}
    assert intent.lifecycle_state == IntentLifecycle.CREATED
    # Linked-artefact fields start empty
    assert intent.linked_decision_id is None
    assert intent.linked_proof_id is None
    assert intent.linked_attempt_ids == []
    assert intent.linked_receipt_id is None
    assert intent.linked_refusal_id is None


def test_intent_round_trips_through_dict():
    """to_dict / from_dict round-trip preserves all fields."""
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="refund-bot",
        metadata={"correlation_id": "abc-123"},
    )
    d = intent.to_dict()
    parsed = AuthorisedExecutionIntent.from_dict(d)
    assert parsed.intent_id == intent.intent_id
    assert parsed.action_type == intent.action_type
    assert parsed.lifecycle_state == intent.lifecycle_state
    assert parsed.metadata == intent.metadata


# ---------------------------------------------------------------------------
# 2. Lifecycle state machine
# ---------------------------------------------------------------------------


def test_lifecycle_has_all_required_states():
    """The lifecycle must include all states the implementation can support."""
    expected = {
        "created", "evaluating", "requires_approval", "authorised", "denied",
        "proof_issued", "executing", "submitted", "succeeded", "failed",
        "refused", "outcome_unknown", "cancelled", "expired",
    }
    actual = {s.value for s in IntentLifecycle}
    assert actual == expected


def test_terminal_states_have_no_outbound_transitions():
    """Terminal states MUST have empty transition sets."""
    for terminal in (
        IntentLifecycle.SUCCEEDED,
        IntentLifecycle.FAILED,
        IntentLifecycle.DENIED,
        IntentLifecycle.CANCELLED,
        IntentLifecycle.EXPIRED,
    ):
        assert INTENT_TRANSITIONS[terminal] == frozenset(), (
            f"{terminal.value!r} should be terminal"
        )


def test_outcome_unknown_can_resolve_to_succeeded_or_failed():
    """outcome_unknown can transition to succeeded/failed via reconciliation."""
    assert can_transition(IntentLifecycle.OUTCOME_UNKNOWN, IntentLifecycle.SUCCEEDED)
    assert can_transition(IntentLifecycle.OUTCOME_UNKNOWN, IntentLifecycle.FAILED)
    # And can stay outcome_unknown.
    assert can_transition(IntentLifecycle.OUTCOME_UNKNOWN, IntentLifecycle.OUTCOME_UNKNOWN)


def test_illegal_transition_rejected():
    """created -> succeeded is illegal (must go through evaluating -> authorised -> ...)."""
    with pytest.raises(IntentTransitionError):
        validate_transition(IntentLifecycle.CREATED, IntentLifecycle.SUCCEEDED)


def test_succeeded_is_terminal():
    """succeeded -> anything is illegal."""
    for target in IntentLifecycle:
        if target == IntentLifecycle.SUCCEEDED:
            continue
        assert not can_transition(IntentLifecycle.SUCCEEDED, target), (
            f"succeeded -> {target.value} should be illegal"
        )


def test_manager_transition_rejects_illegal():
    """IntentManager.transition rejects illegal transitions."""
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    with pytest.raises(IntentTransitionError):
        mgr.transition(intent.intent_id, IntentLifecycle.SUCCEEDED)


def test_manager_transition_allows_created_to_evaluating():
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    intent = mgr.transition(intent.intent_id, IntentLifecycle.EVALUATING)
    assert intent.lifecycle_state == IntentLifecycle.EVALUATING


# ---------------------------------------------------------------------------
# 3. Metadata validation
# ---------------------------------------------------------------------------


def test_metadata_rejects_forbidden_keys():
    """Keys like 'password', 'secret', 'token' are rejected."""
    for forbidden in ("password", "secret", "token", "api_key", "authorization"):
        with pytest.raises(MetadataValidationError):
            validate_metadata({forbidden: "x"})


def test_metadata_rejects_secret_value_prefixes():
    """Values that look like secrets (ghp_, sk_, AKIA, -----BEGIN) are rejected."""
    for prefix in ("ghp_abc", "sk_live_xyz", "AKIA1234", "-----BEGIN PRIVATE KEY-----"):
        with pytest.raises(MetadataValidationError):
            validate_metadata({"some_field": prefix})


def test_metadata_rejects_oversized_payload():
    """Metadata over 4 KiB is rejected."""
    big = {"x": "a" * (MAX_METADATA_BYTES + 100)}
    with pytest.raises(MetadataValidationError):
        validate_metadata(big)


def test_metadata_accepts_normal_fields():
    """Normal metadata passes validation."""
    validate_metadata({"correlation_id": "abc-123", "request_source": "cli"})
    validate_metadata({})


# ---------------------------------------------------------------------------
# 4. Durability profiles
# ---------------------------------------------------------------------------


def test_ephemeral_store_capabilities():
    """Ephemeral store declares it does NOT survive process restart."""
    caps = store_capabilities(EphemeralIntentStore())
    assert caps["durability_profile"] == "ephemeral_local"
    assert caps["survives_process_restart"] is False
    assert caps["survives_host_failure"] is False
    assert caps["pollable_after_process_termination"] is False


def test_sqlite_store_capabilities(tmp_path):
    """SQLite store declares it survives process restart but not host failure."""
    store = SQLiteIntentStore(str(tmp_path / "intents.db"))
    caps = store_capabilities(store)
    assert caps["durability_profile"] == "durable_local"
    assert caps["survives_process_restart"] is True
    assert caps["survives_host_failure"] is False
    assert caps["pollable_after_process_termination"] is True
    store.close()


def test_sqlite_store_persists_across_reopen(tmp_path):
    """Intents written to SQLiteIntentStore survive close + reopen."""
    db_path = str(tmp_path / "intents.db")
    store1 = SQLiteIntentStore(db_path)
    mgr1 = IntentManager(store=store1)
    intent = mgr1.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    store1.close()

    store2 = SQLiteIntentStore(db_path)
    intent2 = store2.get(intent.intent_id)
    assert intent2 is not None
    assert intent2.intent_id == intent.intent_id
    assert intent2.action_type == "issue.create"
    store2.close()


def test_ephemeral_store_does_not_persist():
    """Ephemeral store loses everything when a new instance is created."""
    store1 = EphemeralIntentStore()
    mgr = IntentManager(store=store1)
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    assert store1.get(intent.intent_id) is not None
    # New instance — empty.
    store2 = EphemeralIntentStore()
    assert store2.get(intent.intent_id) is None


# ---------------------------------------------------------------------------
# 5. Execution APIs — brokered
# ---------------------------------------------------------------------------


def test_execute_brokered_succeeded_transitions_lifecycle(tmp_db):
    """execute_brokered on a successful adapter call transitions the
    intent through CREATED -> EVALUATING -> AUTHORISED -> PROOF_ISSUED ->
    EXECUTING -> SUCCEEDED."""
    grant = _make_grant(tmp_db)
    broker = _make_broker(tmp_db)
    adapter = GitHubAdapter(test_mode=True)
    decision = _make_decision_allow()
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "via aei"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    updated, result = mgr.execute_brokered(
        intent, grant=grant, decision=decision, broker=broker,
        adapter=adapter, credential_ref="GITHUB_TOKEN",
    )
    assert updated.lifecycle_state == IntentLifecycle.SUCCEEDED
    assert result.state == "succeeded"
    assert result.mode == "brokered"
    # The proof and attempt links are recorded.
    assert updated.linked_proof_id is not None
    assert len(updated.linked_attempt_ids) == 1


def test_execute_brokered_refused_transitions_lifecycle(tmp_db):
    """execute_brokered on an adapter refusal transitions to REFUSED."""
    grant = _make_grant(tmp_db, scopes_allow=["issue.create"])
    broker = _make_broker(tmp_db)
    adapter = GitHubAdapter(test_mode=True)
    decision = _make_decision_allow()
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "t", "malicious": "x"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    updated, result = mgr.execute_brokered(
        intent, grant=grant, decision=decision, broker=broker,
        adapter=adapter, credential_ref="GITHUB_TOKEN",
    )
    assert updated.lifecycle_state == IntentLifecycle.REFUSED
    assert result.state == "refused"


def test_execute_dispatches_by_mode_brokered(tmp_db):
    """execute() dispatches to execute_brokered() when mode=brokered."""
    grant = _make_grant(tmp_db)
    broker = _make_broker(tmp_db)
    adapter = GitHubAdapter(test_mode=True)
    decision = _make_decision_allow()
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "via dispatch"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    updated, result = mgr.execute(
        intent, grant=grant, decision=decision, broker=broker,
        adapter=adapter, credential_ref="GITHUB_TOKEN",
    )
    assert updated.lifecycle_state == IntentLifecycle.SUCCEEDED
    assert result.mode == "brokered"


def test_execute_brokered_requires_adapter_and_credential_ref(tmp_db):
    """execute_brokered raises ValueError if adapter/credential_ref are missing."""
    grant = _make_grant(tmp_db)
    broker = _make_broker(tmp_db)
    decision = _make_decision_allow()
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    with pytest.raises(ValueError, match="adapter"):
        mgr.execute(intent, grant=grant, decision=decision, broker=broker)


# ---------------------------------------------------------------------------
# 6. Execution APIs — resource_owned
# ---------------------------------------------------------------------------


def test_execute_resource_owned_submitted_transitions_lifecycle(tmp_db, monkeypatch):
    """submit_to_resource transitions the intent through CREATED ->
    EVALUATING -> AUTHORISED -> PROOF_ISSUED -> SUBMITTED -> SUCCEEDED
    (when the resource returns a verified receipt)."""
    import hashlib
    import hmac
    import json

    # Stub the resource boundary.
    secret = b"resource-secret-not-real"
    key = ResourceSigningKey(resource_id="example", key_id="rk_1", secret=secret)
    verifier = ResourceReceiptVerifier()
    verifier.register_key(key)

    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example",
        receipt_verifier=verifier,
    )

    # Build a valid signed receipt the stub will return.
    body = {"resource_id": "example", "result": "ok", "signing_key_id": "rk_1"}
    receipt = dict(body)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    receipt["signature"] = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

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
        return _FakeResponse(200, {"status": "succeeded", "receipt": receipt, "submission_reference": "sub_aei_1"})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="iam.grant_role",
        action_params={"subject": "alice", "role": "viewer"},
        target_type="iam", target_id="iam-control-plane",
        requested_execution_mode="resource_owned",
        requester_subject="bob",
        requester_agent_id="admin-bot",
    )
    proof = {"proof_id": "proof_aei_1", "execution_mode": "resource_owned"}
    updated, result = mgr.submit_to_resource(intent, resource_client=r_client, proof=proof)
    assert updated.lifecycle_state == IntentLifecycle.SUCCEEDED
    assert result.state == "succeeded"
    assert result.mode == "resource_owned"
    assert updated.submission_reference == "sub_aei_1"


def test_execute_dispatches_by_mode_resource_owned(tmp_db, monkeypatch):
    """execute() dispatches to submit_to_resource() when mode=resource_owned."""
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example",
        receipt_verifier=verifier,
    )

    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = __import__("json").dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        # Resource returns accepted (non_final).
        return _FakeResponse(202, {"status": "accepted", "submission_reference": "sub_2"})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="iam.grant_role",
        action_params={"subject": "alice", "role": "viewer"},
        target_type="iam", target_id="iam-control-plane",
        requested_execution_mode="resource_owned",
        requester_subject="bob",
        requester_agent_id="admin-bot",
    )
    proof = {"proof_id": "p_1", "execution_mode": "resource_owned"}
    updated, result = mgr.execute(
        intent, grant=None, decision=_make_decision_allow(), broker=None,  # type: ignore[arg-type]
        resource_client=r_client, proof=proof,
    )
    # accepted maps to SUBMITTED lifecycle (still non_final).
    assert updated.lifecycle_state == IntentLifecycle.SUBMITTED
    assert result.state == "accepted"
    assert result.finality == FinalityStatus.NON_FINAL


def test_resource_owned_does_not_implie_execution(tmp_db, monkeypatch):
    """submit_to_resource on an 'accepted' response keeps the lifecycle
    at SUBMITTED — NOT SUCCEEDED. Submission is not execution."""
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example",
        receipt_verifier=verifier,
    )

    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = __import__("json").dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        return _FakeResponse(202, {"status": "accepted", "submission_reference": "sub_3"})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)

    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="iam.grant_role",
        action_params={"subject": "alice", "role": "viewer"},
        target_type="iam", target_id="iam-control-plane",
        requested_execution_mode="resource_owned",
        requester_subject="bob",
        requester_agent_id="admin-bot",
    )
    proof = {"proof_id": "p_2", "execution_mode": "resource_owned"}
    updated, _ = mgr.submit_to_resource(intent, resource_client=r_client, proof=proof)
    assert updated.lifecycle_state != IntentLifecycle.SUCCEEDED
    assert updated.lifecycle_state == IntentLifecycle.SUBMITTED


# ---------------------------------------------------------------------------
# 7. Mode discrimination
# ---------------------------------------------------------------------------


def test_brokered_and_resource_owned_results_are_not_interchangeable(tmp_db, monkeypatch):
    """The result of execute_brokered and submit_to_resource have
    different mode discriminators and disjoint field sets."""
    # Brokered
    grant = _make_grant(tmp_db)
    broker = _make_broker(tmp_db)
    adapter = GitHubAdapter(test_mode=True)
    decision = _make_decision_allow()
    mgr = IntentManager(store=EphemeralIntentStore())
    b_intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "b"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    _, b_result = mgr.execute_brokered(
        b_intent, grant=grant, decision=decision, broker=broker,
        adapter=adapter, credential_ref="GITHUB_TOKEN",
    )
    assert b_result.mode == "brokered"

    # Resource-owned (accepted)
    verifier = ResourceReceiptVerifier()
    r_client = ResourceOwnedSubmissionClient(
        resource_endpoint="https://example.invalid/submit",
        resource_id="example",
        receipt_verifier=verifier,
    )

    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self._body = __import__("json").dumps(body).encode("utf-8")
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def _fake_urlopen(req, timeout=None):
        return _FakeResponse(202, {"status": "accepted", "submission_reference": "sub_x"})

    monkeypatch.setattr("actenon_permit.execution_modes.urllib.request.urlopen", _fake_urlopen)
    r_intent = mgr.create(
        action_type="iam.grant_role",
        action_params={"subject": "alice", "role": "viewer"},
        target_type="iam", target_id="iam-control-plane",
        requested_execution_mode="resource_owned",
        requester_subject="bob",
        requester_agent_id="admin-bot",
    )
    _, r_result = mgr.submit_to_resource(r_intent, resource_client=r_client, proof={"proof_id": "p", "execution_mode": "resource_owned"})

    assert r_result.mode == "resource_owned"
    assert b_result.mode != r_result.mode

    # The serialised dicts must not share mode-specific keys.
    from actenon_protocol.execution_results import serialise_result
    b_dict = serialise_result(b_result.protocol_result)
    r_dict = serialise_result(r_result.protocol_result)
    brokered_only = {"receipt_received", "receipt_verified", "provider_evidence", "reconciliation_status"}
    resource_only = {"resource_receipt_received", "resource_receipt_verified", "resource_receipt", "submission_reference"}
    assert brokered_only.isdisjoint(r_dict.keys())
    assert resource_only.isdisjoint(b_dict.keys())


# ---------------------------------------------------------------------------
# 8. Compatibility layer
# ---------------------------------------------------------------------------


def test_from_grant_wraps_existing_grant(tmp_db):
    """from_grant() creates an AEI from an existing Grant without
    rewriting the issuance path."""
    grant = _make_grant(tmp_db)
    intent = IntentManager.from_grant(
        grant,
        action_type="issue.create",
        action_params={"owner": "actenon", "repo": "demo", "title": "compat"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
    )
    assert intent.intent_id.startswith("intent_")
    assert intent.requester_subject == grant.agent_id
    assert intent.requester_agent_id == grant.agent_id
    assert intent.expiry == grant.expires_at.isoformat()
    # The grant id is recorded in metadata, NOT in a linked_artefact field
    # (the Grant is the authority, not a proof).
    assert intent.metadata["_source_grant_id"] == grant.id
    assert intent.linked_proof_id is None
    assert intent.lifecycle_state == IntentLifecycle.CREATED


def test_from_grant_rejects_secret_in_metadata(tmp_db):
    """from_grant() runs validate_metadata on caller-supplied metadata."""
    grant = _make_grant(tmp_db)
    with pytest.raises(MetadataValidationError):
        IntentManager.from_grant(
            grant,
            action_type="issue.create",
            action_params={"owner": "a", "repo": "b", "title": "t"},
            target_type="github", target_id="github",
            metadata={"password": "secret-value"},
        )


# ---------------------------------------------------------------------------
# 9. Linked-artefact helpers
# ---------------------------------------------------------------------------


def test_link_proof_sets_linked_proof_id(tmp_db):
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    mgr.link_proof(intent.intent_id, "proof_abc")
    intent = mgr.store.get(intent.intent_id)
    assert intent is not None
    assert intent.linked_proof_id == "proof_abc"


def test_link_attempt_appends_to_list(tmp_db):
    mgr = IntentManager(store=EphemeralIntentStore())
    intent = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    mgr.link_attempt(intent.intent_id, "exec_1")
    mgr.link_attempt(intent.intent_id, "exec_2")
    mgr.link_attempt(intent.intent_id, "exec_1")  # dedup
    intent = mgr.store.get(intent.intent_id)
    assert intent is not None
    assert intent.linked_attempt_ids == ["exec_1", "exec_2"]


# ---------------------------------------------------------------------------
# 10. Store listing
# ---------------------------------------------------------------------------


def test_ephemeral_store_list_filters_by_subject():
    store = EphemeralIntentStore()
    mgr = IntentManager(store=store)
    i1 = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t1"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="alice",
        requester_agent_id="bot",
    )
    i2 = mgr.create(
        action_type="issue.create",
        action_params={"owner": "a", "repo": "b", "title": "t2"},
        target_type="github", target_id="github",
        requested_execution_mode="brokered",
        requester_subject="bob",
        requester_agent_id="bot",
    )
    all_intents = store.list()
    assert len(all_intents) == 2
    alice_intents = store.list(requester_subject="alice")
    assert len(alice_intents) == 1
    assert alice_intents[0].intent_id == i1.intent_id
    bob_intents = store.list(requester_subject="bob")
    assert len(bob_intents) == 1
    assert bob_intents[0].intent_id == i2.intent_id
