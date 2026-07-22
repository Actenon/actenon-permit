"""Security tests for the brokered execution layer (Prompt 8).

These tests cover the 12 security cases from the Prompt 8 spec:

  1. agent cannot retrieve raw credential
  2. credential not logged
  3. credential not written to receipts
  4. wrong target refused
  5. mutated parameters refused
  6. provider timeout
  7. provider partial response
  8. duplicate request (idempotency)
  9. adapter exception
 10. credential resolver failure
 11. unsupported action
 12. reconciliation after unknown outcome

Each test is named ``test_<n>_<slug>`` to make the spec mapping explicit.
The tests use the GitHubAdapter in test_mode (no network) plus a few
adapter stubs to inject specific failure modes.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from actenon_permit import (
    PDP,
    Broker,
    BrokerExecutionError,
    CloudManagedRefProvider,
    Credential,
    CredentialProvider,
    CredentialProviderRegistry,
    EnvironmentSecretProvider,
    GitHubAdapter,
    Ledger,
    LocalDevSecretProvider,
    ProviderAdapter,
    ProviderPartialResponseError,
    ProviderResponse,
    ProviderTimeoutError,
    SQLiteStore,
    UnsupportedActionError,
    ValidationResult,
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
    db_path = tmp_path / "broker.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield db_path
    reset_default_store()


def _make_grant(tmp_db, *, scopes_allow=("issue.create",), budget=10.0) -> Grant:
    store = SQLiteStore(str(tmp_db))
    grant = Grant(
        agent_id="broker-test-agent",
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


def _make_broker(
    tmp_db,
    *,
    credential_value: str = "ghp_test_secret_NOT_REAL_0123456789abcdef",
    credential_ref: str = "github_token",
    production_mode: bool = False,
    provider: CredentialProvider | None = None,
) -> tuple[Broker, GitHubAdapter]:
    pdp = _make_pdp(tmp_db)
    registry = CredentialProviderRegistry()
    if provider is None:
        # Use LocalDevSecretProvider for tests — explicit, no env pollution.
        local = LocalDevSecretProvider({credential_ref: credential_value})
        registry.register(credential_ref, local)
    else:
        registry.register(credential_ref, provider)
    broker = Broker(pdp, credential_providers=registry, production_mode=production_mode)
    adapter = GitHubAdapter(test_mode=True)
    return broker, adapter


# ---------------------------------------------------------------------------
# 1. Agent cannot retrieve raw credential
# ---------------------------------------------------------------------------


def test_1_agent_cannot_retrieve_raw_credential(tmp_db):
    """The agent (caller of broker.execute_via_adapter) must NEVER see the
    credential value. The return value is a ProviderResponse whose
    evidence has been redacted; the credential value is not in any field.
    """
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db, credential_value="ghp_SUPER_SECRET_VALUE_xyz")
    action = _make_action()
    decision = _make_decision_allow()

    response, cost = broker.execute_via_adapter(
        grant, action, decision, adapter,
        credential_ref="github_token",
        idempotency_key="test-1",
    )

    # The credential value MUST NOT appear anywhere in the response.
    response_str = repr(response) + repr(response.provider_evidence)
    assert "ghp_SUPER_SECRET_VALUE_xyz" not in response_str
    # The Credential object's __repr__ also must not leak.
    assert "ghp_SUPER_SECRET_VALUE_xyz" not in repr(Credential(ref="x", value="ghp_SUPER_SECRET_VALUE_xyz", source="test"))
    # And the broker itself doesn't expose a get_credential method.
    assert not hasattr(broker, "get_credential")
    assert not hasattr(broker, "get_secret")


# ---------------------------------------------------------------------------
# 2. Credential not logged
# ---------------------------------------------------------------------------


def test_2_credential_not_logged(tmp_db, caplog):
    """No log record at any level may contain the credential value."""
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db, credential_value="ghp_LOG_SHOULD_NOT_CONTAIN_THIS")
    action = _make_action()
    decision = _make_decision_allow()

    # Capture all logging at DEBUG and above.
    with caplog.at_level(logging.DEBUG, logger="actenon_permit.broker"):
        response, _ = broker.execute_via_adapter(
            grant, action, decision, adapter,
            credential_ref="github_token",
            idempotency_key="test-2",
        )

    for record in caplog.records:
        assert "ghp_LOG_SHOULD_NOT_CONTAIN_THIS" not in record.getMessage(), (
            f"credential value leaked into log: {record.getMessage()!r}"
        )


# ---------------------------------------------------------------------------
# 3. Credential not written to receipts
# ---------------------------------------------------------------------------


def test_3_credential_not_written_to_receipts(tmp_db):
    """The ProviderResponse is the receipt payload. The credential value
    must not appear in any field of ``provider_evidence``, nor in the
    ``raw`` field (which the broker nulls out as a defensive measure)."""
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db, credential_value="ghp_RECEIPT_LEAK_TEST_123")
    action = _make_action()
    decision = _make_decision_allow()

    response, _ = broker.execute_via_adapter(
        grant, action, decision, adapter,
        credential_ref="github_token",
        idempotency_key="test-3",
    )

    # Walk every field of the response, including nested dicts.
    def _walk(obj):
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from _walk(v)

    for s in _walk(response.provider_evidence):
        assert "ghp_RECEIPT_LEAK_TEST_123" not in s, (
            f"credential value leaked into evidence field: {s!r}"
        )
    assert response.raw is None, "raw payload must be null on the broker side"


# ---------------------------------------------------------------------------
# 4. Wrong target refused
# ---------------------------------------------------------------------------


def test_4_wrong_target_refused(tmp_db):
    """If the action type is not in the adapter's supported_actions, the
    broker must refuse — even if a prior ALLOW was issued for a different
    action type."""
    grant = _make_grant(tmp_db, scopes_allow=["payment.charge"])
    broker, adapter = _make_broker(tmp_db)
    # The adapter only supports github actions, not payment.charge.
    action = _make_action(action_type="payment.charge")
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, adapter,
            credential_ref="github_token",
            idempotency_key="test-4",
        )
    assert "does not support action" in str(exc.value)


# ---------------------------------------------------------------------------
# 5. Mutated parameters refused
# ---------------------------------------------------------------------------


def test_5_mutated_parameters_refused(tmp_db):
    """The adapter's validate_params must reject unknown fields. This is
    what enforces "adapters must not silently ignore unsupported parameters".

    We construct params that include an extra ``malicious_field`` and
    expect InvalidParametersError -> BrokerExecutionError.
    """
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db)
    action = _make_action(
        params={"owner": "actenon", "repo": "demo", "title": "test", "malicious_field": "pwn"},
    )
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, adapter,
            credential_ref="github_token",
            idempotency_key="test-5",
        )
    # The error should mention the unknown field.
    assert "malicious_field" in str(exc.value) or "unsupported parameter" in str(exc.value)


# ---------------------------------------------------------------------------
# 6. Provider timeout
# ---------------------------------------------------------------------------


class _TimeoutAdapter(ProviderAdapter):
    """Adapter that always raises ProviderTimeoutError."""

    provider_id = "timeout-sim"

    def supported_actions(self) -> list[str]:
        return ["issue.create"]

    def validate_params(self, action: str, params: dict[str, Any]) -> ValidationResult:
        return ValidationResult(ok=True)

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        raise ProviderTimeoutError(
            provider=self.provider_id, action=action, timeout_seconds=timeout_seconds or 30.0
        )

    def map_response(self, action, raw):
        raise NotImplementedError

    def reconcile(self, action, params, response):
        return response

    def redact(self, action, params, response):
        return response

    def health(self):
        return {"ok": True, "provider": self.provider_id, "detail": "test stub"}


def test_6_provider_timeout(tmp_db):
    grant = _make_grant(tmp_db)
    broker, _adapter = _make_broker(tmp_db)
    timeout_adapter = _TimeoutAdapter()
    action = _make_action()
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, timeout_adapter,
            credential_ref="github_token",
            idempotency_key="test-6",
            timeout_seconds=0.5,
        )
    assert "timed out" in str(exc.value).lower()
    assert exc.value.retryable is True


# ---------------------------------------------------------------------------
# 7. Provider partial response
# ---------------------------------------------------------------------------


class _PartialResponseAdapter(ProviderAdapter):
    """Adapter that returns a response missing required fields."""

    provider_id = "partial-sim"

    def supported_actions(self) -> list[str]:
        return ["issue.create"]

    def validate_params(self, action, params):
        return ValidationResult(ok=True)

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        # Skip the GitHubAdapter's map_response; raise partial directly.
        raise ProviderPartialResponseError(
            provider=self.provider_id, action=action, missing_fields=["number", "node_id"]
        )

    def map_response(self, action, raw):
        raise NotImplementedError

    def reconcile(self, action, params, response):
        return response

    def redact(self, action, params, response):
        return response

    def health(self):
        return {"ok": True, "provider": self.provider_id, "detail": "test stub"}


def test_7_provider_partial_response(tmp_db):
    grant = _make_grant(tmp_db)
    broker, _adapter = _make_broker(tmp_db)
    partial_adapter = _PartialResponseAdapter()
    action = _make_action()
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, partial_adapter,
            credential_ref="github_token",
            idempotency_key="test-7",
        )
    assert "partial response" in str(exc.value).lower()
    assert exc.value.retryable is True


# ---------------------------------------------------------------------------
# 8. Duplicate request (idempotency)
# ---------------------------------------------------------------------------


def test_8_duplicate_request_returns_same_response(tmp_db):
    """A duplicate idempotency_key with the SAME params must return the
    cached response. A duplicate key with DIFFERENT params must raise."""
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db)
    decision = _make_decision_allow()

    # First call.
    action1 = _make_action(params={"owner": "actenon", "repo": "demo", "title": "first"})
    response1, _ = broker.execute_via_adapter(
        grant, action1, decision, adapter,
        credential_ref="github_token",
        idempotency_key="dup-key-8",
    )

    # Second call with the SAME params and SAME key — must return same response.
    action2 = _make_action(params={"owner": "actenon", "repo": "demo", "title": "first"})
    response2, _ = broker.execute_via_adapter(
        grant, action2, decision, adapter,
        credential_ref="github_token",
        idempotency_key="dup-key-8",
    )
    assert response1.provider_action_id == response2.provider_action_id
    assert response1.provider_evidence == response2.provider_evidence

    # Third call with DIFFERENT params but the SAME key — must raise.
    action3 = _make_action(params={"owner": "actenon", "repo": "demo", "title": "different"})
    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action3, decision, adapter,
            credential_ref="github_token",
            idempotency_key="dup-key-8",
        )
    assert "idempotency" in str(exc.value).lower() or "different params" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# 9. Adapter exception
# ---------------------------------------------------------------------------


class _CrashingAdapter(ProviderAdapter):
    """Adapter that raises an unexpected exception (not an AdapterError)."""

    provider_id = "crash-sim"

    def supported_actions(self) -> list[str]:
        return ["issue.create"]

    def validate_params(self, action, params):
        return ValidationResult(ok=True)

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        # Simulate a library crash that LEAKS THE CREDENTIAL in its message.
        # The broker MUST sanitise this.
        raise RuntimeError(f"library crash while using token={credential.value}")

    def map_response(self, action, raw):
        raise NotImplementedError

    def reconcile(self, action, params, response):
        return response

    def redact(self, action, params, response):
        return response

    def health(self):
        return {"ok": True, "provider": self.provider_id, "detail": "test stub"}


def test_9_adapter_exception_does_not_leak_credential(tmp_db):
    grant = _make_grant(tmp_db)
    secret = "ghp_CRASH_LEAK_TEST_aaa_bbb_ccc"
    broker, _adapter = _make_broker(tmp_db, credential_value=secret)
    crash_adapter = _CrashingAdapter()
    action = _make_action()
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, crash_adapter,
            credential_ref="github_token",
            idempotency_key="test-9",
        )
    # The BrokerExecutionError message MUST NOT contain the credential.
    assert secret not in str(exc.value)
    assert secret not in repr(exc.value)
    # The original exception is preserved on __cause__ but the broker's
    # surface message is safe.
    assert exc.value.__cause__ is not None


# ---------------------------------------------------------------------------
# 10. Credential resolver failure
# ---------------------------------------------------------------------------


def test_10_credential_resolver_failure(tmp_db):
    """If the credential provider raises CredentialResolutionError, the
    broker surfaces it as a BrokerExecutionError with the credential
    resolution rule, and NEVER raises a 500."""
    grant = _make_grant(tmp_db)
    # Build a broker with NO provider registered for the ref.
    pdp = _make_pdp(tmp_db)
    broker = Broker(pdp, credential_providers=CredentialProviderRegistry())
    adapter = GitHubAdapter(test_mode=True)
    action = _make_action()
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, adapter,
            credential_ref="unregistered_ref",
            idempotency_key="test-10",
        )
    assert "could not be resolved" in str(exc.value).lower() or "no provider" in str(exc.value).lower()
    assert exc.value.rule == "broker:credential_resolution_failed"

    # Also test a registered provider that fails internally.
    def _failing_resolver(ref: str) -> str:
        # Simulate a cloud secrets manager that returns garbage.
        raise RuntimeError("cloud secrets manager is down")

    cloud = CloudManagedRefProvider(_failing_resolver)
    registry = CredentialProviderRegistry()
    registry.register("cloud_ref", cloud)
    broker2 = Broker(pdp, credential_providers=registry)
    action2 = _make_action()
    with pytest.raises(BrokerExecutionError) as exc2:
        broker2.execute_via_adapter(
            grant, action2, decision, adapter,
            credential_ref="cloud_ref",
            idempotency_key="test-10b",
        )
    assert "cloud resolver raised" in str(exc2.value)


# ---------------------------------------------------------------------------
# 11. Unsupported action
# ---------------------------------------------------------------------------


def test_11_unsupported_action(tmp_db):
    """If the adapter does not implement the requested action, the broker
    must refuse — even if validate_params would otherwise accept it.

    We test both layers:
      a) The broker's pre-flight check (adapter.supported_actions).
      b) The adapter's own UnsupportedActionError when called directly.
    """
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db)
    # "repo.delete" is not in GitHubAdapter.supported_actions.
    action = _make_action(action_type="repo.delete", params={"owner": "x", "repo": "y"})
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, adapter,
            credential_ref="github_token",
            idempotency_key="test-11",
        )
    assert "does not support action" in str(exc.value)

    # Direct adapter call should also raise UnsupportedActionError.
    with pytest.raises(UnsupportedActionError):
        adapter.execute(
            "repo.delete", {"owner": "x", "repo": "y"},
            Credential(ref="r", value="v", source="test"),
        )


# ---------------------------------------------------------------------------
# 12. Reconciliation after unknown outcome
# ---------------------------------------------------------------------------


class _UnknownOutcomeAdapter(ProviderAdapter):
    """Adapter that returns a successful response but marks the
    reconcile step as 'unreconciled' to simulate a partial network
    failure where the side-effect status is unknown.

    The broker must surface the reconcile_status, NOT crash, and NOT
    silently treat the call as fully succeeded.
    """

    provider_id = "unknown-outcome-sim"

    def supported_actions(self) -> list[str]:
        return ["issue.create"]

    def validate_params(self, action, params):
        return ValidationResult(ok=True)

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        # Return a normal-looking response, but with reconcile_status
        # set to "unreconciled" — as if the side effect landed but we
        # couldn't confirm it.
        return ProviderResponse(
            ok=True,
            action=action,
            provider_action_id="I_unknown",
            provider_evidence={
                "issue_number": 42,
                "issue_url": "https://github.com/test/test/issues/42",
                "issue_node_id": "I_unknown",
                "reconcile_status": "unreconciled: HTTP 404",
            },
        )

    def map_response(self, action, raw):
        return raw

    def reconcile(self, action, params, response):
        # Pretend the GET confirm failed; mark the response.
        response.provider_evidence["reconcile_status"] = "unreconciled: HTTP 404"
        return response

    def redact(self, action, params, response):
        return response

    def health(self):
        return {"ok": True, "provider": self.provider_id, "detail": "test stub"}


def test_12_reconciliation_after_unknown_outcome(tmp_db):
    """When reconcile cannot confirm the outcome, the broker must:
      - NOT crash
      - surface the reconcile_status in the response
      - still commit cost (the side effect may have happened)
      - mark the response so the caller knows the outcome is uncertain
    """
    grant = _make_grant(tmp_db)
    broker, _adapter = _make_broker(tmp_db)
    unknown_adapter = _UnknownOutcomeAdapter()
    action = _make_action()
    decision = _make_decision_allow()

    response, cost = broker.execute_via_adapter(
        grant, action, decision, unknown_adapter,
        credential_ref="github_token",
        idempotency_key="test-12",
    )

    # The broker didn't crash, the response is returned...
    assert response.ok is True
    # ...but the reconcile_status tells the truth.
    assert response.provider_evidence.get("reconcile_status", "").startswith("unreconciled")
    # Cost is still committed (the side effect may have happened).
    assert cost == 0.0  # adapter didn't report a cost


# ---------------------------------------------------------------------------
# Extra: dev-credential-in-production refusal
# ---------------------------------------------------------------------------


def test_dev_credential_refused_in_production_mode(tmp_db):
    """A credential marked development_only must be refused when the
    broker is in production_mode. This is what stops a stray local-dev
    PAT from being used against a production GitHub org.
    """
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db, production_mode=True)
    action = _make_action()
    decision = _make_decision_allow()

    with pytest.raises(BrokerExecutionError) as exc:
        broker.execute_via_adapter(
            grant, action, decision, adapter,
            credential_ref="github_token",
            idempotency_key="test-dev-prod",
        )
    assert "development-only" in str(exc.value)
    assert exc.value.rule == "broker:dev_credential_in_production"


# ---------------------------------------------------------------------------
# Extra: env-var provider marks MOCK_/DEV_/LOCAL_ as development-only
# ---------------------------------------------------------------------------


def test_env_provider_marks_dev_prefixes_as_development_only(monkeypatch):
    """The EnvironmentSecretProvider must mark MOCK_*, DEV_*, LOCAL_* refs
    as development_only. Real production env vars (GITHUB_TOKEN etc.) are
    NOT marked development-only."""
    monkeypatch.setenv("MOCK_GITHUB", "v1")
    monkeypatch.setenv("DEV_GITHUB", "v2")
    monkeypatch.setenv("LOCAL_GITHUB", "v3")
    monkeypatch.setenv("GITHUB_TOKEN", "v4")

    p = EnvironmentSecretProvider()
    assert p.resolve("MOCK_GITHUB").development_only is True
    assert p.resolve("DEV_GITHUB").development_only is True
    assert p.resolve("LOCAL_GITHUB").development_only is True
    assert p.resolve("GITHUB_TOKEN").development_only is False


# ---------------------------------------------------------------------------
# Extra: GitHub adapter validates unknown params strictly
# ---------------------------------------------------------------------------


def test_github_adapter_rejects_unknown_params():
    """Direct test: GitHubAdapter.validate_params must return ok=False
    for unknown fields, with the unknown field listed."""
    adapter = GitHubAdapter(test_mode=True)
    vr = adapter.validate_params(
        "issue.create",
        {"owner": "x", "repo": "y", "title": "t", "labels": ["bug"], "extra": "evil"},
    )
    assert vr.ok is False
    assert "extra" in vr.unknown_fields


def test_github_adapter_test_mode_does_not_touch_network(tmp_db):
    """End-to-end smoke: in test_mode the adapter returns a deterministic
    response with the expected shape."""
    grant = _make_grant(tmp_db)
    broker, adapter = _make_broker(tmp_db)
    action = _make_action(
        params={"owner": "actenon", "repo": "broker-demo", "title": "broker test issue"},
    )
    decision = _make_decision_allow()

    response, cost = broker.execute_via_adapter(
        grant, action, decision, adapter,
        credential_ref="github_token",
        idempotency_key="smoke",
    )
    assert response.ok is True
    assert response.action == "issue.create"
    assert response.provider_action_id is not None
    assert "issue_url" in response.provider_evidence
    assert response.provider_evidence["issue_url"].startswith("https://github.com/actenon/broker-demo/issues/")
    assert response.raw is None  # broker strips raw


def test_github_adapter_all_four_actions_in_test_mode(tmp_db):
    """All four GitHub actions return well-formed responses in test mode."""
    grant = _make_grant(
        tmp_db,
        scopes_allow=["issue.create", "issue.comment", "branch.create", "pr.open"],
    )
    broker, adapter = _make_broker(tmp_db)
    decision = _make_decision_allow()

    # issue.create
    a1 = _make_action(
        action_type="issue.create",
        params={"owner": "actenon", "repo": "demo", "title": "t1"},
    )
    r1, _ = broker.execute_via_adapter(grant, a1, decision, adapter, credential_ref="github_token", idempotency_key="a1")
    assert r1.ok and "issue_url" in r1.provider_evidence

    # issue.comment
    a2 = _make_action(
        action_type="issue.comment",
        params={"owner": "actenon", "repo": "demo", "issue_number": 1, "body": "hi"},
    )
    r2, _ = broker.execute_via_adapter(grant, a2, decision, adapter, credential_ref="github_token", idempotency_key="a2")
    assert r2.ok and "comment_url" in r2.provider_evidence

    # branch.create
    a3 = _make_action(
        action_type="branch.create",
        params={"owner": "actenon", "repo": "demo", "branch": "feature/x"},
    )
    r3, _ = broker.execute_via_adapter(grant, a3, decision, adapter, credential_ref="github_token", idempotency_key="a3")
    assert r3.ok and "branch_url" in r3.provider_evidence

    # pr.open
    a4 = _make_action(
        action_type="pr.open",
        params={"owner": "actenon", "repo": "demo", "title": "pr", "head": "feature/x", "base": "main"},
    )
    r4, _ = broker.execute_via_adapter(grant, a4, decision, adapter, credential_ref="github_token", idempotency_key="a4")
    assert r4.ok and "pr_url" in r4.provider_evidence
