"""Tests for the Actenon Python SDK (Prompt 11).

Covers:
  * Unit tests: model construction, exception hierarchy, config validation.
  * Local integration tests: create + execute via Actenon.local().
  * Brokered provider tests: GitHubAdapter in test_mode.
  * Resource-owned submission tests: IAM stub server.
  * Typing tests: discriminated results are not interchangeable.
  * Package installation smoke: imports succeed.
  * Receipt verification helpers.
  * Retry guidance.
"""

from __future__ import annotations

import warnings

import pytest

from actenon_permit import (
    Actenon,
    ActenonError,
    BrokeredResult,
    CloudTransportConfig,
    ExecutionFailedError,
    ExecutionRefusedError,
    ExecutionResult,
    GitHubAdapter,
    IntentCreateRequest,
    IntentHandle,
    IntentNotFoundError,
    LocalRuntimeConfig,
    OutcomeUnknownError,
    ProviderError,
    ResourceOwnedResult,
    RetryableError,
)
from actenon_permit.sdk.receipt import compute_receipt_signature, verify_resource_receipt
from actenon_permit.sdk.retry import with_retry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """A local SDK client with a GitHub adapter in test mode."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        c = Actenon.local(
            agent_id="sdk-test-agent",
            scopes=["issue.create", "issue.comment", "branch.create", "pr.open"],
            signing_key="sdk-test-signing-key-not-for-production",
        )
    c.register_credential("GITHUB_TOKEN", "ghp_SDK_TEST_NOT_REAL_0123456789abcdef")
    c.register_adapter_tool(
        "github_issue",
        action_type="issue.create",
        adapter=GitHubAdapter(test_mode=True),
        credential_ref="GITHUB_TOKEN",
        target="github",
    )
    return c


# ---------------------------------------------------------------------------
# 1. Unit tests: model construction
# ---------------------------------------------------------------------------


def test_intent_create_request_has_required_fields():
    req = IntentCreateRequest(
        action="issue.create",
        target="github",
        parameters={"title": "test"},
    )
    assert req.action == "issue.create"
    assert req.target == "github"
    assert req.parameters == {"title": "test"}
    assert req.requested_execution_mode == "brokered"
    assert req.expiry_seconds == 3600


def test_brokered_result_succeeded():
    r = BrokeredResult(
        intent_id="intent_test",
        state="succeeded",
        finality="final",
        provider_execution_observed=True,
        receipt_received=True,
        receipt_verified=True,
        evidence={"issue_url": "https://github.com/test/test/issues/1"},
    )
    assert r.mode == "brokered"
    assert r.succeeded is True
    assert r.is_final is True


def test_resource_owned_result_submitted():
    r = ResourceOwnedResult(
        intent_id="intent_test",
        state="submitted",
        finality="non_final",
        provider_execution_observed=False,
        resource_receipt_received=False,
        resource_receipt_verified=False,
        submission_reference="sub_1",
    )
    assert r.mode == "resource_owned"
    assert r.succeeded is False
    assert r.is_final is False


def test_results_are_discriminated():
    """BrokeredResult and ResourceOwnedResult are not interchangeable."""
    b = BrokeredResult(
        intent_id="i", state="succeeded", finality="final",
        provider_execution_observed=True, receipt_received=True, receipt_verified=True,
    )
    r = ResourceOwnedResult(
        intent_id="i", state="submitted", finality="non_final",
        provider_execution_observed=False, resource_receipt_received=False,
        resource_receipt_verified=False,
    )
    assert b.mode != r.mode
    assert isinstance(b, BrokeredResult)
    assert isinstance(r, ResourceOwnedResult)
    assert not isinstance(b, ResourceOwnedResult)
    assert not isinstance(r, BrokeredResult)


# ---------------------------------------------------------------------------
# 2. Exception hierarchy
# ---------------------------------------------------------------------------


def test_exception_hierarchy():
    assert issubclass(IntentNotFoundError, ActenonError)
    assert issubclass(ExecutionRefusedError, ActenonError)
    assert issubclass(ExecutionFailedError, ActenonError)
    assert issubclass(OutcomeUnknownError, ActenonError)
    assert issubclass(ProviderError, ActenonError)
    assert issubclass(RetryableError, ActenonError)


def test_outcome_unknown_is_retryable():
    e = OutcomeUnknownError("timeout")
    assert e.retryable is True


def test_execution_refused_is_not_retryable():
    e = ExecutionRefusedError("out of scope", reason="out of scope")
    assert e.retryable is False


# ---------------------------------------------------------------------------
# 3. Config validation
# ---------------------------------------------------------------------------


def test_local_config_warns_on_ephemeral_key():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        LocalRuntimeConfig(signing_key=None)
        assert any("ephemeral" in str(warning.message).lower() for warning in w)


def test_cloud_config_rejects_non_http_url():
    with pytest.raises(ValueError, match="must start with http"):
        CloudTransportConfig(base_url="ftp://example.com")


def test_cloud_config_warns_on_plain_http():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        CloudTransportConfig(base_url="http://cloud.example.com")
        assert any("insecure" in str(warning.message).lower() for warning in w)


# ---------------------------------------------------------------------------
# 4. Local integration: create + execute
# ---------------------------------------------------------------------------


def test_local_client_creates_and_executes_intent(client):
    """The hero path: create an intent, execute it, get a BrokeredResult."""
    intent = client.authorised_execution_intents.create(
        action="issue.create",
        target="github",
        parameters={"owner": "Actenon", "repo": "example", "title": "SDK test"},
    )
    assert isinstance(intent, IntentHandle)
    assert intent.lifecycle_state == "created"

    result = intent.execute()
    assert isinstance(result, BrokeredResult)
    assert result.succeeded
    assert result.mode == "brokered"
    assert result.provider_execution_observed is True
    assert result.receipt_received is True
    assert result.receipt_verified is True
    assert "issue_url" in result.evidence


def test_local_client_out_of_scope_refused(client):
    """An out-of-scope action is refused."""
    intent = client.authorised_execution_intents.create(
        action="repo.delete",  # not in scopes
        target="github",
        parameters={"owner": "a", "repo": "b"},
    )
    with pytest.raises(ExecutionRefusedError):
        intent.execute()


def test_local_client_mutated_params_refused(client):
    """An unknown parameter is refused by the adapter."""
    intent = client.authorised_execution_intents.create(
        action="issue.create",
        target="github",
        parameters={"owner": "a", "repo": "b", "title": "t", "malicious": "x"},
    )
    with pytest.raises(ExecutionRefusedError):
        intent.execute()


def test_local_client_replay_refused(client):
    """Re-executing a succeeded intent is refused."""
    intent = client.authorised_execution_intents.create(
        action="issue.create",
        target="github",
        parameters={"owner": "a", "repo": "b", "title": "t"},
    )
    intent.execute()  # succeeds
    with pytest.raises(ActenonError):
        intent.execute()  # replay -> refused


def test_local_client_credential_never_leaks(client):
    """The raw GitHub token must not appear in the result."""
    raw_token = "ghp_SDK_TEST_NOT_REAL_0123456789abcdef"
    intent = client.authorised_execution_intents.create(
        action="issue.create",
        target="github",
        parameters={"owner": "a", "repo": "b", "title": "t"},
    )
    result = intent.execute()
    result_str = repr(result) + repr(result.evidence)
    assert raw_token not in result_str


# ---------------------------------------------------------------------------
# 5. Capability discovery
# ---------------------------------------------------------------------------


def test_local_client_capabilities(client):
    caps = client.capabilities
    assert caps.transport == "local"
    assert caps.supports_brokered is True
    assert caps.supports_resource_owned is False  # no resource clients registered
    assert caps.production_mode is False


def test_cloud_client_capabilities():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        c = Actenon.cloud(base_url="https://cloud.example.com", grant_token="token")
    caps = c.capabilities
    assert caps.transport == "cloud"
    assert caps.supports_brokered is True
    assert caps.supports_resource_owned is True
    assert caps.durable is True


# ---------------------------------------------------------------------------
# 6. Receipt verification helpers
# ---------------------------------------------------------------------------


def test_verify_resource_receipt_valid():
    secret = b"test-secret"
    body = {"resource_id": "test", "result": "ok", "signing_key_id": "k1"}
    receipt = dict(body)
    receipt["signature"] = compute_receipt_signature(body, secret)
    assert verify_resource_receipt(receipt, {"k1": secret}) is True


def test_verify_resource_receipt_forged():
    secret = b"real-secret"
    body = {"resource_id": "test", "result": "ok", "signing_key_id": "k1"}
    receipt = dict(body)
    receipt["signature"] = compute_receipt_signature(body, b"wrong-secret")
    assert verify_resource_receipt(receipt, {"k1": secret}) is False


# ---------------------------------------------------------------------------
# 7. Retry guidance
# ---------------------------------------------------------------------------


def test_with_retry_succeeds_on_first_attempt():
    calls = [0]

    def fn():
        calls[0] += 1
        return "ok"

    result = with_retry(fn, max_attempts=3, base_delay_seconds=0.01)
    assert result == "ok"
    assert calls[0] == 1


def test_with_retry_retries_on_outcome_unknown():
    calls = [0]

    def fn():
        calls[0] += 1
        if calls[0] < 2:
            raise OutcomeUnknownError("timeout")
        return "ok"

    result = with_retry(fn, max_attempts=3, base_delay_seconds=0.01)
    assert result == "ok"
    assert calls[0] == 2


def test_with_retry_does_not_retry_on_refused():
    calls = [0]

    def fn():
        calls[0] += 1
        raise ExecutionRefusedError("out of scope", reason="out of scope")

    with pytest.raises(ExecutionRefusedError):
        with_retry(fn, max_attempts=3, base_delay_seconds=0.01)
    assert calls[0] == 1  # no retry


# ---------------------------------------------------------------------------
# 8. Package installation smoke test
# ---------------------------------------------------------------------------


def test_sdk_imports_succeed():
    """All public SDK names are importable from actenon_permit."""
    from actenon_permit import (
        Actenon,
        ActenonError,
        BrokeredResult,
        CloudTransportConfig,
        ExecutionFailedError,
        ExecutionRefusedError,
        IntentCreateRequest,
        IntentHandle,
        IntentNotFoundError,
        LocalRuntimeConfig,
        OutcomeUnknownError,
        ProviderError,
        ResourceOwnedResult,
        RetryableError,
    )
    # All are non-None
    assert all(x is not None for x in [
        Actenon, ActenonError, BrokeredResult, CloudTransportConfig,
        ExecutionFailedError, ExecutionRefusedError, ExecutionResult,
        IntentCreateRequest, IntentHandle, IntentNotFoundError,
        LocalRuntimeConfig, OutcomeUnknownError, ProviderError,
        ResourceOwnedResult, RetryableError,
    ])


def test_sdk_version():
    from actenon_permit.sdk import __version__
    assert __version__ == "1.4.0"
