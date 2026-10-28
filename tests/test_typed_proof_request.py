"""Typed request identity through the real bridge and GitHub serializer.

HTTP transport is captured, never sent. These tests demonstrate dispatch
representation, not a provider accepting malformed payloads or a live exploit.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from actenon.core.errors import ProofVerificationError

from actenon_permit.adapters.github import GitHubAdapter
from actenon_permit.credentials import Credential
from actenon_permit.kernel_bridge import (
    KernelBridgeError,
    _permit_action_to_kernel_intent,
    verify_pccb_at_edge,
)
from actenon_permit.ledger import Ledger
from actenon_permit.model import Action, Budget, DecisionOutcome, Grant, Scopes
from actenon_permit.pdp import PDP
from actenon_permit.state import SQLiteStore


@pytest.fixture
def authority(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-typed-request-regression-key")
    store = SQLiteStore(str(tmp_path / "state.db"))
    grant = Grant(
        agent_id="typed-request-test",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        scopes=Scopes(allow=["github.issue.create", "github.issue.comment", "test.typed"]),
        budget=Budget(limit=10, remaining=10),
    ).sign()
    store.put_grant(grant)
    yield store, grant, PDP(store, Ledger(store))
    store.close()


def github_action(grant, body):
    return Action(
        grant_id=grant.id,
        type="github.issue.create",
        target="https://api.github.com/repos/disposable/example/issues",
        params={"owner": "disposable", "repo": "example", "title": "typed request", "body": body},
        est_cost=1,
    )


def captured_adapter(monkeypatch):
    adapter = GitHubAdapter(test_mode=False)
    requests = []

    def capture(request, timeout):
        requests.append({"url": request.full_url, "body": json.loads(request.data)})
        return {
            "id": 42,
            "number": 1,
            "node_id": "public-node-42",
            "html_url": "https://github.com/disposable/example/issues/1",
        }

    monkeypatch.setattr(adapter, "_http_send", capture)
    return adapter, requests


def execute(adapter, action):
    return adapter.execute(
        action.type,
        action.params,
        Credential(ref="test", value="public-dummy-not-a-token", source="test"),
    )


def test_string_proof_cannot_authorize_numeric_actual_github_body(authority, monkeypatch):
    store, grant, pdp = authority
    action = github_action(grant, "1.0")
    decision, intent, proof = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome == DecisionOutcome.ALLOW
    attempted = action.model_copy(update={"params": {**action.params, "body": 1.0}})
    adapter, requests = captured_adapter(monkeypatch)
    try:
        verify_pccb_at_edge(intent, proof, grant, attempted, store=store)
    except (KernelBridgeError, ProofVerificationError):
        pass
    else:
        execute(adapter, attempted)
    assert requests == [], (
        "A proof binding a string body reached the actual GitHub serializer with a float: "
        f"{requests!r}. This is captured transport, not evidence of a live provider side effect."
    )


@pytest.mark.parametrize(
    "value",
    [1.0, -0.0, float("nan"), float("inf"), (1, 2), {"nested": [1.0]}, {"nested": [(1, 2)]}],
)
def test_unsupported_parameters_refused_before_policy_or_debit(authority, monkeypatch, value):
    store, grant, pdp = authority
    action = Action(grant_id=grant.id, type="test.typed", params={"value": value}, est_cost=1)
    calls = []
    original = pdp.decide

    def observed(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(pdp, "decide", observed)
    decision, intent, proof = pdp.decide_and_mint_pccb(grant, action)
    assert (decision.outcome, intent, proof) == (DecisionOutcome.DENY, None, None)
    assert calls == [], "Unsupported representation reached policy evaluation"
    assert store.get_grant(grant.id).budget.remaining == 10


@pytest.mark.parametrize("value", [1.0, (1, 2), {"nested": [1.0]}])
def test_direct_bridge_cannot_bypass_typed_validation(authority, value):
    _, grant, _ = authority
    action = Action(grant_id=grant.id, type="test.typed", params={"value": value})
    with pytest.raises(KernelBridgeError):
        _permit_action_to_kernel_intent(grant, action)


@pytest.mark.parametrize(
    "value", ["1.0", True, 1, [1, 2], {"nested": ["雪", "é", "e\u0301", 2**100, -(2**100)]}]
)
def test_supported_parameters_are_typed_and_unchanged(authority, value):
    store, grant, pdp = authority
    action = Action(grant_id=grant.id, type="test.typed", params={"value": value}, est_cost=1)
    decision, intent, proof = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome == DecisionOutcome.ALLOW
    assert json.dumps(intent.action.parameters, ensure_ascii=False) == json.dumps(
        action.params, ensure_ascii=False
    )
    verify_pccb_at_edge(intent, proof, grant, action, store=store)


def test_boolean_and_integer_have_different_proof_hashes(authority):
    store, grant, pdp = authority
    action = Action(grant_id=grant.id, type="test.typed", params={"value": True})
    _, intent, proof = pdp.decide_and_mint_pccb(grant, action)
    attempted = action.model_copy(update={"params": {"value": 1}})
    with pytest.raises(ProofVerificationError):
        verify_pccb_at_edge(intent, proof, grant, attempted, store=store)


def test_valid_github_body_matches_verified_typed_request(authority, monkeypatch):
    store, grant, pdp = authority
    action = github_action(grant, "Fixed stdout/stderr deadlock — 雪")
    decision, intent, proof = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome == DecisionOutcome.ALLOW
    verify_pccb_at_edge(intent, proof, grant, action, store=store)
    adapter, requests = captured_adapter(monkeypatch)
    execute(adapter, action)
    assert requests == [
        {
            "url": action.target,
            "body": {"title": action.params["title"], "body": intent.action.parameters["body"]},
        }
    ]


@pytest.mark.parametrize(
    "field,value",
    [("body", 1.0), ("body", ["nested"]), ("labels", [1]), ("labels", [{"name": "bug"}])],
)
def test_github_adapter_rejects_wrong_optional_types(field, value):
    params = {"owner": "disposable", "repo": "example", "title": "test", field: value}
    assert not GitHubAdapter().validate_params("github.issue.create", params).ok


def test_github_issue_number_cannot_be_boolean():
    params = {"owner": "disposable", "repo": "example", "body": "test", "issue_number": True}
    assert not GitHubAdapter().validate_params("github.issue.comment", params).ok


@pytest.mark.parametrize("value", [["bug"], {"nested": ["雪", 2**100]}, ("bug",), {"nested": 1.0}])
def test_gateway_proves_every_parameter_it_dispatches(authority, monkeypatch, value):
    from actenon_permit import Broker, Gateway, ToolRegistry
    from actenon_permit.token import grant_to_token

    store, grant, pdp = authority
    called, proven = [], []
    registry = ToolRegistry()
    registry.register(
        "typed", action_type="test.typed", real_call=lambda **params: called.append(params)
    )
    gateway = Gateway(
        state=store, ledger=Ledger(store), pdp=pdp, broker=Broker(pdp), tools=registry
    )
    original = pdp.decide_and_mint_pccb

    def record(*args, **kwargs):
        decision, intent, proof = original(*args, **kwargs)
        if intent is not None:
            proven.append(intent.action.parameters)
        return decision, intent, proof

    monkeypatch.setattr(pdp, "decide_and_mint_pccb", record)
    result = gateway.call_tool("typed", {"value": value}, grant_to_token(grant))
    if type(value) is tuple or isinstance(value, dict) and isinstance(value.get("nested"), float):
        assert result["outcome"] == "DENY"
        assert called == []
    else:
        assert result["outcome"] == "ALLOW", result
        assert proven == called == [{"value": value}], (
            "Gateway dropped nested authority before dispatch"
        )


def test_typed_snapshot_is_owned_before_normative_validation(monkeypatch):
    from actenon_protocol import canonicalisation

    from actenon_permit.kernel_bridge import _canonicalize_params

    supplied = {"value": ["reviewed"]}
    original = canonicalisation.canonicalize_bytes

    def mutate_caller_after_check(value, **kwargs):
        checked = original(value, **kwargs)
        # Deterministic scheduling point for a mutation of caller-owned input.
        supplied["value"].append("unreviewed")
        return checked

    monkeypatch.setattr(canonicalisation, "canonicalize_bytes", mutate_caller_after_check)
    snapshot = _canonicalize_params(supplied)
    assert snapshot == {"value": ["reviewed"]}
    assert supplied == {"value": ["reviewed", "unreviewed"]}
