"""A signed finite effect grant cannot authorize a different consequence."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from actenon_protocol.effects import EFFECT_PROFILE, effect_identity

from actenon_permit.ledger import Ledger
from actenon_permit.model import Action, Budget, DecisionOutcome, Grant, Scopes
from actenon_permit.pdp import PDP
from actenon_permit.state import SQLiteStore, StateError

DESCRIPTOR = {
    "profile": EFFECT_PROFILE,
    "namespace": "owner:publication-store",
    "kind": "semantic",
    "action_type": "http.put",
    "target": {"type": "tool", "id": "https://artifacts.example/report"},
    "semantic_key": {"method": "PUT", "body_sha256": "a" * 64},
}
APPROVED = effect_identity(DESCRIPTOR)


@pytest.fixture
def authority(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-exact-effect-grant-test-key")
    store = SQLiteStore(str(tmp_path / "effects.db"))
    grant = Grant(
        agent_id="publisher",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["http.put"]),
        budget=Budget(limit=10, remaining=10),
        approved_effect_ids=[APPROVED],
    ).sign()
    store.put_grant(grant)
    yield store, grant
    store.close()


def reserve(store, grant, descriptor=DESCRIPTOR):
    return store.reserve_effect(
        grant_id=grant.id,
        action_id="exec_" + uuid4().hex,
        descriptor=descriptor,
        principal=grant.agent_id,
        action_hash="b" * 64,
        amount=1,
    )


@pytest.mark.parametrize("field", ["body", "method", "target", "namespace", "action"])
def test_another_effect_is_refused_without_budget_debit(authority, field):
    store, grant = authority
    changed = deepcopy(DESCRIPTOR)
    if field == "body":
        changed["semantic_key"]["body_sha256"] = "c" * 64
    elif field == "method":
        changed["semantic_key"]["method"] = "DELETE"
    elif field == "target":
        changed["target"]["id"] += "-another"
    elif field == "namespace":
        changed["namespace"] = "owner:another"
    else:
        changed["action_type"] = "http.delete"
    assert not reserve(store, grant, changed)[0], "A finite signed grant authorized X-prime"
    assert store.get_grant(grant.id).budget.remaining == 10
    assert store.get_effect(effect_identity(changed)) == []


def test_exact_effect_is_reserved_and_claimed_once(authority):
    store, grant = authority
    ok, _, snapshot = reserve(store, grant)
    assert ok
    args = dict(
        reference=snapshot["effect"],
        grant_id=grant.id,
        principal=grant.agent_id,
        action_hash="b" * 64,
    )
    assert store.claim_effect(**args)
    assert not store.claim_effect(**args)
    assert not reserve(store, grant)[0]


def test_legacy_reservation_cannot_skip_exact_effect_authority(authority):
    store, grant = authority
    assert not store.reserve(grant.id, "legacy", 1, 0, 60)[0]
    assert store.get_grant(grant.id).budget.remaining == 10


def test_plain_pdp_cannot_bypass_constraint_with_approved_action_id(authority):
    store, grant = authority
    action = Action(grant_id=grant.id, type="http.put", target=DESCRIPTOR["target"]["id"])
    decision = PDP(store, Ledger(store)).decide(
        grant, action, {"approved_action_id": action.action_id}
    )
    assert decision.outcome == DecisionOutcome.DENY
    assert store.get_grant(grant.id).budget.remaining == 10


def test_empty_finite_set_denies_every_effect(authority):
    store, grant = authority
    empty = grant.model_copy(update={"id": "grant_empty", "approved_effect_ids": []}).sign()
    store.put_grant(empty)
    assert not reserve(store, empty)[0]


def test_effect_set_is_signed_and_survives_token_roundtrip(authority):
    from actenon_permit.token import grant_to_token, token_to_grant

    _, grant = authority
    decoded = token_to_grant(grant_to_token(grant))
    assert decoded.approved_effect_ids == [APPROVED]
    decoded.approved_effect_ids = None
    assert not decoded.verify()


def test_dispatch_rechecks_current_signed_finite_constraint(authority):
    store, grant = authority
    _, _, snapshot = reserve(store, grant)
    # Trusted issuer narrows a stored authority after reservation, before edge use.
    narrower = store.get_grant(grant.id)
    narrower.approved_effect_ids = []
    narrower.sign()
    store._conn.execute(
        "UPDATE grants SET body = ? WHERE id = ?", (narrower.model_dump_json(), grant.id)
    )
    with pytest.raises(StateError, match="effect.*approv"):
        store.claim_effect(
            reference=snapshot["effect"],
            grant_id=grant.id,
            principal=grant.agent_id,
            action_hash="b" * 64,
        )
    assert store.get_effect(APPROVED)[0]["state"] == "RESERVED"


def test_attenuation_preserves_or_narrows_the_finite_set(authority):
    store, parent = authority
    child = parent.attenuate(agent_id="child")
    assert child.approved_effect_ids == [APPROVED]
    empty = parent.attenuate(approved_effect_ids=[])
    assert empty.approved_effect_ids == []
    with pytest.raises(ValueError, match="effect"):
        parent.attenuate(approved_effect_ids=["effect_" + "f" * 64])
    store.put_grant(child)
    assert reserve(store, child)[0]


def test_hand_signed_child_cannot_widen_finite_parent(authority):
    store, parent = authority
    child = (
        parent.attenuate(agent_id="child").model_copy(update={"approved_effect_ids": None}).sign()
    )
    store.put_grant(child)
    with pytest.raises(StateError, match="widens its parent"):
        reserve(store, child)
    assert store.get_grant(parent.id).budget.remaining == 10


@pytest.mark.parametrize(
    "value",
    [
        "*",
        ["*"],
        ["effect_" + "F" * 64],
        [APPROVED, APPROVED],
        [None],
        [1],
        [True],
        {APPROVED: True},
    ],
)
def test_malformed_effect_constraints_are_not_authority(authority, value):
    _, grant = authority
    with pytest.raises(ValueError, match="approved_effect_ids"):
        Grant.model_validate({**grant.model_dump(), "approved_effect_ids": value})


def test_legacy_scope_grant_has_identical_signing_and_token_bytes(authority):
    from actenon_permit.model import authority_payload, sign
    from actenon_permit.token import grant_to_token, token_to_grant

    _, grant = authority
    data = grant.model_dump(mode="json")
    data.pop("approved_effect_ids")
    data["signature"] = sign(authority_payload(data))
    legacy = Grant.model_validate(data)
    assert legacy.verify() and "approved_effect_ids" not in legacy.model_dump()
    assert token_to_grant(grant_to_token(legacy)).verify()


def descriptor_for_intent(intent):
    return {
        **DESCRIPTOR,
        "action_type": intent.action.capability,
        "target": {"type": intent.target.resource_type, "id": intent.target.resource_id},
        "semantic_key": {
            name: intent.action.parameters[name] for name in ("method", "body_sha256")
        },
    }


def test_real_signed_proof_and_independent_kernel_enforce_exact_grant(
    authority, tmp_path, monkeypatch
):
    from dataclasses import replace
    from functools import partial

    from actenon.execution.effects import EffectProtector
    from actenon.gate import ActenonGate
    from actenon.replay import ReplayProtector, SqliteReplayStore

    from actenon_permit.boundary.proofs import Ed25519PublicKeyVerifier
    from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair
    from actenon_permit.kernel_bridge import claim_effect_at_edge
    from actenon_permit.revocation import StoreRevocationChecker

    store, grant = authority
    key = generate_ed25519_keypair()
    key_path = tmp_path / "public-test-key.json"
    save_ed25519_keypair(key, key_path)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))
    action = Action(
        grant_id=grant.id,
        type="http.put",
        target=DESCRIPTOR["target"]["id"],
        params=DESCRIPTOR["semantic_key"],
        est_cost=1,
    )
    pdp = PDP(store, Ledger(store))
    # An explicit signed exact grant satisfies human approval for this effect only.
    grant.approval_rules = ["http.put"]
    grant.sign()
    store._conn.execute(
        "UPDATE grants SET body = ? WHERE id = ?", (grant.model_dump_json(), grant.id)
    )
    decision, intent, proof = pdp.decide_and_mint_pccb(
        grant,
        action,
        effect_namespace=DESCRIPTOR["namespace"],
        effect_descriptor_builder=descriptor_for_intent,
    )
    assert decision.outcome == DecisionOutcome.ALLOW, decision.reason
    edge = ActenonGate(
        verifier=Ed25519PublicKeyVerifier([key.public_key_jwk]),
        audience="service:actenon-permit-gateway",
        issuer="service:actenon-permit",
        capabilities=("http.put",),
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.db")),
        revocation_checker=StoreRevocationChecker(store),
        effect_protector=EffectProtector(
            DESCRIPTOR["namespace"],
            partial(claim_effect_at_edge, store=store),
            lambda request: descriptor_for_intent(request.intent),
        ),
    )
    calls = []
    changed = replace(
        intent, action=replace(intent.action, parameters={"method": "PUT", "body_sha256": "f" * 64})
    )
    assert not edge.protect(changed, proof, lambda: calls.append("changed")).ok
    assert calls == []
    reference = proof.extensions["effect"]

    def execute():
        calls.append("exact")
        return {
            "effect_evidence": {
                **reference,
                "outcome": "COMMITTED",
                "execution_occurred": True,
                "evidence_hash": "d" * 64,
            }
        }

    result = edge.protect(intent, proof, execute)
    assert result.ok, result.reason_code
    assert not edge.protect(intent, proof, execute).ok
    other = action.model_copy(
        update={"action_id": "action_changed", "params": {"method": "PUT", "body_sha256": "f" * 64}}
    )
    denied, _, absent = pdp.decide_and_mint_pccb(
        store.get_grant(grant.id),
        other,
        effect_namespace=DESCRIPTOR["namespace"],
        effect_descriptor_builder=descriptor_for_intent,
    )
    assert denied.outcome == DecisionOutcome.DENY and absent is None
    assert calls == ["exact"]


def test_frozen_token_vectors_match_typescript(authority, monkeypatch):
    import json
    from pathlib import Path

    from actenon_permit.token import TokenError, grant_to_token, token_to_grant

    vectors = json.loads(
        (Path(__file__).parents[1] / "ts-sdk/tests/vectors/exact_effect_tokens.json").read_text()
    )
    monkeypatch.setenv("ACTENON_SIGNING_KEY", vectors["signing_key"])
    for vector in vectors["valid"]:
        grant = token_to_grant(vector["token"])
        assert grant.approved_effect_ids == vector["approved_effect_ids"]
        assert grant_to_token(grant) == vector["token"]
    for vector in vectors["invalid"]:
        with pytest.raises(TokenError):
            token_to_grant(vector["token"])
