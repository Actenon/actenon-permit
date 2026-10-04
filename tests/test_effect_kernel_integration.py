"""Real Permit decisions + signed proofs + independent Kernel + durable ledger."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from functools import partial

import pytest
from actenon.execution.effects import EffectProtector
from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore

from actenon_permit import PDP, Action, Budget, DecisionOutcome, Grant, Ledger, Scopes, SQLiteStore
from actenon_permit.boundary.proofs import Ed25519PublicKeyVerifier
from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair
from actenon_permit.kernel_bridge import claim_effect_at_edge, verify_pccb_at_edge
from actenon_permit.revocation import StoreRevocationChecker

NAMESPACE = "merchant:effect-integration"


@pytest.fixture
def integrated(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-effect-integration-key-not-secret")
    keypair = generate_ed25519_keypair(key_id="effect-proof-test-key")
    key_path = tmp_path / "test-only-private-key.json"
    save_ed25519_keypair(keypair, key_path)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))
    verifier = Ed25519PublicKeyVerifier([keypair.public_key_jwk])
    store = SQLiteStore(str(tmp_path / "authority.db"))
    grant = Grant(
        agent_id="external-agent",
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(limit=100, remaining=100),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    ).sign()
    store.put_grant(grant)
    pdp = PDP(store, Ledger(store))
    edge = ActenonGate(
        verifier=verifier,
        audience="service:actenon-permit-gateway",
        issuer="service:actenon-permit",
        capabilities=("payment.refund",),
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "replay.db")),
        revocation_checker=StoreRevocationChecker(store),
        effect_protector=EffectProtector(NAMESPACE, partial(claim_effect_at_edge, store=store)),
    )
    yield store, grant, pdp, edge
    store.close()


def mint(grant, pdp, *, amount=20, target="payment-123"):
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target=target,
        params={"amount": amount},
        est_cost=amount,
    )
    decision, intent, proof = pdp.decide_and_mint_pccb(grant, action, effect_namespace=NAMESPACE)
    assert decision.outcome == DecisionOutcome.ALLOW, decision.reason
    return action, intent, proof


def settle(store, grant, intent, proof, outcome, *, reconciliation=False):
    return store.settle_effect(
        reference=proof.extensions["effect"],
        grant_id=grant.id,
        principal=intent.requester.id,
        action_hash=proof.action_hash.value,
        outcome=outcome,
        execution_occurred={"COMMITTED": True, "NOT_EXECUTED": False, "AMBIGUOUS": None}[outcome],
        evidence_hash="b" * 64,
        observer="provider:refund",
        reconciliation=reconciliation,
    )["effect"]


def test_allow_exact_bound_consequence_and_refuse_new_attempt(integrated):
    store, grant, pdp, edge = integrated
    _, intent, proof = mint(grant, pdp)
    calls = []

    def provider(request, _credential):
        assert request.intent.action.parameters == {"amount": 20}
        assert request.intent.target.resource_id == "payment-123"
        calls.append(request.intent.intent_id)
        return {"effect_evidence": settle(store, grant, intent, proof, "COMMITTED")}

    result = edge.protect(intent, proof, provider)
    assert result.ok, result.reason_code
    assert result.receipt.extensions["effect"]["outcome"] == "COMMITTED"
    assert not edge.protect(intent, proof, provider).ok
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="payment-123",
        params={"amount": 20},
        est_cost=20,
    )
    denied, _, absent = pdp.decide_and_mint_pccb(
        store.get_grant(grant.id), action, effect_namespace=NAMESPACE
    )
    assert denied.outcome == DecisionOutcome.DENY and absent is None
    assert len(calls) == 1
    assert store.get_grant(grant.id).budget.remaining == 80


def test_provider_commits_loses_response_no_fresh_proof_retry_or_refund(integrated):
    store, grant, pdp, edge = integrated
    _, intent, proof = mint(grant, pdp)
    calls = []

    def provider():
        calls.append("remote committed")
        raise TimeoutError("reply lost")

    result = edge.protect(intent, proof, provider)
    assert not result.ok and result.reason_code == "OUTCOME_UNKNOWN"
    assert result.receipt.extensions["effect"]["outcome"] == "AMBIGUOUS"
    settle(store, grant, intent, proof, "AMBIGUOUS")
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="payment-123",
        params={"amount": 20},
        est_cost=20,
    )
    assert (
        pdp.decide_and_mint_pccb(store.get_grant(grant.id), action, effect_namespace=NAMESPACE)[
            0
        ].outcome
        == DecisionOutcome.DENY
    )
    assert store.get_grant(grant.id).budget.remaining == 80
    settle(store, grant, intent, proof, "COMMITTED", reconciliation=True)
    assert store.get_effect(proof.extensions["effect"]["effect_id"])[0]["state"] == "COMMITTED"
    assert calls == ["remote committed"]


def test_crash_after_dispatch_claim_is_not_a_lease_or_new_nonce_escape(integrated):
    store, grant, pdp, edge = integrated
    _, intent, proof = mint(grant, pdp)
    claim = partial(claim_effect_at_edge, store=store)
    from actenon.execution.effects import EffectReference
    from actenon.models.runtime import ProtectedExecutionRequest

    request = ProtectedExecutionRequest(
        intent, proof, edge._build_context(intent, audience=edge.audience)
    )
    assert claim(EffectReference.from_dict(proof.extensions["effect"]), request)
    # Simulate process death before entering handler: still DISPATCHING.
    calls = []
    assert not edge.protect(intent, proof, lambda: calls.append(True) or {}).ok
    assert calls == []
    assert store.get_grant(grant.id).budget.remaining == 80
    settle(store, grant, intent, proof, "NOT_EXECUTED", reconciliation=True)
    assert store.get_grant(grant.id).budget.remaining == 100
    _, new_intent, new_proof = mint(store.get_grant(grant.id), pdp)
    assert edge.protect(
        new_intent,
        new_proof,
        lambda: {"effect_evidence": settle(store, grant, new_intent, new_proof, "COMMITTED")},
    ).ok


def test_gateway_verifier_cannot_ignore_effect_contract(integrated):
    from actenon.core.errors import ProofVerificationError

    store, grant, pdp, _ = integrated
    action, intent, proof = mint(grant, pdp)
    with pytest.raises(ProofVerificationError, match="ownership"):
        verify_pccb_at_edge(intent, proof, grant, action, store=store)
    assert store.get_effect(proof.extensions["effect"]["effect_id"])[0]["state"] == "RESERVED"


def test_two_real_kernel_edges_share_only_one_dispatch_owner(integrated):
    store, grant, pdp, edge = integrated
    _, intent, proof = mint(grant, pdp)
    # Independent replay stores do not replace shared effect ownership.
    other = ActenonGate(
        verifier=edge._verifier,
        audience=edge.audience,
        issuer=edge.issuer,
        capabilities=("payment.refund",),
        replay_protector=ReplayProtector(SqliteReplayStore(store.db_path + ".other-replay")),
        revocation_checker=StoreRevocationChecker(store),
        effect_protector=EffectProtector(NAMESPACE, partial(claim_effect_at_edge, store=store)),
    )
    calls = []

    def provider():
        calls.append(True)
        return {"effect_evidence": settle(store, grant, intent, proof, "COMMITTED")}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda gate: gate.protect(intent, proof, provider).ok, [edge, other])
        )
    assert sorted(results) == [False, True]
    assert calls == [True]
    assert store.get_grant(grant.id).budget.remaining == 80


def _process_edge(path, intent_payload, proof_payload, public_key, ready, start, results):
    import os

    from actenon.models import PCCB, ActionIntent

    store = SQLiteStore(path)
    intent, proof = ActionIntent.from_dict(intent_payload), PCCB.from_dict(proof_payload)
    edge = ActenonGate(
        verifier=Ed25519PublicKeyVerifier([public_key]),
        audience="service:actenon-permit-gateway",
        issuer="service:actenon-permit",
        capabilities=("payment.refund",),
        replay_protector=ReplayProtector(SqliteReplayStore(path + f".replay-{os.getpid()}")),
        revocation_checker=StoreRevocationChecker(store),
        effect_protector=EffectProtector(NAMESPACE, partial(claim_effect_at_edge, store=store)),
    )

    def consequence():
        # Append is the observed local provider consequence, not a mock count.
        fd = os.open(path + ".provider-effects", os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, b"committed\n")
        finally:
            os.close(fd)
        evidence = store.settle_effect(
            reference=proof.extensions["effect"],
            grant_id=proof.extensions["authority"]["grant_id"],
            principal=intent.requester.id,
            action_hash=proof.action_hash.value,
            outcome="COMMITTED",
            execution_occurred=True,
            evidence_hash="b" * 64,
            observer="boundary:process-test",
        )["effect"]
        return {"effect_evidence": evidence}

    try:
        ready.put(True)
        if not start.wait(10):
            raise RuntimeError("start timeout")
        results.put(edge.protect(intent, proof, consequence).ok)
    finally:
        store.close()


def test_two_processes_verify_real_proof_and_mutate_provider_once(integrated):
    import multiprocessing as mp
    import os
    from pathlib import Path

    from actenon_permit.ed25519_signer import load_ed25519_keypair

    store, grant, pdp, _ = integrated
    _, intent, proof = mint(grant, pdp)
    public_key = load_ed25519_keypair(Path(os.environ["ACTENON_ED25519_KEY_FILE"])).public_key_jwk
    ctx = mp.get_context("spawn")
    ready, start, results = ctx.Queue(), ctx.Event(), ctx.Queue()
    workers = [
        ctx.Process(
            target=_process_edge,
            args=(
                store.db_path,
                intent.to_dict(),
                proof.to_dict(),
                public_key,
                ready,
                start,
                results,
            ),
        )
        for _ in range(2)
    ]
    try:
        for worker in workers:
            worker.start()
        assert ready.get(timeout=10) and ready.get(timeout=10)
        start.set()
        assert sorted([results.get(timeout=10), results.get(timeout=10)]) == [False, True]
        for worker in workers:
            worker.join(10)
            assert worker.exitcode == 0
        assert Path(store.db_path + ".provider-effects").read_text() == "committed\n"
        assert store.get_grant(grant.id).budget.remaining == 80
    finally:
        start.set()
        for worker in workers:
            if worker.is_alive():
                worker.kill()
                worker.join(5)
