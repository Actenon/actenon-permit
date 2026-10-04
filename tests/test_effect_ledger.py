"""Attack the real durable store, including independent process clients."""

import multiprocessing as mp
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from actenon_protocol.effects import EFFECT_PROFILE, effect_identity

from actenon_permit.model import Budget, Grant, GrantStatus, Scopes
from actenon_permit.state import SQLiteStore, StateError

DESCRIPTOR = {
    "profile": EFFECT_PROFILE,
    "namespace": "owner:merchant-1",
    "kind": "exact",
    "action_type": "payment.refund",
    "target": {"type": "tool", "id": "payment-123"},
    "parameters": {"amount": 20},
}
ACTION_HASH = "a" * 64


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-test-only-effect-ledger-key")
    path = str(tmp_path / "effect-ledger.db")
    store = SQLiteStore(path)
    grant = Grant(
        agent_id="refund-agent",
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(limit=100, remaining=100),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    ).sign()
    store.put_grant(grant)
    yield store, grant, path
    store.close()


def reserve(store, grant, descriptor=None, amount=20, attempt=None):
    return store.reserve_effect(
        grant_id=grant.id,
        action_id=attempt or "exec_" + uuid4().hex,
        descriptor=descriptor or DESCRIPTOR,
        action_hash=ACTION_HASH,
        principal=grant.agent_id,
        amount=amount,
    )


def owner(grant, snapshot):
    return dict(
        reference=snapshot["effect"],
        grant_id=grant.id,
        principal=grant.agent_id,
        action_hash=ACTION_HASH,
    )


def settle(store, grant, snapshot, outcome, *, reconciliation=False, cost=None, evidence="b" * 64):
    occurred = {"COMMITTED": True, "NOT_EXECUTED": False, "AMBIGUOUS": None}[outcome]
    return store.settle_effect(
        **owner(grant, snapshot),
        outcome=outcome,
        execution_occurred=occurred,
        evidence_hash=evidence,
        observer="boundary:refund",
        reconciliation=reconciliation,
        actual_cost=cost,
    )


def balance(store, grant):
    return store.get_grant(grant.id).budget.remaining


def test_effect_and_budget_reserve_or_fail_together(ledger):
    store, grant, _ = ledger
    ok, _, snap = reserve(store, grant)
    assert ok and balance(store, grant) == 80
    assert store.get_effect(snap["effect"]["effect_id"])[0]["state"] == "RESERVED"
    assert not reserve(store, grant)[0]
    assert balance(store, grant) == 80
    expensive = {**DESCRIPTOR, "target": {"type": "tool", "id": "another-payment"}}
    assert not reserve(store, grant, expensive, amount=90)[0]
    assert store.get_effect(effect_identity(expensive)) == []
    assert balance(store, grant) == 80


def test_failed_effect_insert_rolls_back_budget_debit(ledger):
    store, grant, _ = ledger
    # Force a storage failure AFTER debit; the same transaction must undo it.
    store._conn.execute(
        "CREATE TRIGGER fail_effect BEFORE INSERT ON effect_reservations BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END"
    )
    with pytest.raises(Exception, match="injected disk failure"):
        reserve(store, grant)
    assert balance(store, grant) == 100
    assert store.rate_count(grant.id, 60) == 0
    assert store.get_effect(effect_identity(DESCRIPTOR)) == []


def test_distinct_attempt_or_grant_cannot_duplicate_real_effect(ledger):
    store, grant, _ = ledger
    assert reserve(store, grant)[0]
    other = grant.model_copy(update={"id": "grant-other"}).sign()
    store.put_grant(other)
    assert not reserve(store, other)[0]
    assert balance(store, other) == 100
    assert balance(store, grant) == 80


@pytest.mark.parametrize(
    "change", ["grant", "principal", "action-hash", "attempt", "effect", "reservation"]
)
def test_claim_binds_exact_owner_and_authority(ledger, change):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    args = owner(grant, snap)
    if change == "grant":
        args["grant_id"] = "grant-other"
    elif change == "principal":
        args["principal"] = "other-agent"
    elif change == "action-hash":
        args["action_hash"] = "f" * 64
    else:
        args["reference"] = dict(args["reference"])
        field, val = {
            "attempt": ("owner_attempt_id", "exec_" + "f" * 32),
            "effect": ("effect_id", "effect_" + "f" * 64),
            "reservation": ("reservation_id", "reservation_" + "f" * 32),
        }[change]
        args["reference"][field] = val
    with pytest.raises(StateError):
        store.claim_effect(**args)
    assert store.claim_effect(**owner(grant, snap))
    assert not store.claim_effect(**owner(grant, snap))
    assert balance(store, grant) == 80


def test_lost_response_holds_effect_and_budget_until_reconciled(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    assert store.claim_effect(**owner(grant, snap))
    settle(store, grant, snap, "AMBIGUOUS")
    assert balance(store, grant) == 80
    assert not reserve(store, grant)[0]
    with pytest.raises(StateError, match="requires trusted reconciliation"):
        settle(store, grant, snap, "NOT_EXECUTED")
    assert settle(store, grant, snap, "COMMITTED", reconciliation=True)["remaining"] == 80
    history = store.effect_history(snap["effect"]["effect_id"])
    assert [event["state"] for event in history] == [
        "RESERVED",
        "DISPATCHING",
        "AMBIGUOUS",
        "COMMITTED",
    ]
    assert history[2]["evidence"]["execution_occurred"] is None
    assert history[3]["evidence"]["reconciliation"] is True
    assert not reserve(store, grant)[0]


@pytest.mark.parametrize("state", ["RESERVED", "DISPATCHING", "AMBIGUOUS", "COMMITTED"])
@pytest.mark.parametrize("operation", ["commit", "release"])
def test_legacy_settlement_cannot_bypass_effect_ownership(ledger, state, operation):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    if state != "RESERVED":
        assert store.claim_effect(**owner(grant, snap))
    if state in {"AMBIGUOUS", "COMMITTED"}:
        settle(store, grant, snap, state)
    attempt = snap["effect"]["owner_attempt_id"]
    with pytest.raises(StateError, match="effect-backed"):
        if operation == "commit":
            store.commit(grant.id, attempt, 0, 20)
        else:
            store.release(grant.id, attempt, 20)
    assert balance(store, grant) == 80


def test_not_executed_releases_once_and_retains_history(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    assert store.claim_effect(**owner(grant, snap))
    settle(store, grant, snap, "AMBIGUOUS")
    assert settle(store, grant, snap, "NOT_EXECUTED", reconciliation=True)["remaining"] == 100
    assert settle(store, grant, snap, "NOT_EXECUTED", reconciliation=True)["remaining"] == 100
    with pytest.raises(StateError):
        settle(store, grant, snap, "NOT_EXECUTED", reconciliation=True, evidence="c" * 64)
    # Reuse of the prior attempt is refused; fresh confirmed retry is possible.
    assert not reserve(store, grant, attempt=snap["effect"]["owner_attempt_id"])[0]
    assert reserve(store, grant)[0]
    history = store.get_effect(snap["effect"]["effect_id"])
    assert [r["state"] for r in history] == ["NOT_EXECUTED", "RESERVED"]
    assert balance(store, grant) == 80


def test_signed_reconciliation_cannot_release_a_newer_dispatch(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    reviewed = store.effect_history(snap["effect"]["effect_id"])[-1]["sequence"]
    assert store.claim_effect(**owner(grant, snap))
    with pytest.raises(StateError, match="changed since review"):
        store.settle_effect(
            **owner(grant, snap),
            outcome="NOT_EXECUTED",
            execution_occurred=False,
            evidence_hash="c" * 64,
            observer="operator:reviewed-reservation",
            reconciliation=True,
            expected_event_sequence=reviewed,
        )
    assert balance(store, grant) == 80
    assert store.get_effect(snap["effect"]["effect_id"])[-1]["state"] == "DISPATCHING"
    assert not reserve(store, grant)[0]


@pytest.mark.parametrize("sequence", [True, False, 0, -1, "1", 1.0])
def test_invalid_review_sequence_never_releases_budget(ledger, sequence):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    with pytest.raises(StateError, match="positive integer"):
        store.settle_effect(
            **owner(grant, snap),
            outcome="NOT_EXECUTED",
            execution_occurred=False,
            evidence_hash="c" * 64,
            observer="operator:invalid-sequence",
            reconciliation=True,
            expected_event_sequence=sequence,
        )
    assert balance(store, grant) == 80


def test_reconciliation_snapshot_and_identical_replay_do_not_refund_twice(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    assert store.claim_effect(**owner(grant, snap))
    settle(store, grant, snap, "AMBIGUOUS")
    reviewed = store.get_effect(snap["effect"]["effect_id"])[-1]
    assert reviewed["descriptor"] == DESCRIPTOR
    assert (
        reviewed["event_sequence"]
        == store.effect_history(snap["effect"]["effect_id"])[-1]["sequence"]
    )
    args = dict(
        **owner(grant, snap),
        outcome="NOT_EXECUTED",
        execution_occurred=False,
        evidence_hash="c" * 64,
        observer="operator:reviewed-ambiguity",
        reconciliation=True,
        expected_event_sequence=reviewed["event_sequence"],
    )
    assert store.settle_effect(**args)["remaining"] == 100
    assert store.settle_effect(**args)["remaining"] == 100
    assert balance(store, grant) == 100
    assert [r["state"] for r in store.effect_history(snap["effect"]["effect_id"])].count(
        "NOT_EXECUTED"
    ) == 1


def test_confirmed_nonexecution_restores_exhausted_grant(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant, amount=100)
    assert store.get_grant(grant.id).status == GrantStatus.EXHAUSTED
    assert store.claim_effect(**owner(grant, snap))
    settle(store, grant, snap, "NOT_EXECUTED")
    assert store.get_grant(grant.id).status == GrantStatus.ACTIVE
    assert reserve(store, grant)[0]


def test_refund_does_not_reactivate_revoked_grant(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant, amount=100)
    store.set_status(grant.id, GrantStatus.REVOKED)
    settle(store, grant, snap, "NOT_EXECUTED")
    assert store.get_grant(grant.id).status == GrantStatus.REVOKED
    with pytest.raises(StateError):
        reserve(store, grant)


def test_committed_settlement_is_once_and_cost_overrun_is_debited(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    assert store.claim_effect(**owner(grant, snap))
    assert settle(store, grant, snap, "COMMITTED", cost=30)["remaining"] == 70
    assert settle(store, grant, snap, "COMMITTED", cost=30)["remaining"] == 70
    with pytest.raises(StateError):
        settle(store, grant, snap, "COMMITTED", cost=0)
    assert not reserve(store, grant)[0]
    assert balance(store, grant) == 70


def test_unclaimed_or_contradictory_result_never_refunds(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    with pytest.raises(StateError):
        settle(store, grant, snap, "COMMITTED")
    with pytest.raises(ValueError):
        store.settle_effect(
            **owner(grant, snap),
            outcome="AMBIGUOUS",
            execution_occurred=False,
            evidence_hash="b" * 64,
            observer="boundary:refund",
        )
    assert balance(store, grant) == 80


def test_distinct_parameters_and_reviewed_semantic_key(ledger):
    store, grant, _ = ledger
    assert reserve(store, grant)[0]
    assert reserve(store, grant, {**DESCRIPTOR, "parameters": {"amount": 30}})[0]
    semantic = {k: v for k, v in DESCRIPTOR.items() if k != "parameters"}
    semantic.update(kind="semantic", semantic_key={"refund_of": "original-charge-123"})
    assert reserve(store, grant, semantic)[0]
    assert not reserve(store, grant, semantic)[0]
    assert balance(store, grant) == 40


def test_two_independent_store_clients_reserve_once(ledger):
    store, grant, path = ledger

    def attempt(_):
        client = SQLiteStore(path)
        try:
            return reserve(client, grant)[0]
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [False, True]
    assert balance(store, grant) == 80


def _process_attempt(path, grant_id, ready, start, results, crash=False):
    client = SQLiteStore(path)
    grant = client.get_grant(grant_id)
    ready.put(True)
    if not start.wait(10):
        raise RuntimeError("process start timeout")
    result = reserve(client, grant)
    if crash:
        os._exit(37)
    results.put(result[0])
    client.close()


def test_two_processes_reserve_one_effect_and_one_budget_debit(ledger):
    store, grant, path = ledger
    ctx = mp.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    workers = [
        ctx.Process(target=_process_attempt, args=(path, grant.id, ready, start, results))
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
    finally:
        start.set()
        for worker in workers:
            if worker.is_alive():
                worker.kill()
                worker.join(5)
    assert balance(store, grant) == 80


def test_crashed_reservation_is_durable_and_cannot_retry(ledger):
    store, grant, path = ledger
    ctx = mp.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    worker = ctx.Process(
        target=_process_attempt, args=(path, grant.id, ready, start, results, True)
    )
    try:
        worker.start()
        assert ready.get(timeout=10)
        start.set()
        worker.join(10)
        assert worker.exitcode == 37
        reopened = SQLiteStore(path)
        try:
            assert not reserve(reopened, grant)[0]
            assert balance(reopened, grant) == 80
            assert reopened.get_effect(effect_identity(DESCRIPTOR))[0]["state"] == "RESERVED"
        finally:
            reopened.close()
    finally:
        if worker.is_alive():
            worker.kill()
            worker.join(5)


def test_real_pdp_mints_signed_effect_only_after_policy_and_atomic_debit(ledger):
    from actenon_permit import PDP, Action, DecisionOutcome, Ledger
    from actenon_permit.kernel_bridge import effect_attempt_id

    store, grant, _ = ledger
    pdp = PDP(store, Ledger(store))
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="payment-123",
        params={"amount": 20},
        est_cost=20,
    )
    decision, intent, proof = pdp.decide_and_mint_pccb(
        grant, action, effect_namespace="owner:merchant-1"
    )
    assert decision.outcome == DecisionOutcome.ALLOW, decision.reason
    assert intent.intent_id == effect_attempt_id(action)
    assert proof.extensions["effect"] == decision.state_delta["effect"]
    assert proof.extensions["authority"]["grant_id"] == grant.id
    assert proof.extensions["effect"]["effect_id"] == effect_identity(DESCRIPTOR)
    assert balance(store, grant) == 80
    retry = action.model_copy(update={"action_id": "act_new_nonce"})
    denied, absent_intent, absent_proof = pdp.decide_and_mint_pccb(
        store.get_grant(grant.id), retry, effect_namespace="owner:merchant-1"
    )
    assert denied.outcome == DecisionOutcome.DENY
    assert absent_intent is None and absent_proof is None
    assert balance(store, grant) == 80


def test_effect_policy_denial_and_approval_cannot_be_bypassed_by_context(ledger):
    from actenon_permit import PDP, Action, DecisionOutcome, Ledger

    store, grant, _ = ledger
    pdp = PDP(store, Ledger(store))
    action = Action(
        grant_id=grant.id,
        type="payment.delete",
        target="payment-123",
        params={"amount": 20},
        est_cost=20,
    )
    denied, _, _ = pdp.decide_and_mint_pccb(grant, action, effect_namespace="owner:merchant-1")
    assert denied.outcome == DecisionOutcome.DENY
    assert balance(store, grant) == 100
    # Policy is immutable under a grant identity. Issue a new grant for the
    # approval-required policy; never use import to overwrite live authority.
    grant = grant.model_copy(deep=True, update={"id": "grant_approval_required"})
    grant.approval_rules = ["payment.refund > 10"]
    grant.sign()
    store.put_grant(grant)
    action.grant_id = grant.id
    action.type = "payment.refund"
    waiting, _, _ = pdp.decide_and_mint_pccb(
        grant,
        action,
        ctx={"approved_action_id": action.action_id},
        effect_namespace="owner:merchant-1",
    )
    assert waiting.outcome == DecisionOutcome.REQUIRE_APPROVAL
    assert balance(store, grant) == 100
    assert store.get_effect(effect_identity(DESCRIPTOR)) == []


def test_overrun_debt_survives_reopen_and_refunds_pay_debt_first(ledger):
    store, grant, path = ledger
    _, _, original = reserve(store, grant, amount=80)
    other = {**DESCRIPTOR, "target": {"type": "tool", "id": "payment-other"}}
    _, _, waiting = reserve(store, grant, descriptor=other, amount=20)
    assert store.claim_effect(**owner(grant, original))
    assert settle(store, grant, original, "COMMITTED", cost=110)["remaining"] == 0
    assert balance(store, grant) == 0
    assert store.get_grant(grant.id).status == GrantStatus.EXHAUSTED
    assert store.get_effect(original["effect"]["effect_id"])[0]["state"] == "COMMITTED"
    reopened = SQLiteStore(path)
    try:
        assert (
            reopened._conn.execute(
                "SELECT amount FROM budget_overruns WHERE grant_id = ?", (grant.id,)
            ).fetchone()[0]
            == 30
        )
        # Confirmed non-execution of the other effect returns 20, all to debt.
        assert settle(reopened, grant, waiting, "NOT_EXECUTED")["remaining"] == 0
        assert (
            reopened._conn.execute(
                "SELECT amount FROM budget_overruns WHERE grant_id = ?", (grant.id,)
            ).fetchone()[0]
            == 10
        )
        assert not reserve(reopened, grant, {**other, "parameters": {"amount": 1}}, amount=1)[0]
        assert settle(reopened, grant, original, "COMMITTED", cost=110)["remaining"] == 0
    finally:
        reopened.close()


def test_review_expiring_while_waiting_for_store_lock_cannot_refund(ledger):
    store, grant, path = ledger
    _, _, snap = reserve(store, grant)
    assert store.claim_effect(**owner(grant, snap))
    settle(store, grant, snap, "AMBIGUOUS")
    reviewed = store.get_effect(snap["effect"]["effect_id"])[-1]
    contender = SQLiteStore(path)
    started = threading.Event()
    deadline = datetime.now(UTC) + timedelta(milliseconds=150)

    def reconcile():
        started.set()
        return contender.settle_effect(
            **owner(grant, snap),
            outcome="NOT_EXECUTED",
            execution_occurred=False,
            evidence_hash="c" * 64,
            observer="operator:expires-while-waiting",
            reconciliation=True,
            expected_event_sequence=reviewed["event_sequence"],
            review_expires_at=deadline,
        )

    store._conn.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(reconcile)
            assert started.wait(2)
            # A distinct store client holds the database until the review expires.
            threading.Event().wait(0.2)
            assert datetime.now(UTC) > deadline
            store._conn.execute("ROLLBACK")
            with pytest.raises(StateError, match="expired before settlement"):
                task.result(timeout=5)
    finally:
        if store._conn.in_transaction:
            store._conn.execute("ROLLBACK")
        contender.close()
    assert balance(store, grant) == 80
    assert store.get_effect(snap["effect"]["effect_id"])[-1]["state"] == "AMBIGUOUS"


def test_settlement_audit_time_is_stable_for_identical_terminal_replay(ledger):
    store, grant, _ = ledger
    _, _, snap = reserve(store, grant)
    reviewed = store.get_effect(snap["effect"]["effect_id"])[-1]
    deadline = datetime.now(UTC) + timedelta(seconds=10)
    args = dict(
        **owner(grant, snap),
        outcome="NOT_EXECUTED",
        execution_occurred=False,
        evidence_hash="c" * 64,
        observer="operator:confirmed-nonexecution",
        reconciliation=True,
        expected_event_sequence=reviewed["event_sequence"],
        review_expires_at=deadline,
    )
    result = store.settle_effect(**args)
    assert datetime.fromisoformat(result["settled_at"]) < deadline
    assert store.settle_effect(**args)["settled_at"] == result["settled_at"]
