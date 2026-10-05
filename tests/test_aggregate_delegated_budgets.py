"""Delegation must share ancestor spending, including independent store clients."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from actenon_protocol.effects import EFFECT_PROFILE

from actenon_permit.model import Budget, Grant, GrantStatus, Rate, Scopes
from actenon_permit.state import SQLiteStore, StateError


@pytest.fixture
def family(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-test-only-shared-budget-key")
    path = str(tmp_path / "delegated-budget.sqlite3")
    store = SQLiteStore(path)
    parent = Grant(
        agent_id="owner",
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(limit=50, remaining=50),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    ).sign()
    children = [parent.attenuate(agent_id="agent-" + str(i), budget_limit=40) for i in range(2)]
    for grant in [parent, *children]:
        store.put_grant(grant)
    yield store, path, parent, children
    store.close()


def reserve(store, child, index, amount=30):
    return store.reserve_effect(
        grant_id=child.id,
        action_id="exec_" + format(index, "016x"),
        descriptor={
            "profile": EFFECT_PROFILE,
            "namespace": "owner:shared-finance",
            "kind": "exact",
            "action_type": "payment.refund",
            "target": {"type": "tool", "id": "payment-" + str(index)},
            "parameters": {"amount": 30},
        },
        action_hash=f"{index + 1:064x}",
        principal=child.agent_id,
        amount=Decimal(str(amount)),
    )


def test_siblings_cannot_amplify_a_parent_budget(family):
    store, _, parent, children = family
    first = reserve(store, children[0], 0)
    assert first[0]
    second = reserve(store, children[1], 1)
    assert not second[0], "Two child grants spent 60 against a shared parent limit of 50"
    assert store.get_grant(parent.id).budget.remaining == Decimal("20")
    assert store.get_grant(children[0].id).budget.remaining == Decimal("10")
    assert store.get_grant(children[1].id).budget.remaining == Decimal("40")


def test_independent_clients_atomically_share_the_ancestor_budget(family):
    store, path, parent, children = family
    barrier = threading.Barrier(2)

    def attempt(index):
        client = SQLiteStore(path)
        try:
            barrier.wait(timeout=5)
            return reserve(client, children[index], index)[0]
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sum(results) == 1, "Independent clients both spent an ancestor's remaining authority"
    assert store.get_grant(parent.id).budget.remaining == Decimal("20")
    balances = [store.get_grant(child.id).budget.remaining for child in children]
    assert sorted(balances) == [Decimal("10"), Decimal("40")]


def settle(store, child, result, outcome, *, cost=None, reconcile=False):
    reference = result[2]["effect"]
    return store.settle_effect(
        reference=reference,
        grant_id=child.id,
        principal=child.agent_id,
        action_hash=f"{int(reference['owner_attempt_id'][5:], 16) + 1:064x}",
        outcome=outcome,
        execution_occurred={"COMMITTED": True, "NOT_EXECUTED": False, "AMBIGUOUS": None}[outcome],
        observer="trusted-test-boundary",
        evidence_hash="e" * 64,
        actual_cost=cost,
        reconciliation=reconcile,
    )


def claim(store, child, result):
    reference = result[2]["effect"]
    return store.claim_effect(
        reference=reference,
        grant_id=child.id,
        principal=child.agent_id,
        action_hash=f"{int(reference['owner_attempt_id'][5:], 16) + 1:064x}",
    )


def test_not_executed_refunds_every_owner_once(family):
    store, _, parent, children = family
    result = reserve(store, children[0], 0)
    settle(store, children[0], result, "NOT_EXECUTED")
    settle(store, children[0], result, "NOT_EXECUTED")
    assert store.get_grant(parent.id).budget.remaining == 50
    assert store.get_grant(children[0].id).budget.remaining == 40
    assert store.rate_count(parent.id, 60) == 0


def test_actual_cost_and_replay_settle_the_frozen_chain(family):
    store, _, parent, children = family
    result = reserve(store, children[0], 0)
    assert claim(store, children[0], result)
    settle(store, children[0], result, "COMMITTED", cost=20)
    settle(store, children[0], result, "COMMITTED", cost=20)
    assert store.get_grant(parent.id).budget.remaining == 30
    assert store.get_grant(children[0].id).budget.remaining == 20
    assert store.rate_count(parent.id, 60) == 1


def test_ambiguity_and_reopen_hold_all_owners(family):
    store, path, parent, children = family
    result = reserve(store, children[0], 0)
    assert claim(store, children[0], result)
    settle(store, children[0], result, "AMBIGUOUS")
    with pytest.raises(StateError, match="reconciliation"):
        settle(store, children[0], result, "NOT_EXECUTED")
    client = SQLiteStore(path)
    try:
        assert not reserve(client, children[1], 1)[0]
        assert client.get_grant(parent.id).budget.remaining == 20
        settle(client, children[0], result, "NOT_EXECUTED", reconcile=True)
        assert client.get_grant(parent.id).budget.remaining == 50
        assert client.get_grant(children[0].id).budget.remaining == 40
    finally:
        client.close()


def test_parent_overrun_is_durable_and_blocks_siblings(family):
    store, path, parent, children = family
    result = reserve(store, children[0], 0)
    assert claim(store, children[0], result)
    settle(store, children[0], result, "COMMITTED", cost=70)
    client = SQLiteStore(path)
    try:
        assert not reserve(client, children[1], 1, amount=1)[0]
        assert client.get_grant(parent.id).budget.remaining == 0
        assert (
            client._conn.execute(
                "SELECT amount_units FROM budget_overruns WHERE grant_id = ?", (parent.id,)
            ).fetchone()[0]
            == "20000000000"
        )
        assert (
            client._conn.execute(
                "SELECT amount_units FROM budget_overruns WHERE grant_id = ?", (children[0].id,)
            ).fetchone()[0]
            == "30000000000"
        )
    finally:
        client.close()


def test_legacy_reserve_and_settlement_cannot_skip_parent_accounting(family):
    store, _, parent, children = family
    assert store.reserve(children[0].id, "legacy-action", 30, 0, 60)[0]
    assert not store.reserve(children[1].id, "legacy-sibling", 30, 0, 60)[0]
    assert store.commit(children[0].id, "legacy-action", 20, 30) == 20
    assert store.get_grant(parent.id).budget.remaining == 30


def test_nested_delegation_charges_root_and_each_intermediate(family):
    store, _, parent, children = family
    grandchild = children[0].attenuate(agent_id="grandchild", budget_limit=35)
    store.put_grant(grandchild)
    result = reserve(store, grandchild, 0)
    assert result[0]
    assert result[2]["budget_owners"] == [grandchild.id, children[0].id, parent.id]
    assert [store.get_grant(g.id).budget.remaining for g in (parent, children[0], grandchild)] == [
        20,
        10,
        5,
    ]
    settle(store, grandchild, result, "NOT_EXECUTED")
    assert [store.get_grant(g.id).budget.remaining for g in (parent, children[0], grandchild)] == [
        50,
        40,
        35,
    ]


def test_aggregate_rate_applies_across_siblings(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-test-rate-key")
    store = SQLiteStore(str(tmp_path / "rate.db"))
    try:
        parent = Grant(
            agent_id="root",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            budget=Budget(limit=100, remaining=100),
            rate=Rate(max=1, per_seconds=60),
        ).sign()
        children = [parent.attenuate(agent_id=f"child-{i}", budget_limit=50) for i in range(2)]
        for grant in (parent, *children):
            store.put_grant(grant)
        assert store.reserve(children[0].id, "rate-one", 1, 0, 60)[0]
        assert not store.reserve(children[1].id, "rate-two", 1, 0, 60)[0]
        assert store.rate_count(parent.id, 60) == 1
        store.release(children[0].id, "rate-one", 1)
        assert store.reserve(children[1].id, "rate-two", 1, 0, 60)[0]
    finally:
        store.close()


@pytest.mark.parametrize("defect", ["missing", "signature", "currency", "cycle", "expiry", "scope"])
def test_invalid_lineage_is_refused_without_any_charge(family, defect):
    store, _, parent, children = family
    child = children[0]
    if defect == "missing":
        store._conn.execute("DELETE FROM grants WHERE id = ?", (parent.id,))
    else:
        changed = parent.model_copy(deep=True)
        if defect == "signature":
            changed.signature = "invalid"
        elif defect == "currency":
            changed.budget.currency = "EUR"
        elif defect == "cycle":
            changed.parent_grant_id = child.id
        elif defect == "expiry":
            changed.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        elif defect == "scope":
            changed.scopes.allow = ["payment.read"]
        if defect != "signature":
            changed.sign()
        store._conn.execute(
            "UPDATE grants SET body = ? WHERE id = ?", (changed.model_dump_json(), parent.id)
        )
    assert not store.reserve(child.id, "invalid-lineage", 1, 0, 60)[0]
    assert store.get_grant(child.id).budget.remaining == 40
    assert store._conn.execute("SELECT COUNT(*) FROM rate_events").fetchone()[0] == 0


def test_revoked_parent_cannot_dispatch_a_paid_child_reservation(family):
    store, _, parent, children = family
    result = reserve(store, children[0], 0)
    store.set_status(parent.id, GrantStatus.REVOKED)
    with pytest.raises(StateError, match="revoked"):
        claim(store, children[0], result)
    settle(store, children[0], result, "NOT_EXECUTED")
    assert store.get_grant(parent.id).status == GrantStatus.REVOKED
    assert store.get_grant(parent.id).budget.remaining == 50


def test_known_parent_debt_stops_another_paid_reservation(family):
    store, _, parent, children = family
    first = reserve(store, children[0], 0, amount=20)
    second = reserve(store, children[1], 1, amount=30)
    assert first[0] and second[0]
    assert claim(store, children[0], first)
    settle(store, children[0], first, "COMMITTED", cost=60)
    with pytest.raises(StateError, match="overrun"):
        claim(store, children[1], second)
    settle(store, children[1], second, "NOT_EXECUTED")
    assert store.get_grant(parent.id).budget.remaining == 0
    assert (
        store._conn.execute(
            "SELECT amount_units FROM budget_overruns WHERE grant_id = ?", (parent.id,)
        ).fetchone()[0]
        == "10000000000"
    )


def test_legacy_child_holds_migrate_to_parent_once_across_clients(family):
    store, path, parent, children = family
    result = reserve(store, children[0], 0)
    # Reconstruct the old independent-child database state, retaining its
    # original cost/effect evidence. The old engine did not debit the parent.
    store._conn.execute("DELETE FROM reservation_budget_owners")
    store._conn.execute(
        "UPDATE grants SET body = ?, remaining = 50, remaining_units = '50000000000', status = 'active' WHERE id = ?",
        (parent.model_dump_json(), parent.id),
    )
    barrier = threading.Barrier(4)

    def reopen(_):
        barrier.wait(timeout=10)
        client = SQLiteStore(path)
        try:
            assert client.get_grant(parent.id).budget.remaining == 20
            return client._conn.execute(
                "SELECT COUNT(*) FROM reservation_budget_owners"
            ).fetchone()[0]
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(reopen, range(4))) == [2] * 4
    assert not reserve(store, children[1], 1)[0]
    settle(store, children[0], result, "NOT_EXECUTED")
    assert store.get_grant(parent.id).budget.remaining == 50


def test_invalid_legacy_lineage_cannot_half_migrate(family):
    store, path, parent, children = family
    assert reserve(store, children[0], 0)[0]
    store._conn.execute("DELETE FROM reservation_budget_owners")
    store._conn.execute("DELETE FROM grants WHERE id = ?", (parent.id,))
    before = store.get_grant(children[0].id).model_dump_json()
    with pytest.raises(StateError, match="missing"):
        SQLiteStore(path)
    assert store.get_grant(children[0].id).model_dump_json() == before
    assert store._conn.execute("SELECT COUNT(*) FROM reservation_budget_owners").fetchone()[0] == 0


def test_failed_settlement_cannot_refund_only_one_owner(family, monkeypatch):
    store, _, parent, children = family
    result = reserve(store, children[0], 0)
    original = store._write_owner_balance

    def interrupt_after_write(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("injected settlement storage failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_write_owner_balance", interrupt_after_write)
        with pytest.raises(OSError, match="storage failure"):
            settle(store, children[0], result, "NOT_EXECUTED")
    assert store.get_grant(parent.id).budget.remaining == 20
    assert store.get_grant(children[0].id).budget.remaining == 10
    assert store.get_effect(result[2]["effect"]["effect_id"])[0]["state"] == "RESERVED"
    settle(store, children[0], result, "NOT_EXECUTED")
    assert store.get_grant(parent.id).budget.remaining == 50


def test_independent_clients_settle_shared_cost_once(family):
    store, path, parent, children = family
    result = reserve(store, children[0], 0)
    assert claim(store, children[0], result)
    barrier = threading.Barrier(2)

    def finish(_):
        client = SQLiteStore(path)
        try:
            barrier.wait(timeout=5)
            return settle(client, children[0], result, "COMMITTED", cost=20)["remaining_exact"]
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(finish, range(2))) == ["20.000000000"] * 2
    assert store.get_grant(parent.id).budget.remaining == 30
    assert store.get_grant(children[0].id).budget.remaining == 20
