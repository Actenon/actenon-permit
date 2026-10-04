"""Budget settlement must spend only a real, matching reservation, once."""
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from actenon_permit.model import Budget, Grant, Scopes
from actenon_permit.state import SQLiteStore, StateError


@pytest.fixture
def reserved(tmp_path):
    path = str(tmp_path / "state.sqlite3")
    store = SQLiteStore(path)
    grant = Grant(agent_id="settlement-agent", scopes=Scopes(allow=["payment.refund"]),
                  expires_at=datetime.now(UTC) + timedelta(hours=1),
                  budget=Budget(limit=100, remaining=100)).sign()
    store.put_grant(grant)
    assert store.reserve(grant.id, "action-original", 20, 0, 60)[0]
    try:
        yield store, grant, path
    finally:
        store.close()


def remaining(store, grant):
    return store.get_grant(grant.id).budget.remaining


@pytest.mark.parametrize("operation", ["commit", "release"])
def test_missing_reservation_cannot_increase_budget(reserved, operation):
    store, grant, _ = reserved
    with pytest.raises(StateError):
        if operation == "commit":
            store.commit(grant.id, "made-up-action", 0, 20)
        else:
            store.release(grant.id, "made-up-action", 20)
    assert remaining(store, grant) == 80


@pytest.mark.parametrize("operation", ["commit", "release"])
def test_settlement_amount_must_match_durable_reservation(reserved, operation):
    store, grant, _ = reserved
    with pytest.raises(StateError):
        if operation == "commit":
            store.commit(grant.id, "action-original", 0, 90)
        else:
            store.release(grant.id, "action-original", 90)
    assert remaining(store, grant) == 80
    assert store.rate_count(grant.id, 60) == 1


@pytest.mark.parametrize("operation", ["commit", "release"])
def test_other_grant_cannot_spend_this_reservation(reserved, operation):
    store, original, _ = reserved
    other = Grant(agent_id="other", expires_at=datetime.now(UTC) + timedelta(hours=1),
                  budget=Budget(limit=100, remaining=100)).sign()
    store.put_grant(other)
    with pytest.raises(StateError):
        if operation == "commit":
            store.commit(other.id, "action-original", 0, 20)
        else:
            store.release(other.id, "action-original", 20)
    assert remaining(store, original) == 80
    assert remaining(store, other) == 100
    assert store.rate_count(original.id, 60) == 1


def test_replayed_commit_does_not_refund_twice_even_after_reopen(reserved):
    store, grant, path = reserved
    assert store.commit(grant.id, "action-original", 10, 20) == 90
    another = SQLiteStore(path)
    try:
        assert another.commit(grant.id, "action-original", 10, 20) == 90
    finally:
        another.close()
    assert remaining(store, grant) == 90


def test_committed_reservation_cannot_change_cost_or_be_released(reserved):
    store, grant, _ = reserved
    store.commit(grant.id, "action-original", 10, 20)
    with pytest.raises(StateError):
        store.commit(grant.id, "action-original", 0, 20)
    with pytest.raises(StateError):
        store.release(grant.id, "action-original", 20)
    assert remaining(store, grant) == 90


def test_replayed_release_is_refused_without_budget_change(reserved):
    store, grant, _ = reserved
    assert store.release(grant.id, "action-original", 20) == 100
    with pytest.raises(StateError):
        store.release(grant.id, "action-original", 20)
    assert remaining(store, grant) == 100
    assert store.rate_count(grant.id, 60) == 0


def test_released_approval_request_can_reserve_again(reserved):
    store, grant, _ = reserved
    store.release(grant.id, "action-original", 20)
    assert store.reserve(grant.id, "action-original", 20, 0, 60)[0]
    assert store.commit(grant.id, "action-original", 20, 20) == 80


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), Decimal("NaN"), Decimal("Infinity"), True])
def test_invalid_cost_cannot_modify_a_reservation(reserved, value):
    store, grant, _ = reserved
    with pytest.raises(StateError):
        store.commit(grant.id, "action-original", value, 20)
    assert remaining(store, grant) == 80
    assert store._conn.execute("SELECT committed FROM rate_events WHERE action_id = ?", ("action-original",)).fetchone()[0] == 0


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True])
def test_invalid_reservation_is_not_recorded(reserved, value):
    store, grant, _ = reserved
    with pytest.raises(StateError):
        store.reserve(grant.id, "invalid-action", value, 0, 60)
    assert remaining(store, grant) == 80
    assert store.rate_count(grant.id, 60) == 1


def test_two_store_clients_settle_same_action_only_once(reserved):
    store, grant, path = reserved
    def settle(_):
        client = SQLiteStore(path)
        try:
            return client.commit(grant.id, "action-original", 10, 20)
        finally:
            client.close()
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(settle, range(2))) == [90, 90]
    assert remaining(store, grant) == 90


def _settle_in_process(path, grant_id, ready, start, results):
    client = SQLiteStore(path)
    try:
        ready.put(True)
        assert start.wait(10)
        results.put(client.commit(grant_id, "action-original", 10, 20))
    finally:
        client.close()


def test_two_processes_settle_same_action_only_once(reserved):
    store, grant, path = reserved
    ctx = mp.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    workers = [ctx.Process(target=_settle_in_process, args=(path, grant.id, ready, start, results)) for _ in range(2)]
    try:
        for worker in workers:
            worker.start()
        assert ready.get(timeout=10) and ready.get(timeout=10)
        start.set()
        assert sorted([results.get(timeout=10), results.get(timeout=10)]) == [90, 90]
        for worker in workers:
            worker.join(10)
            assert worker.exitcode == 0
    finally:
        start.set()
        for worker in workers:
            if worker.is_alive():
                worker.kill()
                worker.join(5)
    assert remaining(store, grant) == 90


def test_writes_are_durable_before_releasing_a_consequence(reserved):
    store, _, _ = reserved
    assert store._conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
