"""Precision migrations retain real SQLite transaction ownership and data."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from threading import Barrier

import pytest

from actenon_permit import Budget, Grant, Scopes, SQLiteStore
from actenon_permit.state import StateError

COLUMNS = (
    ("grants", "remaining_units"),
    ("rate_events", "reserved_units"),
    ("rate_events", "actual_units"),
    ("budget_overruns", "amount_units"),
    ("effect_reservations", "reserved_units"),
)


def legacy(path):
    store = SQLiteStore(path)
    grant = Grant(
        agent_id="migrating-agent",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(limit=50, remaining=50),
    ).sign()
    store.put_grant(grant)
    assert store.reserve(grant.id, "held-old-charge", 30, 0, 60)[0]
    for table, column in COLUMNS:
        store._conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    before = store.get_grant(grant.id).model_dump_json()
    store.close()
    return grant, before


def test_independent_clients_migrate_existing_held_budget_once(tmp_path):
    path = str(tmp_path / "shared.db")
    grant, _ = legacy(path)
    barrier = Barrier(4)

    def owner(_):
        barrier.wait(timeout=10)
        store = SQLiteStore(path)
        try:
            current = store.get_grant(grant.id)
            assert current.verify()
            assert Decimal("19.99999999") <= current.budget.remaining <= Decimal("20")
            assert not store.reserve(grant.id, "too-large", 21, 0, 60)[0]
            return current.budget.remaining
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(owner, range(4)))
    assert len(set(results)) == 1  # no second narrowing on repeated setup
    store = SQLiteStore(path)
    try:
        store.release(grant.id, "held-old-charge", 30)
        assert Decimal("49.99999999") <= store.get_grant(grant.id).budget.remaining <= Decimal("50")
        with pytest.raises(StateError, match="reservation not found"):
            store.release(grant.id, "held-old-charge", 30)
    finally:
        store.close()


def test_failed_precision_migration_restores_columns_and_body(tmp_path, monkeypatch):
    path = str(tmp_path / "rollback.db")
    _, before = legacy(path)
    connect = sqlite3.connect
    connections = []

    class FailureCursor(sqlite3.Cursor):
        def execute(self, sql, *args):
            if sql == "ALTER TABLE rate_events ADD COLUMN reserved_units TEXT":
                raise sqlite3.OperationalError("injected precision migration failure")
            return super().execute(sql, *args)

    class FailureConnection(sqlite3.Connection):
        def cursor(self, *args, **kwargs):
            return super().cursor(*args, **dict(kwargs, factory=FailureCursor))

    def connect_failure(*args, **kwargs):
        connection = connect(*args, **dict(kwargs, factory=FailureConnection))
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect_failure)
    with pytest.raises(sqlite3.OperationalError, match="injected precision migration failure"):
        SQLiteStore(path)
    with connect(path) as connection:
        for table, column in COLUMNS:
            assert column not in {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            }
        assert connection.execute("SELECT body FROM grants").fetchone()[0] == before
        assert connection.execute("SELECT COUNT(*) FROM rate_events").fetchone()[0] == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")
