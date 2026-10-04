"""Real independent SQLite clients must serialize schema inspection and migration."""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from actenon_permit.ledger import Ledger


class DelayedColumns(sqlite3.Cursor):
    def execute(self, sql, *args):
        self.inspect_columns = sql == "PRAGMA table_info(ledger)"
        return super().execute(sql, *args)

    def fetchall(self):
        result = super().fetchall()
        if self.inspect_columns:
            time.sleep(0.1)  # widen the real inspection/ALTER race, never fake its result
        return result


class DelayedConnection(sqlite3.Connection):
    def cursor(self, *args, **kwargs):
        return super().cursor(*args, **dict(kwargs, factory=DelayedColumns))


@pytest.mark.parametrize("legacy", [False, True])
def test_independent_ledger_clients_migrate_without_duplicate_columns(
    tmp_path, monkeypatch, legacy
):
    path = str(tmp_path / "shared.db")
    ledger = Ledger(path)
    ledger.close()
    connect = sqlite3.connect
    if legacy:
        with connect(path) as conn:
            for column in ("failure_code", "authority_boundary", "chain_version"):
                conn.execute(f"ALTER TABLE ledger DROP COLUMN {column}")
    monkeypatch.setattr(
        sqlite3, "connect", lambda *a, **kw: connect(*a, **dict(kw, factory=DelayedConnection))
    )
    barrier = threading.Barrier(4)

    def initialize():
        barrier.wait(timeout=10)
        ledger = Ledger(path)
        try:
            columns = {row[1] for row in ledger._conn.execute("PRAGMA table_info(ledger)")}
            assert {"failure_code", "authority_boundary", "chain_version"} <= columns
            assert ledger.verify()
            return ledger._conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            ledger.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: initialize(), range(4))) == ["wal"] * 4


def test_failed_migration_rolls_back_prior_columns_and_closes_connection(tmp_path, monkeypatch):
    path = str(tmp_path / "legacy.db")
    # Freeze a genuine pre-migration schema by creating it once, then removing
    # only its v2 columns. The existing ledger regression suite checks old rows.
    ledger = Ledger(path)
    ledger.close()
    connect = sqlite3.connect
    with connect(path) as conn:
        for column in ("failure_code", "authority_boundary", "chain_version"):
            conn.execute(f"ALTER TABLE ledger DROP COLUMN {column}")

    connections = []

    class FailingCursor(sqlite3.Cursor):
        def execute(self, sql, *args):
            if sql == "ALTER TABLE ledger ADD COLUMN authority_boundary TEXT":
                raise sqlite3.OperationalError("injected migration failure")
            return super().execute(sql, *args)

    class FailingConnection(sqlite3.Connection):
        def cursor(self, *args, **kwargs):
            return super().cursor(*args, **dict(kwargs, factory=FailingCursor))

    def broken_connect(*args, **kwargs):
        conn = connect(*args, **dict(kwargs, factory=FailingConnection))
        connections.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", broken_connect)
    with pytest.raises(sqlite3.OperationalError, match="injected migration failure"):
        Ledger(path)
    with connect(path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(ledger)")}
        assert "failure_code" not in columns
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")
