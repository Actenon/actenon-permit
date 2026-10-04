"""Independent owners can start one durable effect ledger concurrently."""

import multiprocessing
import sqlite3

import pytest

from actenon_permit.state import SQLiteStore


def _cold_start(path, barrier, queue):
    barrier.wait(timeout=20)
    store = SQLiteStore(path)
    try:
        queue.put(
            (
                store._conn.execute("PRAGMA journal_mode").fetchone()[0],
                store._conn.execute("SELECT COUNT(*) FROM effect_reservations").fetchone()[0],
            )
        )
    finally:
        store.close()


@pytest.mark.parametrize("round", range(3))
def test_independent_processes_share_cold_start_schema(tmp_path, round):
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(4), context.Queue()
    processes = [
        context.Process(
            target=_cold_start, args=(str(tmp_path / f"cold-{round}.db"), barrier, queue)
        )
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    try:
        assert [queue.get(timeout=20) for _ in processes] == [("wal", 0)] * 4
        for process in processes:
            process.join(timeout=20)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)
        queue.close()


def test_schema_errors_are_not_silenced(tmp_path):
    # A directory is not a SQLite database. Contention retry cannot convert
    # an unusable authoritative store into an unprotected execution path.
    with pytest.raises(sqlite3.OperationalError):
        SQLiteStore(str(tmp_path))
