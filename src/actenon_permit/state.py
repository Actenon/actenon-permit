"""Actenon-Permit state store.

The state store holds the mutable, authoritative view of every grant's live
state: budget remaining, rate counters, status. This is the only place where
budget reservation and rate counting happen, and they MUST be atomic.

Concurrency model
-----------------
SQLite is configured for WAL mode with ``BEGIN IMMEDIATE`` transactions for
writes. A write transaction acquires the database write lock immediately,
which means two parallel reserve() calls serialize at the SQLite layer: the
second one blocks until the first commits, then sees the updated ``remaining``
and correctly fails. A threading.Lock around the connection is also held
during critical sections as belt-and-braces, so even a SQLite build without
WAL behaves correctly.

The contract test in ``tests/test_state.py`` fires two parallel $30 refunds
against a $50 budget and asserts exactly one is ALLOWED.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from .model import Grant, GrantStatus


class StateError(RuntimeError):
    """Raised on state-store level failures (e.g. unknown grant)."""


class StateStore(ABC):
    """Abstract interface for grant-state storage."""

    @abstractmethod
    def put_grant(self, grant: Grant) -> None:
        """Persist a new grant. Idempotent on grant.id."""

    @abstractmethod
    def get_grant(self, grant_id: str) -> Grant | None:
        """Return the grant, or None if unknown."""

    @abstractmethod
    def list_grants(self, agent_id: str | None = None) -> list[Grant]:
        """List grants, optionally filtered by agent_id."""

    @abstractmethod
    def set_status(self, grant_id: str, status: GrantStatus) -> None:
        """Transition a grant to a new status."""

    @abstractmethod
    def reserve(
        self,
        grant_id: str,
        action_id: str,
        amount: float,
        rate_max: int,
        rate_per_seconds: int,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Atomically reserve ``amount`` against the grant's budget and bump
        the rate counter. Returns ``(ok, reason, state_snapshot)``.

        On success: ``remaining`` is decremented by ``amount`` and a rate
        hit is recorded. On failure: nothing is mutated. Either way, the
        call holds a single write transaction for the entire operation.
        """

    @abstractmethod
    def commit(
        self,
        grant_id: str,
        action_id: str,
        actual_cost: float,
        reserved_amount: float,
    ) -> float:
        """Commit the actual cost of an action, releasing the difference
        between reservation and actual. Returns the new ``remaining``.
        """

    @abstractmethod
    def release(self, grant_id: str, action_id: str, reserved_amount: float) -> float:
        """Release a reservation without recording an actual cost (e.g. on
        DENY-after-reserve failure paths). Returns the new ``remaining``.
        """

    @abstractmethod
    def rate_count(self, grant_id: str, per_seconds: int) -> int:
        """Number of actions recorded for this grant in the last ``per_seconds``."""


def _default_db_path() -> str:
    return os.environ.get("ACTENON_DB_PATH", "actenon.db")


class SQLiteStore(StateStore):
    """SQLite-backed state store. Single-file, local, durable."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or _default_db_path()
        # check_same_thread=False because we use our own lock; isolation_level
        # None puts the connection in autocommit mode so we control txns
        # explicitly with BEGIN IMMEDIATE.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                PRAGMA busy_timeout=10000;

                CREATE TABLE IF NOT EXISTS grants (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    status TEXT NOT NULL,
                    remaining REAL NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rate_events (
                    action_id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL,
                    ts REAL NOT NULL,
                    reserved_amount REAL NOT NULL,
                    committed INTEGER NOT NULL DEFAULT 0,
                    actual_cost REAL
                );

                CREATE INDEX IF NOT EXISTS idx_rate_events_grant_ts
                    ON rate_events(grant_id, ts);
                """
            )

    # ------------------------------------------------------------------
    # Grant CRUD
    # ------------------------------------------------------------------

    def put_grant(self, grant: Grant) -> None:
        body = grant.model_dump_json()
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO grants (id, agent_id, body, status, remaining, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    grant.id,
                    grant.agent_id,
                    body,
                    grant.status.value,
                    grant.budget.remaining,
                    now,
                ),
            )

    def get_grant(self, grant_id: str) -> Grant | None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT body FROM grants WHERE id = ?", (grant_id,))
            row = cur.fetchone()
        if not row:
            return None
        return Grant.model_validate_json(row[0])

    def list_grants(self, agent_id: str | None = None) -> list[Grant]:
        with self._lock:
            cur = self._conn.cursor()
            if agent_id:
                cur.execute("SELECT body FROM grants WHERE agent_id = ? ORDER BY updated_at DESC", (agent_id,))
            else:
                cur.execute("SELECT body FROM grants ORDER BY updated_at DESC")
            rows = cur.fetchall()
        return [Grant.model_validate_json(r[0]) for r in rows]

    def set_status(self, grant_id: str, status: GrantStatus) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    "UPDATE grants SET status = ?, updated_at = ? WHERE id = ?",
                    (status.value, now, grant_id),
                )
                # Reflect status change in the stored body too, so get_grant
                # returns the new status without a separate reload.
                cur.execute("SELECT body FROM grants WHERE id = ?", (grant_id,))
                row = cur.fetchone()
                if row:
                    g = Grant.model_validate_json(row[0])
                    g.status = status
                    cur.execute(
                        "UPDATE grants SET body = ? WHERE id = ?",
                        (g.model_dump_json(), grant_id),
                    )
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------
    # Atomic reserve / commit / release
    # ------------------------------------------------------------------

    def reserve(
        self,
        grant_id: str,
        action_id: str,
        amount: float,
        rate_max: int,
        rate_per_seconds: int,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Atomic reserve-then-record. Single write transaction.

        Returns ``(ok, reason, snapshot)`` where snapshot is the post-reserve
        grant state (status, remaining) for the PDP to log.
        """
        now_ts = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute("SELECT body, status, remaining FROM grants WHERE id = ?", (grant_id,))
                row = cur.fetchone()
                if not row:
                    cur.execute("ROLLBACK")
                    return False, "grant not found", {}
                body, status_str, remaining = row
                grant = Grant.model_validate_json(body)

                if grant.status != GrantStatus.ACTIVE:
                    cur.execute("ROLLBACK")
                    return False, f"grant status is {grant.status.value}", {}

                # Rate check (within this same transaction so it's atomic).
                if rate_max > 0:
                    window_start = now_ts - rate_per_seconds
                    cur.execute(
                        "SELECT COUNT(*) FROM rate_events WHERE grant_id = ? AND ts >= ?",
                        (grant_id, window_start),
                    )
                    n = cur.fetchone()[0]
                    if n >= rate_max:
                        cur.execute("ROLLBACK")
                        return False, "rate limit", {}

                # Budget check.
                # SECURITY: reject negative amounts — a negative est_cost would
                # inflate the budget (remaining - (-50) = remaining + 50),
                # which is a budget bypass. Found by adversarial testing.
                if amount < 0:
                    cur.execute("ROLLBACK")
                    return (
                        False,
                        "negative amounts are not allowed — this is a budget bypass attempt",
                        {},
                    )
                if remaining - amount < 0:
                    cur.execute("ROLLBACK")
                    return (
                        False,
                        f"would exceed {grant.budget.currency} {grant.budget.limit} budget",
                        {},
                    )

                # Reserve.
                new_remaining = remaining - amount
                now_iso = datetime.now(UTC).isoformat()
                cur.execute(
                    "UPDATE grants SET remaining = ?, updated_at = ? WHERE id = ?",
                    (new_remaining, now_iso, grant_id),
                )
                cur.execute(
                    "INSERT INTO rate_events (action_id, grant_id, ts, reserved_amount, committed) "
                    "VALUES (?, ?, ?, ?, 0)",
                    (action_id, grant_id, now_ts, amount),
                )

                # Always reflect the new remaining in the body JSON so that
                # get_grant() (which reads body, not the column) returns the
                # live value. Without this, concurrent reserves see stale
                # remaining from body and over-spend.
                grant.budget.remaining = new_remaining
                new_status = grant.status
                if new_remaining <= 0 and amount > 0:
                    new_status = GrantStatus.EXHAUSTED
                    grant.status = new_status
                    cur.execute(
                        "UPDATE grants SET status = ?, updated_at = ? WHERE id = ?",
                        (new_status.value, now_iso, grant_id),
                    )
                cur.execute(
                    "UPDATE grants SET body = ? WHERE id = ?",
                    (grant.model_dump_json(), grant_id),
                )

                cur.execute("COMMIT")
                return True, "reserved", {
                    "remaining": new_remaining,
                    "status": new_status.value,
                }
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def commit(
        self,
        grant_id: str,
        action_id: str,
        actual_cost: float,
        reserved_amount: float,
    ) -> float:
        """Commit actual cost and release the over-reservation."""
        now_iso = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute("SELECT body, remaining FROM grants WHERE id = ?", (grant_id,))
                row = cur.fetchone()
                if not row:
                    cur.execute("ROLLBACK")
                    raise StateError(f"grant not found: {grant_id}")
                body, remaining = row
                grant = Grant.model_validate_json(body)

                # Release the difference back.
                release_amount = max(0.0, reserved_amount - actual_cost)
                new_remaining = remaining + release_amount

                cur.execute(
                    "UPDATE grants SET remaining = ?, updated_at = ? WHERE id = ?",
                    (new_remaining, now_iso, grant_id),
                )
                cur.execute(
                    "UPDATE rate_events SET committed = 1, actual_cost = ? WHERE action_id = ?",
                    (actual_cost, action_id),
                )
                # Reflect in body
                grant.budget.remaining = new_remaining
                cur.execute(
                    "UPDATE grants SET body = ? WHERE id = ?",
                    (grant.model_dump_json(), grant_id),
                )
                cur.execute("COMMIT")
                return new_remaining
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def release(self, grant_id: str, action_id: str, reserved_amount: float) -> float:
        """Release a reservation without an actual cost (failure path)."""
        now_iso = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute("SELECT body, remaining FROM grants WHERE id = ?", (grant_id,))
                row = cur.fetchone()
                if not row:
                    cur.execute("ROLLBACK")
                    raise StateError(f"grant not found: {grant_id}")
                body, remaining = row
                grant = Grant.model_validate_json(body)

                new_remaining = remaining + reserved_amount
                cur.execute(
                    "UPDATE grants SET remaining = ?, updated_at = ? WHERE id = ?",
                    (new_remaining, now_iso, grant_id),
                )
                # Remove the rate_events row entirely — a released action
                # should not count toward rate limit (the action didn't fire).
                cur.execute("DELETE FROM rate_events WHERE action_id = ?", (action_id,))
                grant.budget.remaining = new_remaining
                cur.execute(
                    "UPDATE grants SET body = ? WHERE id = ?",
                    (grant.model_dump_json(), grant_id),
                )
                cur.execute("COMMIT")
                return new_remaining
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def rate_count(self, grant_id: str, per_seconds: int) -> int:
        now_ts = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM rate_events WHERE grant_id = ? AND ts >= ?",
                (grant_id, now_ts - per_seconds),
            )
            return cur.fetchone()[0]

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# Module-level singleton for CLI / demo convenience.
_default_store: SQLiteStore | None = None
_default_store_lock = threading.Lock()


def get_default_store() -> SQLiteStore:
    global _default_store
    with _default_store_lock:
        if _default_store is None:
            _default_store = SQLiteStore()
        return _default_store


def reset_default_store() -> None:
    """Test helper: drop the cached singleton so the next call re-opens."""
    global _default_store
    with _default_store_lock:
        if _default_store is not None:
            _default_store.close()
        _default_store = None
