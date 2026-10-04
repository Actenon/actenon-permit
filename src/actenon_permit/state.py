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
import math
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from .effects import EffectLedgerMixin
from .model import Grant, GrantStatus


class StateError(RuntimeError):
    """Raised on state-store level failures (e.g. unknown grant)."""


def _budget_amount(value: float | Decimal | int) -> Decimal:
    """Validate and normalize a value to the store's SQLite REAL precision."""
    if isinstance(value, bool) or not isinstance(value, (float, Decimal, int)):
        raise StateError("budget amount must be a finite number")
    try:
        decimal_value = Decimal(str(value))
        stored_value = float(decimal_value)
    except (ValueError, OverflowError) as exc:
        raise StateError("budget amount must be a finite number") from exc
    if not decimal_value.is_finite() or not math.isfinite(stored_value):
        raise StateError("budget amount must be a finite number")
    if decimal_value != 0 and stored_value == 0:
        raise StateError("budget amount is below the store's numeric precision")
    return Decimal(str(stored_value))


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
        amount: float | Decimal | int,
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
        actual_cost: float | Decimal | int,
        reserved_amount: float | Decimal | int,
    ) -> float:
        """Settle a matching durable reservation once. An identical commit
        replay returns the current remaining budget without changing it.
        Missing, mismatched or conflicting settlements raise StateError.
        """

    @abstractmethod
    def release(
        self, grant_id: str, action_id: str, reserved_amount: float | Decimal | int
    ) -> float:
        """Release a matching, uncommitted reservation when non-execution is
        established. Missing, mismatched or committed reservations raise
        StateError. An uncertain dispatch must keep its reservation.
        """

    @abstractmethod
    def rate_count(self, grant_id: str, per_seconds: int) -> int:
        """Number of actions recorded for this grant in the last ``per_seconds``."""


def _default_db_path() -> str:
    return os.environ.get("ACTENON_DB_PATH", "actenon.db")


def _retry_sqlite_initialization(attempt) -> None:
    """Bounded idempotent setup retry, only for actual SQLite contention."""
    deadline = time.monotonic() + 10
    while True:
        try:
            attempt()
            return
        except sqlite3.OperationalError as exc:
            code = getattr(exc, "sqlite_errorcode", None)
            busy = (code is not None and code & 255 in {5, 6}) or (
                code is None and str(exc) in {"database is locked", "database table is locked"}
            )
            remaining = deadline - time.monotonic()
            if not busy or remaining <= 0:
                raise
            time.sleep(min(0.02, remaining))


class SQLiteStore(EffectLedgerMixin, StateStore):
    """SQLite-backed state store. Single-file, local, durable."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or _default_db_path()
        # check_same_thread=False because we use our own lock; isolation_level
        # None puts the connection in autocommit mode so we control txns
        # explicitly with BEGIN IMMEDIATE.
        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False, isolation_level=None, timeout=10
        )
        self._lock = threading.RLock()
        try:
            self._init_schema()
        except Exception:
            self._conn.close()
            raise

    def _init_schema(self) -> None:
        # journal_mode's lock upgrade can return SQLITE_BUSY immediately even
        # with a busy timeout. Retry idempotent schema setup on contention only;
        # never downgrade durability, ignore other errors, or open without it.
        self._conn.execute("PRAGMA busy_timeout=10000")
        _retry_sqlite_initialization(self._init_schema_attempt)

    def _init_schema_attempt(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
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
                CREATE TABLE IF NOT EXISTS budget_overruns (
                    grant_id TEXT PRIMARY KEY,
                    amount REAL NOT NULL CHECK (amount >= 0)
                );
                """
            )

            self._init_effect_schema(cur)

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
                    float(grant.budget.remaining),
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
                cur.execute(
                    "SELECT body FROM grants WHERE agent_id = ? ORDER BY updated_at DESC",
                    (agent_id,),
                )
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

    @staticmethod
    def _revoked_ancestor(cur: sqlite3.Cursor, parent_id: str | None, grant_id: str) -> str | None:
        """Return the id of the nearest revoked ancestor, else None.

        Walks ``parent_grant_id`` links with the caller's cursor (inside its
        transaction). An ancestor that is not in this store cannot be
        checked here and ends the walk.
        """
        seen = {grant_id}
        while parent_id and parent_id not in seen:
            seen.add(parent_id)
            cur.execute("SELECT status, body FROM grants WHERE id = ?", (parent_id,))
            row = cur.fetchone()
            if row is None:
                return None
            if row[0] == GrantStatus.REVOKED.value:
                return parent_id
            parent_id = Grant.model_validate_json(row[1]).parent_grant_id
        return None

    # ------------------------------------------------------------------
    # Atomic reserve / commit / release
    # ------------------------------------------------------------------

    def reserve(
        self,
        grant_id: str,
        action_id: str,
        amount: float | Decimal | int,
        rate_max: int,
        rate_per_seconds: int,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Atomic reserve-then-record. Single write transaction.

        Returns ``(ok, reason, snapshot)`` where snapshot is the post-reserve
        grant state (status, remaining) for the PDP to log.
        """
        dec_amount = _budget_amount(amount)
        now_ts = time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                ok, reason, snapshot = self._reserve_in_transaction(
                    cur, grant_id, action_id, dec_amount, rate_max, rate_per_seconds, now_ts
                )
                cur.execute("COMMIT" if ok else "ROLLBACK")
                return ok, reason, snapshot
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def _reserve_in_transaction(
        self, cur, grant_id, action_id, dec_amount, rate_max, rate_per_seconds, now_ts
    ):
        cur.execute("SELECT body, status, remaining FROM grants WHERE id = ?", (grant_id,))
        row = cur.fetchone()
        if not row:
            return False, "grant not found", {}
        body, status_str, remaining = row
        grant = Grant.model_validate_json(body)

        if grant.status != GrantStatus.ACTIVE:
            return False, f"grant status is {grant.status.value}", {}

        overrun = cur.execute(
            "SELECT amount FROM budget_overruns WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if overrun is not None and _budget_amount(overrun[0]) > 0:
            return False, "budget overrun remains unsettled", {}

        # Revocation cascades to every attenuated descendant. Checked
        # here, in the reserve transaction every ALLOW passes through,
        # so it holds however the ancestor was revoked (HTTP, CLI
        # kill switch by agent id, direct set_status).
        revoked_ancestor = self._revoked_ancestor(cur, grant.parent_grant_id, grant.id)
        if revoked_ancestor is not None:
            return False, f"ancestor grant {revoked_ancestor} is revoked", {}

        # Rate check (within this same transaction so it's atomic).
        if rate_max > 0:
            window_start = now_ts - rate_per_seconds
            cur.execute(
                "SELECT COUNT(*) FROM rate_events WHERE grant_id = ? AND ts >= ?",
                (grant_id, window_start),
            )
            n = cur.fetchone()[0]
            if n >= rate_max:
                return False, "rate limit", {}

        dec_remaining = _budget_amount(remaining)

        # SECURITY: reject negative amounts
        if dec_amount < 0:
            return (
                False,
                "negative amounts are not allowed — this is a budget bypass attempt",
                {},
            )
        if dec_remaining - dec_amount < 0:
            return (
                False,
                f"would exceed {grant.budget.currency} {grant.budget.limit} budget",
                {},
            )

        # Reserve.
        new_remaining = float(dec_remaining - dec_amount)
        now_iso = datetime.now(UTC).isoformat()
        cur.execute(
            "UPDATE grants SET remaining = ?, updated_at = ? WHERE id = ?",
            (new_remaining, now_iso, grant_id),
        )
        cur.execute(
            "INSERT INTO rate_events (action_id, grant_id, ts, reserved_amount, committed) "
            "VALUES (?, ?, ?, ?, 0)",
            (action_id, grant_id, now_ts, float(dec_amount)),
        )

        # Always reflect the new remaining in the body JSON so that
        # get_grant() (which reads body, not the column) returns the
        # live value. Without this, concurrent reserves see stale
        # remaining from body and over-spend.
        grant.budget.remaining = (
            Decimal(str(new_remaining)) if isinstance(new_remaining, float) else new_remaining
        )
        new_status = grant.status
        if new_remaining <= 0 and dec_amount > 0:
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

        return (
            True,
            "reserved",
            {
                "remaining": new_remaining,
                "status": new_status.value,
            },
        )

    def commit(
        self,
        grant_id: str,
        action_id: str,
        actual_cost: float | Decimal | int,
        reserved_amount: float | Decimal | int,
    ) -> float:
        """Commit actual cost and release the over-reservation exactly once."""
        # SECURITY: reject negative actual costs — a negative actual_cost would
        # inflate the budget via the reconciliation step (release = reserved -
        # actual = 20 - (-10) = 30, adding 30 to remaining). Found by
        # adversarial testing (round 2, test_negative_actual_cost_rejected).
        dec_actual = max(Decimal("0"), _budget_amount(actual_cost))
        claimed_reserved = _budget_amount(reserved_amount)

        now_iso = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                self._require_legacy_reservation(cur, action_id)
                result = self._commit_in_transaction(
                    cur, grant_id, action_id, dec_actual, claimed_reserved, now_iso
                )
                cur.execute("COMMIT")
                return result
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def _commit_in_transaction(
        self, cur, grant_id, action_id, dec_actual, claimed_reserved, now_iso
    ):
        cur.execute("SELECT body, remaining FROM grants WHERE id = ?", (grant_id,))
        row = cur.fetchone()
        if not row:
            raise StateError(f"grant not found: {grant_id}")
        body, remaining = row
        grant = Grant.model_validate_json(body)

        dec_reserved, committed, settled_cost = self._reservation(
            cur, grant_id, action_id, claimed_reserved
        )
        if committed:
            if settled_cost is None or _budget_amount(settled_cost) != dec_actual:
                raise StateError("reservation was already committed with a different cost")
            return float(_budget_amount(remaining))
        release_amount = dec_reserved - dec_actual
        new_remaining = self._settled_balance(cur, grant_id, remaining, release_amount)

        cur.execute(
            "UPDATE grants SET remaining = ?, updated_at = ? WHERE id = ?",
            (new_remaining, now_iso, grant_id),
        )
        cur.execute(
            "UPDATE rate_events SET committed = 1, actual_cost = ? WHERE action_id = ? AND grant_id = ?",
            (float(dec_actual), action_id, grant_id),
        )
        self._settled_status(cur, grant, new_remaining, now_iso)
        # Reflect in body
        grant.budget.remaining = (
            Decimal(str(new_remaining)) if isinstance(new_remaining, float) else new_remaining
        )
        cur.execute(
            "UPDATE grants SET body = ? WHERE id = ?",
            (grant.model_dump_json(), grant_id),
        )
        return new_remaining

    def release(
        self, grant_id: str, action_id: str, reserved_amount: float | Decimal | int
    ) -> float:
        """Release a matching reservation only after establishing no execution."""
        claimed_reserved = _budget_amount(reserved_amount)
        now_iso = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                self._require_legacy_reservation(cur, action_id)
                result = self._release_in_transaction(
                    cur, grant_id, action_id, claimed_reserved, now_iso
                )
                cur.execute("COMMIT")
                return result
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def _release_in_transaction(self, cur, grant_id, action_id, claimed_reserved, now_iso):
        cur.execute("SELECT body, remaining FROM grants WHERE id = ?", (grant_id,))
        row = cur.fetchone()
        if not row:
            raise StateError(f"grant not found: {grant_id}")
        body, remaining = row
        grant = Grant.model_validate_json(body)

        dec_reserved, committed, _ = self._reservation(cur, grant_id, action_id, claimed_reserved)
        if committed:
            raise StateError("committed reservation cannot be released")
        new_remaining = self._settled_balance(cur, grant_id, remaining, dec_reserved)
        cur.execute(
            "UPDATE grants SET remaining = ?, updated_at = ? WHERE id = ?",
            (new_remaining, now_iso, grant_id),
        )
        # Remove the rate_events row entirely — a released action
        # should not count toward rate limit (the action didn't fire).
        cur.execute(
            "DELETE FROM rate_events WHERE action_id = ? AND grant_id = ?", (action_id, grant_id)
        )
        self._settled_status(cur, grant, new_remaining, now_iso)
        grant.budget.remaining = (
            Decimal(str(new_remaining)) if isinstance(new_remaining, float) else new_remaining
        )
        cur.execute(
            "UPDATE grants SET body = ? WHERE id = ?",
            (grant.model_dump_json(), grant_id),
        )
        return new_remaining

    @staticmethod
    def _settled_balance(cur, grant_id, remaining, adjustment):
        # A provider overrun is real consumption, even beyond remaining
        # authority. Preserve the debt durably; subsequent non-execution
        # refunds pay it before restoring available authority. Budget's
        # public non-negative shape stays stable, and exhausted debt cannot
        # be erased by replaying a settlement.
        row = cur.execute(
            "SELECT amount FROM budget_overruns WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        debt = _budget_amount(row[0]) if row else Decimal("0")
        balance = _budget_amount(remaining) - debt + adjustment
        new_remaining = float(max(Decimal("0"), balance))
        new_debt = float(max(Decimal("0"), -balance))
        cur.execute(
            "INSERT INTO budget_overruns(grant_id,amount) VALUES (?,?) "
            "ON CONFLICT(grant_id) DO UPDATE SET amount = excluded.amount",
            (grant_id, new_debt),
        )
        return new_remaining

    @staticmethod
    def _settled_status(cur, grant, remaining, now_iso):
        if grant.status == GrantStatus.EXHAUSTED and remaining > 0:
            grant.status = GrantStatus.ACTIVE
        elif grant.status == GrantStatus.ACTIVE and remaining <= 0:
            grant.status = GrantStatus.EXHAUSTED
        cur.execute(
            "UPDATE grants SET status = ?, updated_at = ? WHERE id = ?",
            (grant.status.value, now_iso, grant.id),
        )

    @staticmethod
    def _reservation(
        cur: sqlite3.Cursor,
        grant_id: str,
        action_id: str,
        claimed_amount: Decimal,
    ) -> tuple[Decimal, bool, float | None]:
        """Read and validate a reservation inside the settlement transaction."""
        cur.execute(
            "SELECT grant_id, reserved_amount, committed, actual_cost FROM rate_events WHERE action_id = ?",
            (action_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise StateError("reservation not found")
        if row[0] != grant_id:
            raise StateError("reservation belongs to another grant")
        amount = _budget_amount(row[1])
        if amount < 0 or amount != claimed_amount:
            raise StateError("reserved amount does not match the stored reservation")
        return amount, bool(row[2]), row[3]

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
