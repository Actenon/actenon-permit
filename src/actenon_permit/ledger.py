"""Actenon-Permit ledger: append-only, hash-chained audit log.

Every decision the PDP makes is appended here as a ledger entry. Entries are
hash-chained: ``hash = sha256(prev_hash + canonical_json(entry_without_hash))``.
The genesis entry uses ``prev_hash = "0" * 64``.

Tampering with any row — its decision, its params, or its hash — breaks the
chain. ``verify()`` recomputes the chain from row 0 and returns False on any
mismatch. The contract test in ``tests/test_ledger.py`` mutates a row in-place
and asserts that ``verify()`` fails.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import threading
from datetime import UTC, datetime
from typing import Any

from .model import canonical_json

GENESIS_PREV_HASH = "0" * 64


def _hash_entry(prev_hash: str, entry_body: dict[str, Any]) -> str:
    """``sha256(prev_hash + canonical_json(entry_without_hash))``."""
    payload = (prev_hash + canonical_json(entry_body)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class Ledger:
    """Append-only, hash-chained ledger backed by SQLite.

    The ledger is deliberately minimal: each row records the action, the
    decision, the rule matched, and a state delta. It is a feature, not the
    centrepiece — Actenon-Permit is an authorization product, not a receipts
    product.
    """

    def __init__(self, conn_or_store: Any = None):
        # The Ledger ALWAYS opens its own SQLite connection. Sharing a
        # connection with the StateStore would mean two different locks
        # (StateStore._lock and Ledger._lock) covering the same connection,
        # which lets two threads issue BEGIN IMMEDIATE simultaneously on
        # one connection — undefined behavior in sqlite3 and the root cause
        # of intermittent "cannot start a transaction within a transaction"
        # errors under concurrent load.
        #
        # We accept a StateStore or connection argument only to discover the
        # database path; we never reuse the connection itself.
        import sqlite3

        from .state import _default_db_path

        if conn_or_store is None:
            db_path = _default_db_path()
        elif hasattr(conn_or_store, "db_path"):
            db_path = conn_or_store.db_path  # type: ignore[attr-defined]
        elif hasattr(conn_or_store, "execute"):
            # It's a connection — we can't easily extract the path, so fall
            # back to the default. (This branch only fires if someone passes
            # a raw connection, which is not the documented usage.)
            db_path = _default_db_path()
        else:
            db_path = str(conn_or_store)

        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None
        )
        self._owns_conn = True
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

                CREATE TABLE IF NOT EXISTS ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT,
                    params TEXT NOT NULL,
                    est_cost REAL,
                    outcome TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    rule_matched TEXT,
                    state_delta TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_ledger_grant ON ledger(grant_id);
                CREATE INDEX IF NOT EXISTS idx_ledger_action ON ledger(action_id);
                """
            )

            # Migration: add v2 columns if they don't exist
            columns = {row[1] for row in cur.execute("PRAGMA table_info(ledger)").fetchall()}
            if "failure_code" not in columns:
                cur.execute("ALTER TABLE ledger ADD COLUMN failure_code TEXT")
            if "authority_boundary" not in columns:
                cur.execute("ALTER TABLE ledger ADD COLUMN authority_boundary TEXT")

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------

    def append(
        self,
        *,
        action_id: str,
        grant_id: str,
        ts: datetime | str,
        action_type: str,
        target: str,
        params: dict[str, Any],
        est_cost: float | None,
        outcome: str,
        reason: str,
        rule_matched: str | None,
        state_delta: dict[str, Any],
        failure_code: str | None = None,
        authority_boundary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append a single entry. Computes and stores the hash. Returns the entry."""
        ts_str = ts.astimezone(UTC).isoformat() if isinstance(ts, datetime) else ts

        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1")
                row = cur.fetchone()
                prev_hash = row[0] if row else GENESIS_PREV_HASH

                entry_body: dict[str, Any] = {
                    "entry_format": "v2",
                    "action_id": action_id,
                    "grant_id": grant_id,
                    "ts": ts_str,
                    "action_type": action_type,
                    "target": target,
                    "params": params,
                    "est_cost": est_cost,
                    "outcome": outcome,
                    "reason": reason,
                    "rule_matched": rule_matched,
                    "state_delta": state_delta,
                    "failure_code": failure_code,
                    "authority_boundary": authority_boundary,
                    "prev_hash": prev_hash,
                }
                h = _hash_entry(prev_hash, entry_body)

                cur.execute(
                    """
                    INSERT INTO ledger (
                        action_id, grant_id, ts, action_type, target, params,
                        est_cost, outcome, reason, rule_matched, state_delta,
                        failure_code, authority_boundary, prev_hash, hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        grant_id,
                        ts_str,
                        action_type,
                        target,
                        json.dumps(params, sort_keys=True, default=str),
                        est_cost,
                        outcome,
                        reason,
                        rule_matched,
                        json.dumps(state_delta, sort_keys=True, default=str),
                        failure_code,
                        json.dumps(authority_boundary, sort_keys=True, default=str)
                        if authority_boundary is not None
                        else None,
                        prev_hash,
                        h,
                    ),
                )
                cur.execute("COMMIT")
                return {**entry_body, "hash": h, "seq": cur.lastrowid}
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_entries(
        self, grant_id: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            if grant_id:
                cur.execute(
                    "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
                    "est_cost, outcome, reason, rule_matched, state_delta, "
                    "failure_code, authority_boundary, prev_hash, hash "
                    "FROM ledger WHERE grant_id = ? ORDER BY seq ASC LIMIT ?",
                    (grant_id, limit),
                )
            else:
                cur.execute(
                    "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
                    "est_cost, outcome, reason, rule_matched, state_delta, "
                    "failure_code, authority_boundary, prev_hash, hash "
                    "FROM ledger ORDER BY seq ASC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()

        entries = []
        for r in rows:
            entries.append(
                {
                    "seq": r[0],
                    "action_id": r[1],
                    "grant_id": r[2],
                    "ts": r[3],
                    "action_type": r[4],
                    "target": r[5],
                    "params": json.loads(r[6]) if r[6] else {},
                    "est_cost": r[7],
                    "outcome": r[8],
                    "reason": r[9],
                    "rule_matched": r[10],
                    "state_delta": json.loads(r[11]) if r[11] else {},
                    "failure_code": r[12],
                    "authority_boundary": json.loads(r[13]) if r[13] else None,
                    "prev_hash": r[14],
                    "hash": r[15],
                }
            )
        return entries

    def last_hash(self) -> str:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
        return row[0] if row else GENESIS_PREV_HASH

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(self) -> bool:
        """Recompute the chain from row 0 and return True iff it is intact."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
                "est_cost, outcome, reason, rule_matched, state_delta, "
                "failure_code, authority_boundary, prev_hash, hash "
                "FROM ledger ORDER BY seq ASC"
            )
            rows = cur.fetchall()

        prev_hash = GENESIS_PREV_HASH
        for r in rows:
            (seq, action_id, grant_id, ts, action_type, target, params_json,
             est_cost, outcome, reason, rule_matched, state_delta_json,
             failure_code, authority_boundary_json, stored_prev_hash,
             stored_hash) = r

            # Check the prev_hash field matches what we expect.
            if stored_prev_hash != prev_hash:
                return False

            authority_boundary = (
                json.loads(authority_boundary_json) if authority_boundary_json else None
            )

            entry_body = {
                "entry_format": "v2",
                "action_id": action_id,
                "grant_id": grant_id,
                "ts": ts,
                "action_type": action_type,
                "target": target,
                "params": json.loads(params_json) if params_json else {},
                "est_cost": est_cost,
                "outcome": outcome,
                "reason": reason,
                "rule_matched": rule_matched,
                "state_delta": json.loads(state_delta_json) if state_delta_json else {},
                "failure_code": failure_code,
                "authority_boundary": authority_boundary,
                "prev_hash": prev_hash,
            }
            expected_hash = _hash_entry(prev_hash, entry_body)
            if expected_hash != stored_hash:
                return False

            prev_hash = stored_hash
        return True

    def close(self) -> None:
        if self._owns_conn:
            with self._lock:
                self._conn.close()
