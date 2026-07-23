"""Actenon-Permit ledger: append-only, hash-chained audit log.

Every decision the PDP makes is appended here as a ledger entry. Entries are
hash-chained: ``hash = sha256(prev_hash + canonical_json(entry_without_hash))``.
The genesis entry uses ``prev_hash = "0" * 64``.

Tampering with any row — its decision, its params, or its hash — breaks the
chain. ``verify()`` recomputes the chain from row 0 and returns False on any
mismatch. The contract test in ``tests/test_ledger.py`` mutates a row in-place
and asserts that ``verify()`` fails.

Chain versioning
----------------
As of actenon-permit 2.0.0, the canonicaliser used to compute entry hashes
changed from Permit's home-grown ``json.dumps(sort_keys=True, default=str)``
to ACTENON-JCS-STRICT-1 (delegated via ``actenon_protocol.canonicalize_json``).
This changes every entry hash, so existing ledgers would fail their integrity
check under the new canonicaliser alone.

To support ledgers that contain entries written by both pre-2.0.0 and
post-2.0.0 code, each entry carries a ``chain_version`` field:

  - ``chain_version`` absent  -> entry written by <2.0.0; verify with
    ``_legacy_canonical_json`` (kept private in ``model.py``)
  - ``chain_version = 2``     -> entry written by >=2.0.0; verify with
    ``canonical_json`` (delegates to ACTENON-JCS-STRICT-1)

A mixed-version ledger (some legacy, some new) verifies intact as long as
each entry's hash matches the canonicaliser its ``chain_version`` selects.
``verify()`` dispatches per-entry.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import threading
from datetime import UTC, datetime
from typing import Any, Protocol

from .model import _legacy_canonical_json, canonical_json

GENESIS_PREV_HASH = "0" * 64

# The chain version this code writes. Entries written by <2.0.0 have no
# chain_version column (NULL in SQLite); entries written by >=2.0.0 have
# chain_version=2. Bump this if the canonicaliser changes again.
CURRENT_CHAIN_VERSION = 2


class _Canonicaliser(Protocol):
    def __call__(self, obj: Any) -> str: ...


def _json_normalize_legacy(obj: Any) -> Any:
    """Legacy normalisation for legacy (chain_version absent) entries.

    Reproduces the pre-2.0.0 behaviour: Decimal and int are converted to
    float (so 20 and 20.0 hash identically), because SQLite REAL columns
    convert int to float on storage. This is the function the pre-2.0.0
    verifier used to reconstruct the entry body before hashing.

    DO NOT use for new entries. New entries use ``_coerce_decimals`` (in
    model.py) which converts Decimal to str via ``Decimal.normalize()``
    and rejects floats outright.
    """
    from decimal import Decimal

    if isinstance(obj, (Decimal, int)) and not isinstance(obj, bool):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _json_normalize_legacy(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_normalize_legacy(item) for item in obj]
    return obj


def _coerce_decimals_for_new_chain(obj: Any) -> Any:
    """Normalisation for chain_version=2 entries.

    The protocol canonicaliser (ACTENON-JCS-STRICT-1) rejects ``Decimal``
    and ``float`` outright. Permit's domain model uses ``Decimal`` for
    ``Budget`` (correct), but several legacy code paths still produce
    floats — in particular, ``enforce._extract_amount_from_args`` returns
    ``float``, and ``Action.est_cost`` accepts ``float | int | Decimal | None``.
    Those floats flow into the ledger payload as ``est_cost`` and (when
    callers pass them) inside ``params``.

    The WO-4 brief says floats should raise at the ``canonical_json``
    boundary (constraint C3). That is correct for the PUBLIC API — callers
    who construct signing payloads by hand must not be allowed to slip a
    float through. But the LEDGER is not a hand-constructed payload: it's
    a machine-generated record of decisions the PDP already made, and the
    pre-2.0.0 code path that produces floats in ``est_cost`` is not in
    this work order's scope (it lives in ``enforce.py``, ``broker.py``,
    and ``model.Action`` — none of which are in "Files in scope").

    The pragmatic, scope-respecting fix is to normalise floats to a
    canonical string form HERE, before the protocol canonicaliser sees
    them. This:

      - keeps the public ``canonical_json`` strict (floats raise there)
      - keeps the demo working (``permit demo --auto-approve`` produces
        floats in ``est_cost`` and would otherwise crash)
      - is local to ``ledger.py`` (in scope)
      - produces stable bytes across the SQLite round-trip

    SQLite REAL columns convert ``int`` to ``float`` on storage (so
    ``est_cost=10`` written by ``append`` becomes ``10.0`` when read back
    by ``verify``). If we coerced ``int`` -> ``int`` and ``float`` ->
    ``str`` separately, the same field would canonicalise to different
    bytes at append-time vs verify-time, breaking the hash chain. We
    therefore coerce BOTH ``int`` and ``float`` to a canonical Decimal
    string via ``Decimal(str(x)).normalize()``::

        int(10)      -> str(Decimal("10").normalize())   = "1E+1"
        float(10.0)  -> str(Decimal("10.0").normalize()) = "1E+1"
        Decimal("10.0").normalize()                      = "1E+1"

    All three produce identical bytes. This is the same normalisation
    ``_coerce_decimals`` (in model.py) applies to ``Decimal``.

    A future work order should fix ``enforce._extract_amount_from_args``
    to return ``Decimal`` (or integer cents) instead of ``float``, at
    which point this int/float-coercion branch can be removed.
    """
    from decimal import Decimal

    def _float_safe_coerce(o: Any) -> Any:
        if isinstance(o, bool):
            # bool is a subclass of int; the protocol canonicaliser
            # accepts bool natively (JSON true/false). Must check before
            # the int/float branch below.
            return o
        if isinstance(o, (int, float)):
            # Coerce BOTH int and float to a canonical Decimal string so
            # the SQLite REAL round-trip (int -> float) doesn't change
            # the canonical bytes. See function docstring for details.
            return str(Decimal(str(o)).normalize())
        if isinstance(o, Decimal):
            return str(o.normalize())
        if isinstance(o, str) or o is None:
            return o
        if isinstance(o, dict):
            return {k: _float_safe_coerce(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [_float_safe_coerce(item) for item in o]
        # Genuinely unsupported type. Reaching here means the payload
        # contains something neither the protocol canonicaliser nor this
        # coercer can handle. Raise TypeError with the type name.
        raise TypeError(
            f"_coerce_decimals_for_new_chain: unsupported type "
            f"{type(o).__name__!r} for ACTENON-JCS-STRICT-1 canonicalisation."
        )

    return _float_safe_coerce(obj)


def _hash_entry(
    prev_hash: str,
    entry_body: dict[str, Any],
    *,
    canonicaliser: _Canonicaliser,
    normaliser: Any = None,
) -> str:
    """``sha256(prev_hash + canonicaliser(normaliser(entry_without_hash)))``.

    The ``canonicaliser`` and ``normaliser`` are passed in explicitly so the
    same function can hash entries with either the legacy or the new
    canonicaliser (chain-version discrimination lives in the caller).
    """
    normalized = normaliser(entry_body) if normaliser is not None else entry_body
    payload = (prev_hash + canonicaliser(normalized)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _hash_entry_v2(prev_hash: str, entry_body: dict[str, Any]) -> str:
    """Hash a chain_version=2 entry (ACTENON-JCS-STRICT-1 canonicaliser)."""
    return _hash_entry(
        prev_hash,
        entry_body,
        canonicaliser=canonical_json,
        normaliser=_coerce_decimals_for_new_chain,
    )


def _hash_entry_legacy(prev_hash: str, entry_body: dict[str, Any]) -> str:
    """Hash a legacy (chain_version absent) entry (pre-2.0.0 canonicaliser)."""
    return _hash_entry(
        prev_hash,
        entry_body,
        canonicaliser=_legacy_canonical_json,
        normaliser=_json_normalize_legacy,
    )


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

        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
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
            # WO-4: chain_version discriminator. NULL (absent) = legacy
            # (<2.0.0) entry, verify with _legacy_canonical_json. 2 = entry
            # written by >=2.0.0, verify with canonical_json (ACTENON-JCS-STRICT-1).
            if "chain_version" not in columns:
                cur.execute("ALTER TABLE ledger ADD COLUMN chain_version INTEGER")

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
        """Append a single entry. Computes and stores the hash. Returns the entry.

        All new entries are written with ``chain_version = CURRENT_CHAIN_VERSION``
        (2 as of actenon-permit 2.0.0) and hashed via the ACTENON-JCS-STRICT-1
        canonicaliser. Legacy entries (written by <2.0.0) have ``chain_version``
        NULL and are verified with ``_legacy_canonical_json`` — see ``verify()``.
        """
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
                    "chain_version": CURRENT_CHAIN_VERSION,
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
                h = _hash_entry_v2(prev_hash, entry_body)

                cur.execute(
                    """
                    INSERT INTO ledger (
                        action_id, grant_id, ts, action_type, target, params,
                        est_cost, outcome, reason, rule_matched, state_delta,
                        failure_code, authority_boundary, prev_hash, hash,
                        chain_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        CURRENT_CHAIN_VERSION,
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

    def list_entries(self, grant_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            if grant_id:
                cur.execute(
                    "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
                    "est_cost, outcome, reason, rule_matched, state_delta, "
                    "failure_code, authority_boundary, prev_hash, hash, chain_version "
                    "FROM ledger WHERE grant_id = ? ORDER BY seq ASC LIMIT ?",
                    (grant_id, limit),
                )
            else:
                cur.execute(
                    "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
                    "est_cost, outcome, reason, rule_matched, state_delta, "
                    "failure_code, authority_boundary, prev_hash, hash, chain_version "
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
                    "chain_version": r[16],
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
        """Recompute the chain from row 0 and return True iff it is intact.

        Per-entry chain-version discrimination:

          - ``chain_version`` NULL  -> legacy entry; verify with
            ``_legacy_canonical_json`` (pre-2.0.0 canonicaliser).
          - ``chain_version = 2``   -> new entry; verify with
            ``canonical_json`` (ACTENON-JCS-STRICT-1).

        A mixed-version ledger (some legacy, some new) verifies intact as
        long as each entry's hash matches its own canonicaliser and the
        ``prev_hash`` chain is unbroken.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
                "est_cost, outcome, reason, rule_matched, state_delta, "
                "failure_code, authority_boundary, prev_hash, hash, chain_version "
                "FROM ledger ORDER BY seq ASC"
            )
            rows = cur.fetchall()

        prev_hash = GENESIS_PREV_HASH
        for r in rows:
            # Use dict to avoid column-order fragility (ALTER TABLE adds cols at end)
            cols = [
                "seq",
                "action_id",
                "grant_id",
                "ts",
                "action_type",
                "target",
                "params",
                "est_cost",
                "outcome",
                "reason",
                "rule_matched",
                "state_delta",
                "failure_code",
                "authority_boundary",
                "prev_hash",
                "hash",
                "chain_version",
            ]
            row_dict = dict(zip(cols, r, strict=True))
            action_id = row_dict["action_id"]
            grant_id = row_dict["grant_id"]
            ts = row_dict["ts"]
            action_type = row_dict["action_type"]
            target = row_dict["target"]
            params_json = row_dict["params"]
            est_cost = row_dict["est_cost"]
            outcome = row_dict["outcome"]
            reason = row_dict["reason"]
            rule_matched = row_dict["rule_matched"]
            state_delta_json = row_dict["state_delta"]
            failure_code = row_dict["failure_code"]
            authority_boundary_json = row_dict["authority_boundary"]
            stored_prev_hash = row_dict["prev_hash"]
            stored_hash = row_dict["hash"]
            chain_version = row_dict["chain_version"]

            # Check the prev_hash field matches what we expect.
            if stored_prev_hash != prev_hash:
                return False

            authority_boundary = (
                json.loads(authority_boundary_json) if authority_boundary_json else None
            )

            # Dispatch on chain_version. Legacy entries (NULL/absent) get the
            # legacy canonicaliser + legacy normaliser; new entries (==2) get
            # ACTENON-JCS-STRICT-1 + the float-safe Decimal coercer.
            if chain_version is None:
                # Pre-2.0.0 entry. Reconstruct the entry_body exactly as the
                # pre-2.0.0 code did (no chain_version field in the body).
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
                expected_hash = _hash_entry_legacy(prev_hash, entry_body)
            else:
                # chain_version == 2 (or future versions, when added).
                # New entries include chain_version in the hashed body.
                entry_body = {
                    "entry_format": "v2",
                    "chain_version": chain_version,
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
                expected_hash = _hash_entry_v2(prev_hash, entry_body)

            if expected_hash != stored_hash:
                return False

            prev_hash = stored_hash
        return True

    def close(self) -> None:
        if self._owns_conn:
            with self._lock:
                self._conn.close()
