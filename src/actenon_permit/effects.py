"""Durable consequence ownership in the same transaction as grant budget.

This is the authority store's implementation, not a parallel policy engine.
Only trusted boundary/operator code may settle or reconcile effects. Agents
must never receive a writable connection to this ledger or its signing keys.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from actenon_protocol.canonicalisation import canonicalize_json
from actenon_protocol.effects import EFFECT_PROFILE, effect_identity, validate_effect_outcome
from actenon_protocol.types.effects import EffectReference

from .model import Grant, GrantStatus


class EffectLedgerMixin:
    """SQLite effect operations; the owning store provides its connection/lock."""

    @staticmethod
    def _init_effect_schema(cur):
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS effect_reservations (
                reservation_id TEXT PRIMARY KEY,
                effect_id TEXT NOT NULL,
                action_id TEXT NOT NULL UNIQUE,
                grant_id TEXT NOT NULL,
                principal TEXT NOT NULL,
                action_hash TEXT NOT NULL,
                descriptor TEXT NOT NULL,
                reserved_amount REAL NOT NULL,
                state TEXT NOT NULL CHECK (state IN
                    ('RESERVED','DISPATCHING','COMMITTED','NOT_EXECUTED','AMBIGUOUS')),
                execution_occurred INTEGER,
                evidence TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_effect_live_owner
                ON effect_reservations(effect_id) WHERE state <> 'NOT_EXECUTED';
            CREATE TABLE IF NOT EXISTS effect_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                reservation_id TEXT NOT NULL,
                state TEXT NOT NULL,
                evidence TEXT,
                occurred_at TEXT NOT NULL
            );
        """)

    def reserve_effect(
        self,
        *,
        grant_id: str,
        action_id: str,
        descriptor: Mapping[str, Any],
        action_hash: str,
        principal: str,
        amount,
        rate_max: int = 0,
        rate_per_seconds: int = 60,
    ):
        """Reserve an effect AND debit its grant in one durable transaction.

        This method follows PDP authorization; it does not authorize policy.
        Namespace/semantic identity must come from trusted adapter config.
        Returns (ok, reason, snapshot), with a Protocol reference on success.
        A changed proof/action nonce never changes descriptor identity.
        """
        from .state import StateError, _budget_amount

        # Freeze the descriptor before hashing, storing or calling the ledger.
        descriptor_json = canonicalize_json(dict(descriptor))
        effect_id = effect_identity(json.loads(descriptor_json))
        reference = EffectReference(
            profile=EFFECT_PROFILE,
            effect_id=effect_id,
            reservation_id="reservation_" + uuid4().hex,
            owner_attempt_id=action_id,
        ).model_dump()
        if not isinstance(action_hash, str) or re.fullmatch(r"[0-9a-f]{64}", action_hash) is None:
            raise StateError("effect reservation requires an exact action hash")
        dec_amount = _budget_amount(amount)
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                # Scope identity is resource-owner-wide, never grant-wide:
                # obtaining another grant cannot repeat the same consequence.
                prior = cur.execute(
                    "SELECT state FROM effect_reservations WHERE effect_id = ? AND state <> 'NOT_EXECUTED'",
                    (effect_id,),
                ).fetchone()
                if prior:
                    cur.execute("ROLLBACK")
                    return (
                        False,
                        "effect already reserved, committed, or unresolved",
                        {"effect_id": effect_id},
                    )
                if cur.execute(
                    "SELECT 1 FROM effect_reservations WHERE action_id = ?", (action_id,)
                ).fetchone():
                    cur.execute("ROLLBACK")
                    return False, "effect attempt was already used", {"effect_id": effect_id}
                grant = self._effect_grant(cur, grant_id, principal)
                if grant.expires_at <= datetime.now(UTC):
                    raise StateError("effect grant is expired")
                ok, reason, snapshot = self._reserve_in_transaction(
                    cur, grant_id, action_id, dec_amount, rate_max, rate_per_seconds, time.time()
                )
                if not ok:
                    cur.execute("ROLLBACK")
                    return ok, reason, snapshot
                cur.execute(
                    """INSERT INTO effect_reservations
                    (reservation_id,effect_id,action_id,grant_id,principal,action_hash,descriptor,
                     reserved_amount,state,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,'RESERVED',?,?)""",
                    (
                        reference["reservation_id"],
                        effect_id,
                        action_id,
                        grant_id,
                        principal,
                        action_hash,
                        descriptor_json,
                        float(dec_amount),
                        now,
                        now,
                    ),
                )
                self._effect_event(
                    cur, reference["reservation_id"], "RESERVED", canonicalize_json(reference), now
                )
                cur.execute("COMMIT")
                return True, "effect and budget reserved", {**snapshot, "effect": reference}
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    @staticmethod
    def _effect_row(cur, reference, grant_id, principal, action_hash):
        from .state import StateError

        ref = EffectReference.model_validate(reference).model_dump()
        row = cur.execute(
            """SELECT reservation_id,effect_id,action_id,grant_id,principal,action_hash,
                                    descriptor,reserved_amount,state,execution_occurred,evidence
                             FROM effect_reservations WHERE reservation_id = ?""",
            (ref["reservation_id"],),
        ).fetchone()
        if row is None or tuple(row[:6]) != (
            ref["reservation_id"],
            ref["effect_id"],
            ref["owner_attempt_id"],
            grant_id,
            principal,
            action_hash,
        ):
            raise StateError(
                "effect reservation does not match authority, principal, attempt, or action"
            )
        return row

    def _effect_grant(self, cur, grant_id, principal):
        from .state import StateError

        row = cur.execute("SELECT body FROM grants WHERE id = ?", (grant_id,)).fetchone()
        if row is None:
            raise StateError("effect grant not found")
        grant = Grant.model_validate_json(row[0])
        if grant.agent_id != principal or not grant.verify():
            raise StateError("effect grant does not match the authenticated principal")
        if (
            grant.status not in {GrantStatus.ACTIVE, GrantStatus.EXHAUSTED}
            or self._revoked_ancestor(cur, grant.parent_grant_id, grant.id) is not None
        ):
            raise StateError("effect grant or ancestor is not active")
        return grant

    def claim_effect(self, *, reference, grant_id, principal, action_hash) -> bool:
        """One atomic RESERVED -> DISPATCHING transition, before credentials.

        Expiration is checked even when a proof still fits its own TTL. An
        exhausted grant may dispatch its already-paid reservation. A crash
        after this transition never releases the effect or its budget.
        """
        from .state import StateError

        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = self._effect_row(cur, reference, grant_id, principal, action_hash)
                grant = self._effect_grant(cur, grant_id, principal)
                if grant.expires_at <= datetime.now(UTC):
                    raise StateError("effect grant expired before dispatch")
                if row[8] != "RESERVED":
                    cur.execute("ROLLBACK")
                    return False
                cur.execute(
                    "UPDATE effect_reservations SET state = 'DISPATCHING', updated_at = ? WHERE reservation_id = ? AND state = 'RESERVED'",
                    (datetime.now(UTC).isoformat(), row[0]),
                )
                if cur.rowcount != 1:
                    raise StateError("effect ownership could not be claimed")
                self._effect_event(cur, row[0], "DISPATCHING", None, datetime.now(UTC).isoformat())
                cur.execute("COMMIT")
                return True
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    def settle_effect(
        self,
        *,
        reference,
        grant_id,
        principal,
        action_hash,
        outcome: str,
        execution_occurred: bool | None,
        evidence_hash: str,
        observer: str,
        actual_cost=None,
        reconciliation: bool = False,
        expected_event_sequence: int | None = None,
    ):
        """Record trusted certainty and settle the held budget atomically.

        ``observer`` and ``evidence_hash`` must identify authenticated boundary
        observation/operator evidence; a hash alone authenticates nothing.
        This is a trusted engine API, not an agent-callable reconcile route.
        Ambiguity keeps ownership and budget. No timer or lease clears it.
        A repeated identical settlement is read-only; conflict is refused.
        Signed/staged reconciliations must supply the reviewed event sequence.
        It is checked in the settlement transaction, so a decision prepared
        before dispatch cannot subsequently release an in-flight effect.
        """
        from .state import StateError, _budget_amount

        validate_effect_outcome(outcome, execution_occurred, evidence_hash)
        if not isinstance(observer, str) or not observer or observer.strip() != observer:
            raise StateError("effect settlement requires a trusted observer")
        if type(reconciliation) is not bool:
            raise StateError("reconciliation must be explicit")
        if expected_event_sequence is not None and (
            not reconciliation
            or type(expected_event_sequence) is not int
            or expected_event_sequence <= 0
        ):
            raise StateError("reviewed event sequence requires a positive integer reconciliation")
        cost = _budget_amount(actual_cost) if actual_cost is not None else None
        if cost is not None and cost < 0:
            raise StateError("effect settlement cost cannot be negative")
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = self._effect_row(cur, reference, grant_id, principal, action_hash)
                state, reserved = row[8], _budget_amount(row[7])
                if outcome == "NOT_EXECUTED" and cost not in (None, 0):
                    raise StateError("non-execution cannot have consequential cost")
                if outcome == "COMMITTED" and cost is None:
                    cost = reserved  # conservative reservation, no guessed refund
                if outcome == "AMBIGUOUS" and cost is not None:
                    raise StateError("ambiguous effects retain their entire reservation")
                evidence = canonicalize_json(
                    {
                        "outcome": outcome,
                        "execution_occurred": execution_occurred,
                        "evidence_hash": evidence_hash,
                        "observer": observer,
                        "reconciliation": reconciliation,
                        "actual_cost": str(cost) if cost is not None else None,
                    }
                )
                if state in {"COMMITTED", "NOT_EXECUTED"}:
                    if state != outcome or row[10] != evidence:
                        raise StateError("effect was already settled with different evidence")
                    remaining = cur.execute(
                        "SELECT remaining FROM grants WHERE id = ?", (grant_id,)
                    ).fetchone()[0]
                    cur.execute("ROLLBACK")
                    return {
                        "remaining": remaining,
                        "effect": {
                            **dict(reference),
                            "outcome": outcome,
                            "execution_occurred": execution_occurred,
                            "evidence_hash": evidence_hash,
                        },
                    }
                if expected_event_sequence is not None:
                    latest = cur.execute(
                        "SELECT MAX(sequence) FROM effect_events WHERE reservation_id = ?",
                        (row[0],),
                    ).fetchone()[0]
                    if latest != expected_event_sequence:
                        raise StateError(
                            "effect changed since review; obtain a fresh reconciliation"
                        )
                if state == "AMBIGUOUS" and outcome != "AMBIGUOUS" and not reconciliation:
                    raise StateError("ambiguous outcome requires trusted reconciliation")
                if state == "RESERVED" and outcome != "NOT_EXECUTED":
                    raise StateError("an unclaimed effect cannot be reported as executed")
                if reconciliation and state not in {"DISPATCHING", "AMBIGUOUS", "RESERVED"}:
                    raise StateError("effect does not require reconciliation")
                if outcome == "COMMITTED":
                    # Overruns debit additional authority rather than vanishing.
                    # Excess beyond the public non-negative balance is durable debt.
                    remaining = self._commit_in_transaction(
                        cur, grant_id, row[2], cost, reserved, now
                    )
                elif outcome == "NOT_EXECUTED":
                    remaining = self._release_in_transaction(cur, grant_id, row[2], reserved, now)
                else:
                    remaining = cur.execute(
                        "SELECT remaining FROM grants WHERE id = ?", (grant_id,)
                    ).fetchone()[0]
                cur.execute(
                    "UPDATE effect_reservations SET state = ?, execution_occurred = ?, evidence = ?, updated_at = ? WHERE reservation_id = ?",
                    (outcome, execution_occurred, evidence, now, row[0]),
                )
                self._effect_event(cur, row[0], outcome, evidence, now)
                cur.execute("COMMIT")
                return {
                    "remaining": remaining,
                    "effect": {
                        **dict(reference),
                        "outcome": outcome,
                        "execution_occurred": execution_occurred,
                        "evidence_hash": evidence_hash,
                    },
                }
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
                raise

    @staticmethod
    def _effect_event(cur, reservation_id, state, evidence, now):
        cur.execute(
            "INSERT INTO effect_events(reservation_id,state,evidence,occurred_at) VALUES (?,?,?,?)",
            (reservation_id, state, evidence, now),
        )

    def effect_history(self, effect_id):
        """Trusted audit input: prior ambiguity and reconciliation are retained."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT e.sequence,e.reservation_id,e.state,e.evidence,e.occurred_at
                FROM effect_events e JOIN effect_reservations r ON r.reservation_id = e.reservation_id
                WHERE r.effect_id = ? ORDER BY e.sequence""",
                (effect_id,),
            ).fetchall()
        return [
            {
                "sequence": r[0],
                "reservation_id": r[1],
                "state": r[2],
                "evidence": json.loads(r[3]) if r[3] else None,
                "occurred_at": r[4],
            }
            for r in rows
        ]

    def get_effect(self, effect_id: str):
        """Trusted diagnostics; retains all attempts, including non-execution."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT reservation_id,action_id,grant_id,principal,action_hash,state,
                  execution_occurred,evidence,descriptor,
                  (SELECT MAX(sequence) FROM effect_events e
                   WHERE e.reservation_id = effect_reservations.reservation_id)
                  FROM effect_reservations WHERE effect_id = ? ORDER BY created_at""",
                (effect_id,),
            ).fetchall()
        return [
            {
                "reference": {
                    "profile": EFFECT_PROFILE,
                    "effect_id": effect_id,
                    "reservation_id": r[0],
                    "owner_attempt_id": r[1],
                },
                "grant_id": r[2],
                "principal": r[3],
                "action_hash": r[4],
                "state": r[5],
                "execution_occurred": None if r[6] is None else bool(r[6]),
                "evidence": json.loads(r[7]) if r[7] else None,
                "descriptor": json.loads(r[8]),
                "event_sequence": r[9],
            }
            for r in rows
        ]

    @staticmethod
    def _require_legacy_reservation(cur, action_id):
        from .state import StateError

        if cur.execute(
            "SELECT 1 FROM effect_reservations WHERE action_id = ?", (action_id,)
        ).fetchone():
            raise StateError("effect-backed budget requires effect settlement or reconciliation")
