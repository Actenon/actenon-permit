"""Tamper-evidence test: mutating a ledger row breaks the hash chain and
``verify()`` returns False.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

from actenon_permit import (
    PDP,
    Budget,
    Grant,
    Ledger,
    Rate,
    Scopes,
    SQLiteStore,
)
from actenon_permit.model import Action


def _make_grant() -> Grant:
    g = Grant(
        agent_id="ledger-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(currency="USD", limit=100, remaining=100),
        rate=Rate(max=0, per_seconds=60),
    )
    g.sign()
    return g


def test_ledger_appends_and_verifies(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    a1 = Action(grant_id=g.id, type="payment.refund", params={"amount": 10}, est_cost=10)
    a2 = Action(grant_id=g.id, type="payment.refund", params={"amount": 20}, est_cost=20)
    pdp.decide(g, a1)
    pdp.decide(g, a2)

    entries = ledger.list_entries()
    assert len(entries) == 2
    assert ledger.verify() is True


def test_ledger_genesis_prev_hash(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    a = Action(grant_id=g.id, type="payment.refund", params={"amount": 10}, est_cost=10)
    pdp.decide(g, a)
    entries = ledger.list_entries()
    assert entries[0]["prev_hash"] == "0" * 64


def test_ledger_tamper_breaks_chain(tmp_db):
    """Mutate a row in-place — verify() must catch it."""
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    a1 = Action(grant_id=g.id, type="payment.refund", params={"amount": 10}, est_cost=10)
    a2 = Action(grant_id=g.id, type="payment.refund", params={"amount": 20}, est_cost=20)
    a3 = Action(grant_id=g.id, type="payment.refund", params={"amount": 5}, est_cost=5)
    pdp.decide(g, a1)
    pdp.decide(g, a2)
    pdp.decide(g, a3)

    # Chain should be intact initially.
    assert ledger.verify() is True

    # Mutate the SECOND entry's reason in-place. The hash no longer matches.
    conn = sqlite3.connect(str(tmp_db), isolation_level=None)
    conn.execute(
        "UPDATE ledger SET reason = ? WHERE seq = ?",
        ("TAMPERED", 2),
    )
    conn.commit()
    conn.close()

    assert ledger.verify() is False


def test_ledger_tamper_hash_breaks_chain(tmp_db):
    """If an attacker recomputes only the tampered row's hash (but not the
    downstream rows), verify() must still catch it.
    """
    import hashlib

    from actenon_permit.model import canonical_json

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    a1 = Action(grant_id=g.id, type="payment.refund", params={"amount": 10}, est_cost=10)
    a2 = Action(grant_id=g.id, type="payment.refund", params={"amount": 20}, est_cost=20)
    pdp.decide(g, a1)
    pdp.decide(g, a2)
    assert ledger.verify() is True

    # Tamper: change the first entry's reason AND recompute its hash, but
    # leave the second entry's prev_hash pointing at the OLD hash. verify()
    # should fail because the second entry's prev_hash no longer matches.
    conn = sqlite3.connect(str(tmp_db), isolation_level=None)
    cur = conn.cursor()
    cur.execute("UPDATE ledger SET reason = ? WHERE seq = 1", ("TAMPERED",))
    # Compute a "fake" hash for the tampered row.
    fake_payload = {"reason": "TAMPERED"}
    fake_hash = hashlib.sha256(canonical_json(fake_payload).encode("utf-8")).hexdigest()
    cur.execute("UPDATE ledger SET hash = ? WHERE seq = 1", (fake_hash,))
    conn.commit()
    conn.close()

    assert ledger.verify() is False


def test_ledger_hash_chain_progression(tmp_db):
    """Each entry's prev_hash equals the previous entry's hash."""
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    for amt in (10, 20, 5, 15):
        a = Action(grant_id=g.id, type="payment.refund", params={"amount": amt}, est_cost=amt)
        pdp.decide(g, a)

    entries = ledger.list_entries()
    assert len(entries) == 4
    assert entries[0]["prev_hash"] == "0" * 64
    for i in range(1, len(entries)):
        assert entries[i]["prev_hash"] == entries[i - 1]["hash"]


# ===========================================================================
# WO-4: chain_version discrimination — mixed-version ledger verifies intact
# ===========================================================================


def test_mixed_version_ledger_verifies_intact(tmp_db):
    """WO-4 acceptance criterion 3: a ledger containing BOTH legacy entries
    (chain_version absent, written by <2.0.0) AND new entries (chain_version=2,
    written by >=2.0.0) must verify intact.

    The verifier dispatches per-entry: legacy entries are hashed with
    _legacy_canonical_json (pre-2.0.0 canonicaliser), new entries with
    canonical_json (ACTENON-JCS-STRICT-1). A mixed chain verifies as long
    as each entry's hash matches its own canonicaliser and the prev_hash
    chain is unbroken.

    This test constructs a mixed-version ledger by:
      1. Appending 2 entries with the NEW code (chain_version=2).
      2. Manually rewriting 2 entries as LEGACY (chain_version=NULL,
         hashes computed with _legacy_canonical_json) via direct SQL.
      3. Asserting verify() returns True.
    """
    import sqlite3

    from actenon_permit.ledger import GENESIS_PREV_HASH, _hash_entry_legacy

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    # Append 4 entries normally (all chain_version=2).
    for amt in (10, 20, 5, 15):
        a = Action(grant_id=g.id, type="payment.refund", params={"amount": amt}, est_cost=amt)
        pdp.decide(g, a)

    # Sanity: all 4 are chain_version=2 and verify.
    entries = ledger.list_entries()
    assert len(entries) == 4
    assert all(e["chain_version"] == 2 for e in entries), (
        f"expected all chain_version=2, got {[e['chain_version'] for e in entries]}"
    )
    assert ledger.verify() is True

    # Now rewrite entries 1 and 2 as LEGACY (chain_version=NULL, legacy hash).
    # We use _hash_entry_legacy to compute the legacy hash for the legacy
    # entry body (which does NOT include chain_version as a field).
    conn = sqlite3.connect(str(tmp_db), isolation_level=None)
    cur = conn.cursor()

    # Read the current entries 1 and 2 to reconstruct their bodies.
    rows = cur.execute(
        "SELECT seq, action_id, grant_id, ts, action_type, target, params, "
        "est_cost, outcome, reason, rule_matched, state_delta, failure_code, "
        "authority_boundary, prev_hash FROM ledger WHERE seq IN (1, 2) ORDER BY seq"
    ).fetchall()

    # Genesis prev_hash for entry 1; entry 2's prev_hash is entry 1's NEW hash.
    # But we're rewriting entry 1's hash too, so entry 2's prev_hash must point
    # at entry 1's NEW (legacy) hash. We'll compute both legacy hashes in order.
    prev = GENESIS_PREV_HASH
    for r in rows:
        (
            seq,
            action_id,
            grant_id,
            ts,
            action_type,
            target,
            params_json,
            est_cost,
            outcome,
            reason,
            rule_matched,
            state_delta_json,
            failure_code,
            authority_boundary_json,
            _old_prev_hash,
        ) = r
        params = json.loads(params_json) if params_json else {}
        state_delta = json.loads(state_delta_json) if state_delta_json else {}
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
            "params": params,
            "est_cost": est_cost,
            "outcome": outcome,
            "reason": reason,
            "rule_matched": rule_matched,
            "state_delta": state_delta,
            "failure_code": failure_code,
            "authority_boundary": authority_boundary,
            "prev_hash": prev,
        }
        legacy_hash = _hash_entry_legacy(prev, entry_body)
        cur.execute(
            "UPDATE ledger SET chain_version = NULL, hash = ?, prev_hash = ? WHERE seq = ?",
            (legacy_hash, prev, seq),
        )
        prev = legacy_hash
    conn.commit()
    conn.close()

    # Now cascade: entries 3 and 4 were written with v2 hashes computed
    # against the ORIGINAL prev_hash chain. Rewriting entries 1,2 as legacy
    # changed entry 2's hash, which invalidates entry 3's prev_hash (and
    # therefore entry 3's hash, and therefore entry 4's prev_hash, and
    # therefore entry 4's hash). In a real migration, entries 3 and 4
    # would have been written AFTER the upgrade, with prev_hash pointing
    # at whatever the then-current entry 2 hash was. We simulate that by
    # recomputing entries 3 and 4 with the v2 canonicaliser against the
    # new prev_hash chain.
    from actenon_permit.ledger import _hash_entry_v2

    conn = sqlite3.connect(str(tmp_db), isolation_level=None)
    cur = conn.cursor()
    # Walk entries 3 and 4 in order, recomputing each one's prev_hash and
    # hash against the previous entry's CURRENT hash.
    prev = cur.execute("SELECT hash FROM ledger WHERE seq = 2").fetchone()[0]
    for seq in (3, 4):
        row = cur.execute(
            "SELECT action_id, grant_id, ts, action_type, target, params, "
            "est_cost, outcome, reason, rule_matched, state_delta, failure_code, "
            "authority_boundary FROM ledger WHERE seq = ?",
            (seq,),
        ).fetchone()
        (
            action_id,
            grant_id,
            ts,
            action_type,
            target,
            params_json,
            est_cost,
            outcome,
            reason,
            rule_matched,
            state_delta_json,
            failure_code,
            authority_boundary_json,
        ) = row
        body = {
            "entry_format": "v2",
            "chain_version": 2,
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
            "authority_boundary": json.loads(authority_boundary_json)
            if authority_boundary_json
            else None,
            "prev_hash": prev,
        }
        new_hash = _hash_entry_v2(prev, body)
        cur.execute(
            "UPDATE ledger SET prev_hash = ?, hash = ? WHERE seq = ?",
            (prev, new_hash, seq),
        )
        prev = new_hash
    conn.commit()
    conn.close()

    # Verify: mixed-version ledger (entries 1,2 = legacy; entries 3,4 = v2).
    entries = ledger.list_entries()
    assert entries[0]["chain_version"] is None, (
        f"entry 1 should be legacy, got {entries[0]['chain_version']}"
    )
    assert entries[1]["chain_version"] is None, (
        f"entry 2 should be legacy, got {entries[1]['chain_version']}"
    )
    assert entries[2]["chain_version"] == 2, (
        f"entry 3 should be v2, got {entries[2]['chain_version']}"
    )
    assert entries[3]["chain_version"] == 2, (
        f"entry 4 should be v2, got {entries[3]['chain_version']}"
    )

    assert ledger.verify() is True, (
        "mixed-version ledger (legacy entries 1,2 + v2 entries 3,4) must verify intact"
    )


def test_new_entries_have_chain_version_2(tmp_db):
    """WO-4: all new entries written by >=2.0.0 carry chain_version=2."""
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    a = Action(grant_id=g.id, type="payment.refund", params={"amount": 10}, est_cost=10)
    pdp.decide(g, a)

    entries = ledger.list_entries()
    assert len(entries) == 1
    assert entries[0]["chain_version"] == 2


def test_legacy_entry_with_wrong_hash_breaks_chain(tmp_db):
    """WO-4: a legacy entry (chain_version=NULL) whose hash doesn't match
    _legacy_canonical_json's output breaks the chain — verify() returns False."""
    import sqlite3

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    g = _make_grant()
    store.put_grant(g)

    a = Action(grant_id=g.id, type="payment.refund", params={"amount": 10}, est_cost=10)
    pdp.decide(g, a)

    # Rewrite entry 1 as "legacy" but with a WRONG hash.
    conn = sqlite3.connect(str(tmp_db), isolation_level=None)
    conn.execute(
        "UPDATE ledger SET chain_version = NULL, hash = ? WHERE seq = 1", ("deadbeef" * 8,)
    )
    conn.commit()
    conn.close()

    assert ledger.verify() is False
