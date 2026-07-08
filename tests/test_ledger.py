"""Tamper-evidence test: mutating a ledger row breaks the hash chain and
``verify()`` returns False.
"""

from __future__ import annotations

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
