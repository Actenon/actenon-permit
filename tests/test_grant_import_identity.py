"""A reusable signed grant is authority, never a mutable-state reset command."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from threading import Barrier

import pytest

from actenon_permit import Budget, Grant, GrantStatus, Scopes, SQLiteStore
from actenon_permit.state import StateError


def grant():
    return Grant(
        agent_id="imported-agent",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(limit=50, remaining=50),
    ).sign()


def test_reimport_cannot_restore_spent_budget_or_reservation(tmp_path):
    path = str(tmp_path / "state.db")
    original = grant()
    with closing(SQLiteStore(path)) as first:
        first.put_grant(original)
        assert first.reserve(original.id, "reserved", 30, 0, 60)[0]
    with closing(SQLiteStore(path)) as second:
        second.put_grant(original)
        assert second.get_grant(original.id).budget.remaining == Decimal("20")
        assert not second.reserve(original.id, "overspend", 30, 0, 60)[0]
        assert second.commit(original.id, "reserved", 25, 30) == 25
        second.put_grant(original)
        assert second.get_grant(original.id).budget.remaining == Decimal("25")


@pytest.mark.parametrize(
    "status", [GrantStatus.REVOKED, GrantStatus.EXPIRED, GrantStatus.EXHAUSTED]
)
def test_reimport_cannot_reactivate_grant(tmp_path, status):
    original = grant()
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        store.put_grant(original)
        store.set_status(original.id, status)
        store.put_grant(original)
        assert store.get_grant(original.id).status == status
        assert not store.reserve(original.id, "forbidden", 1, 0, 60)[0]


@pytest.mark.parametrize("field", ["scope", "cap", "subject", "expiry", "approval", "parent"])
def test_even_resigned_changed_authority_requires_new_identity(tmp_path, field):
    original = grant()
    changed = original.model_copy(deep=True)
    if field == "scope":
        changed.scopes.allow.append("*")
    elif field == "cap":
        changed.budget.limit = 100
    elif field == "subject":
        changed.agent_id = "other-agent"
    elif field == "expiry":
        changed.expires_at += timedelta(hours=1)
    elif field == "approval":
        changed.approval_rules = ["payment.refund > 10"]
    else:
        changed.parent_grant_id = "different-parent"
    changed.sign()
    assert changed.verify()
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        store.put_grant(original)
        before = store.get_grant(original.id).model_dump_json()
        with pytest.raises(StateError, match="authority.*identity"):
            store.put_grant(changed)
        assert store.get_grant(original.id).model_dump_json() == before


def test_two_importing_clients_do_not_reset_each_others_spend(tmp_path):
    path = str(tmp_path / "state.db")
    original = grant()
    ready = Barrier(2)

    def client(index):
        with closing(SQLiteStore(path)) as store:
            ready.wait(timeout=10)
            store.put_grant(original)
            return store.reserve(original.id, f"attempt-{index}", 30, 0, 60)[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(client, range(2)))
    assert sorted(results) == [False, True]
    with closing(SQLiteStore(path)) as store:
        assert store.get_grant(original.id).budget.remaining == Decimal("20")


def test_new_grant_cannot_start_above_signed_cap(tmp_path):
    overfunded = grant()
    overfunded.budget.remaining = 500
    assert overfunded.verify()  # remaining is live state, not signed authority
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        with pytest.raises(StateError, match="remaining.*limit"):
            store.put_grant(overfunded)
        assert store.get_grant(overfunded.id) is None


def test_legacy_signature_bootstrap_preserves_live_state(tmp_path):
    original = grant()
    original.signature = ""
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        store.put_grant(original)
        assert store.reserve(original.id, "legacy-reservation", 30, 0, 60)[0]
        store.set_status(original.id, GrantStatus.REVOKED)
        invalid = original.model_copy(deep=True, update={"signature": "not-a-signature"})
        with pytest.raises(StateError, match="authority.*identity"):
            store.put_grant(invalid)
        original.sign()
        store.put_grant(original)
        live = store.get_grant(original.id)
        assert live.verify()
        assert live.budget.remaining == Decimal("20")
        assert live.status == GrantStatus.REVOKED
        assert not store.reserve(original.id, "revoked-attempt", 1, 0, 60)[0]
