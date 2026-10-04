"""Budget arithmetic must not discard small charges or round a cap upward."""

from contextlib import closing
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext

import pytest

from actenon_permit import PDP, Action, Broker, Budget, Grant, Ledger, Scopes, SQLiteStore
from actenon_permit.policy import compile_policy, load_policy
from actenon_permit.state import StateError


def grant(limit):
    return Grant(
        agent_id="exact-budget",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"]),
        budget=Budget(limit=limit, remaining=limit),
    ).sign()


def test_small_charges_survive_large_balance_and_reopen(tmp_path):
    path = str(tmp_path / "state.db")
    original = grant(Decimal("10000000000000000"))
    with closing(SQLiteStore(path)) as store:
        store.put_grant(original)
        for index in range(3):
            assert store.reserve(original.id, f"charge-{index}", Decimal("1"), 0, 60)[0]
    with closing(SQLiteStore(path)) as store:
        assert store.get_grant(original.id).budget.remaining == Decimal("9999999999999997")
        store.commit(original.id, "charge-0", Decimal("0.125"), Decimal("1"))
        assert store.get_grant(original.id).budget.remaining == Decimal("9999999999999997.875")
        store.release(original.id, "charge-1", Decimal("1"))
        assert store.get_grant(original.id).budget.remaining == Decimal("9999999999999998.875")


def test_balance_is_not_rounded_up_above_signed_cap(tmp_path):
    original = grant(Decimal("9007199254740995"))
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        store.put_grant(original)
        assert not store.reserve(original.id, "above-cap", Decimal("9007199254740996"), 0, 60)[0]
        assert store.get_grant(original.id).budget.remaining == original.budget.limit


def test_policy_compilation_retains_exact_decimal_limit():
    compiled = compile_policy(
        {
            "agent": "exact-policy",
            "ttl": "1h",
            "budget": {"limit": "9007199254740995.125"},
            "scopes": {"allow": ["payment.refund"]},
        }
    )
    assert compiled.budget.limit == Decimal("9007199254740995.125")
    assert compiled.budget.remaining == compiled.budget.limit


def test_decimal_context_cannot_change_reservation_arithmetic(tmp_path):
    original = grant(Decimal("123456789012345678901234567890.125"))
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        store.put_grant(original)
        with localcontext() as context:
            context.prec = 6
            assert store.reserve(original.id, "context-charge", Decimal("0.001"), 0, 60)[0]
        assert store.get_grant(original.id).budget.remaining == Decimal(
            "123456789012345678901234567890.124"
        )


def test_unrepresentable_cost_is_refused_without_mutation(tmp_path):
    original = grant(Decimal("1"))
    with closing(SQLiteStore(str(tmp_path / "state.db"))) as store:
        store.put_grant(original)
        with pytest.raises(StateError, match="precision"):
            store.reserve(original.id, "nano-fraction", Decimal("0.0000000001"), 0, 60)
        assert store.get_grant(original.id).budget.remaining == Decimal("1")


def test_real_pdp_records_and_verifies_exact_decimal_cost(tmp_path):
    path = str(tmp_path / "pdp.db")
    original = grant(Decimal("10000000000000000"))
    with closing(SQLiteStore(path)) as store, closing(Ledger(path)) as ledger:
        store.put_grant(original)
        pdp = PDP(store, ledger)
        with localcontext() as context:
            context.prec = 6
            decision = pdp.decide(
                original,
                Action(
                    grant_id=original.id,
                    type="payment.refund",
                    target="payment-1",
                    params={"amount": "1234567890123456.125"},
                    est_cost=Decimal("1234567890123456.125"),
                ),
            )
        assert decision.outcome.value == "ALLOW"
        assert store.get_grant(original.id).budget.remaining == Decimal("8765432109876543.875")
        assert Decimal(ledger.list_entries()[0]["est_cost"]) == Decimal("1234567890123456.125")
        assert ledger.verify()
    with closing(Ledger(path)) as reopened:
        assert reopened.verify()


def test_legacy_migration_cannot_restore_known_lost_charges(tmp_path):
    path = str(tmp_path / "legacy.db")
    original = grant(Decimal("10000000000000000"))
    with closing(SQLiteStore(path)) as store:
        store.put_grant(original)
        for index in range(3):
            assert store.reserve(original.id, f"old-{index}", 1, 0, 60)[0]
        # Construct the actual previous schema and its lossy 1e16 remainder.
        store._conn.execute("UPDATE grants SET remaining = ?", (1e16,))
        original.budget.remaining = Decimal("10000000000000000")
        store._conn.execute("UPDATE grants SET body = ?", (original.model_dump_json(),))
        for table, column in (
            ("grants", "remaining_units"),
            ("rate_events", "reserved_units"),
            ("rate_events", "actual_units"),
            ("budget_overruns", "amount_units"),
            ("effect_reservations", "reserved_units"),
        ):
            store._conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    with closing(SQLiteStore(path)) as store:
        migrated = store.get_grant(original.id)
        assert migrated.verify()
        assert migrated.budget.remaining <= Decimal("9999999999999997")
        assert not store.reserve(
            original.id, "over-old-cap", Decimal("9999999999999997.001"), 0, 60
        )[0]
        store.release(original.id, "old-0", 1)
        assert store.get_grant(original.id).budget.remaining <= Decimal("9999999999999998")


def test_yaml_decimal_and_delegation_do_not_pass_through_float(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "agent: exact-yaml\nbudget:\n  limit: 9007199254740995.125\n"
        "scopes:\n  allow: [payment.refund]\n"
    )
    parent = compile_policy(load_policy(path))
    assert parent.budget.limit == Decimal("9007199254740995.125")
    child = parent.attenuate(budget_limit="9007199254740995.124")
    assert child.budget.limit == Decimal("9007199254740995.124")
    assert child.verify()


def test_v3_exact_cost_tampering_and_unknown_version_are_refused(tmp_path):
    path = str(tmp_path / "audit.db")
    with closing(Ledger(path)) as ledger:
        ledger.append(
            action_id="audit-cost",
            grant_id="g",
            ts=datetime.now(UTC),
            action_type="payment.refund",
            target="payment-1",
            params={},
            est_cost=Decimal("9007199254740995.125"),
            outcome="ALLOW",
            reason="test",
            rule_matched=None,
            state_delta={},
        )
        assert ledger.verify()
        ledger._conn.execute("UPDATE ledger SET est_cost_exact = ?", ("9007199254740996.125",))
        assert not ledger.verify()
        ledger._conn.execute(
            "UPDATE ledger SET est_cost_exact = ?, chain_version = 999", ("9007199254740995.125",)
        )
        assert not ledger.verify()


def test_real_broker_settles_exact_provider_cost(tmp_path, monkeypatch):
    path = str(tmp_path / "broker.db")
    original = grant(Decimal("10000000000000000"))
    monkeypatch.setenv("EXACT_COST_TEST_KEY", "synthetic-test-only")
    with closing(SQLiteStore(path)) as store, closing(Ledger(path)) as ledger:
        store.put_grant(original)
        pdp = PDP(store, ledger)
        action = Action(grant_id=original.id, type="payment.refund", est_cost=Decimal("20.125"))
        decision = pdp.decide(original, action)
        assert decision.outcome.value == "ALLOW"
        calls = []

        def provider(secret):
            assert secret == "synthetic-test-only"
            calls.append(True)
            return {"cost": Decimal("20.124")}

        _, actual = Broker(pdp).execute(original, action, decision, provider, "EXACT_COST_TEST_KEY")
        assert actual == Decimal("20.124")
        assert calls == [True]
        assert store.get_grant(original.id).budget.remaining == Decimal("9999999999999979.876")
        assert ledger.verify()


def test_approval_band_does_not_round_a_large_amount_under_threshold(tmp_path):
    path = str(tmp_path / "approval.db")
    original = grant(Decimal("10000000000000000"))
    original.approval_rules = ["payment.refund > 9007199254740992"]
    original.sign()
    with closing(SQLiteStore(path)) as store, closing(Ledger(path)) as ledger:
        store.put_grant(original)
        decision = PDP(store, ledger).decide(
            original,
            Action(
                grant_id=original.id,
                type="payment.refund",
                params={"amount": 9007199254740993},
                est_cost=Decimal("9007199254740993"),
            ),
        )
        assert decision.outcome.value == "REQUIRE_APPROVAL"
        assert store.get_grant(original.id).budget.remaining == original.budget.limit
        assert ledger.verify()


def test_json_float_cannot_silently_widen_declared_budget():
    import json

    policy = json.loads('{"agent":"json-authority","budget":{"limit":9007199254740995.125}}')
    with pytest.raises(ValueError, match="fixed-point precision"):
        compile_policy(policy)
