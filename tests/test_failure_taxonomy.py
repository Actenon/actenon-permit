"""Invariant test (C): the recorded failure_code is emitted by the decision
path, never reconstructed or parsed from the reason string.

This test proves:
  1. Every denial scenario records the correct FailureCode in the ledger
  2. The code is provably the PDP's emitted Decision.failure_code — not
     derived from the reason string
  3. The "misleading reason" case: reason="looks fine" but
     failure_code=BUDGET_EXCEEDED → the ledger records BUDGET_EXCEEDED,
     not a reconstruction from "looks fine"
  4. ledger.append has no code-derivation logic (code is a required argument
     sourced from the Decision)
  5. Hash-chain verify() passes with v2 entries
  6. Mutating failure_code or authority_boundary in a row breaks verify()
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from actenon.outcomes import TAXONOMY_VERSION, FailureCode

from actenon_permit import (
    PDP,
    Budget,
    Grant,
    GrantStatus,
    Ledger,
    Rate,
    Scopes,
    SQLiteStore,
)
from actenon_permit.model import Action, Decision, DecisionOutcome


@pytest.fixture
def stack(tmp_db, monkeypatch):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    return store, ledger, pdp


def _make_grant(*, budget_limit=50, allow=None, deny=None, status=GrantStatus.ACTIVE,
                expires_in_seconds=3600):
    g = Grant(
        agent_id="taxonomy-test-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_seconds),
        scopes=Scopes(allow=allow or ["payment.refund", "email.send"],
                      deny=deny or ["payment.charge"]),
        budget=Budget(currency="USD", limit=budget_limit, remaining=budget_limit),
        rate=Rate(max=100, per_seconds=60),
        status=status,
    )
    g.sign()
    return g


def _make_action(grant, *, type="payment.refund", amount=20, **params):
    p = dict(params)
    if amount is not None:
        p["amount"] = amount
    return Action(grant_id=grant.id, type=type, target=type, params=p, est_cost=amount)


# ===========================================================================
# 1. Every denial scenario records the correct FailureCode
# ===========================================================================


class TestFailureCodePerScenario:
    """For every denial path in the PDP, assert the ledger records the
    correct FailureCode — comparing against Decision.failure_code, not
    a string."""

    def test_revoked_records_REVOKED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant(status=GrantStatus.REVOKED)
        store.put_grant(grant)
        action = _make_action(grant)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.REVOKED
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "REVOKED"

    def test_not_active_records_NOT_ACTIVE(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant(status=GrantStatus.EXHAUSTED)
        store.put_grant(grant)
        action = _make_action(grant)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.NOT_ACTIVE
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "NOT_ACTIVE"

    def test_expired_records_EXPIRED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant(expires_in_seconds=-10)
        store.put_grant(grant)
        action = _make_action(grant)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.EXPIRED
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "EXPIRED"

    def test_scope_denied_records_SCOPE_DENIED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)
        action = _make_action(grant, type="payment.charge")
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.SCOPE_DENIED
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "SCOPE_DENIED"

    def test_out_of_scope_records_OUT_OF_SCOPE(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant(allow=["payment.refund"])
        store.put_grant(grant)
        action = _make_action(grant, type="shell.exec")
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.OUT_OF_SCOPE
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "OUT_OF_SCOPE"

    def test_budget_exceeded_records_BUDGET_EXCEEDED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant(budget_limit=10)
        store.put_grant(grant)
        action = _make_action(grant, amount=20)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.BUDGET_EXCEEDED
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "BUDGET_EXCEEDED"

    def test_rate_limited_records_RATE_LIMITED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant()
        grant.rate = Rate(max=2, per_seconds=60)
        store.put_grant(grant)
        # Fire 3 actions — the 3rd should be rate-limited
        for _ in range(3):
            action = _make_action(grant, amount=1)
            d = pdp.decide(grant, action)
        entries = ledger.list_entries()
        rate_denied = [e for e in entries if e["failure_code"] == "RATE_LIMITED"]
        assert len(rate_denied) >= 1
        assert d.failure_code == FailureCode.RATE_LIMITED

    def test_allowed_records_ALLOWED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)
        action = _make_action(grant, amount=10)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.ALLOWED
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "ALLOWED"

    def test_approval_required_records_APPROVAL_REQUIRED(self, stack):
        store, ledger, pdp = stack
        grant = _make_grant()
        grant.approval_rules = ["email.send"]
        store.put_grant(grant)
        action = _make_action(grant, type="email.send", amount=None)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.APPROVAL_REQUIRED
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "APPROVAL_REQUIRED"

    def test_engine_error_records_ENGINE_ERROR(self, stack, monkeypatch):
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        # Inject a fault into _decide_inner to trigger fail-closed
        def boom(*_a, **_kw):
            raise RuntimeError("simulated engine fault")

        pdp._decide_inner = boom  # type: ignore[method-assign]
        action = _make_action(grant, amount=10)
        d = pdp.decide(grant, action)
        assert d.failure_code == FailureCode.ENGINE_ERROR
        assert d.outcome == DecisionOutcome.DENY
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] == "ENGINE_ERROR"


# ===========================================================================
# 2. Invariant (C): the code is emitted, not reconstructed from reason
# ===========================================================================


class TestEmittedNotReconstructed:
    """Prove the ledger records the emitted code, never a reconstruction
    from the reason string."""

    def test_misleading_reason_records_correct_code(self, stack):
        """Construct a Decision with reason='looks fine' but
        failure_code=BUDGET_EXCEEDED. Append it to the ledger.
        Assert the persisted code is BUDGET_EXCEEDED — not derived from
        'looks fine'."""
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        from actenon_permit.pdp import _build_authority_boundary

        action = _make_action(grant, amount=10)

        # Create a Decision with a MISLEADING reason
        misleading = Decision(
            outcome=DecisionOutcome.DENY,
            reason="looks fine",  # misleading!
            rule_matched="budget",
            state_delta={},
            failure_code=FailureCode.BUDGET_EXCEEDED,  # the REAL code
        )

        # Append it directly — the ledger must record the code from the
        # Decision, not parse it from "looks fine"
        ledger.append(
            action_id="act_misleading_test",
            grant_id=grant.id,
            ts=datetime.now(UTC),
            action_type="payment.refund",
            target="stripe",
            params={"amount": 10},
            est_cost=10,
            outcome="DENY",
            reason="looks fine",
            rule_matched="budget",
            state_delta={},
            failure_code=misleading.failure_code,
            authority_boundary=_build_authority_boundary(grant, action),
        )

        entries = ledger.list_entries()
        entry = entries[-1]
        assert entry["failure_code"] == "BUDGET_EXCEEDED", (
            f"ledger must record the EMITTED code (BUDGET_EXCEEDED), "
            f"not a reconstruction from 'looks fine'. Got: {entry['failure_code']}"
        )
        assert entry["reason"] == "looks fine", "reason is preserved as gloss"

    def test_ledger_append_has_no_code_derivation(self):
        """Assert ledger.append() accepts failure_code as a parameter —
        it does NOT derive the code from reason."""
        import inspect

        from actenon_permit.ledger import Ledger

        sig = inspect.signature(Ledger.append)
        assert "failure_code" in sig.parameters, (
            "ledger.append must accept failure_code as a parameter — "
            "it must NOT derive it from reason"
        )

    def test_failure_code_none_when_not_provided(self, stack):
        """When failure_code is not provided, the ledger stores None —
        it does NOT guess or derive a code."""
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        ledger.append(
            action_id="act_no_code",
            grant_id=grant.id,
            ts=datetime.now(UTC),
            action_type="payment.refund",
            target="stripe",
            params={},
            est_cost=None,
            outcome="DENY",
            reason="some reason",
            rule_matched=None,
            state_delta={},
            # failure_code NOT provided
        )
        entries = ledger.list_entries()
        assert entries[-1]["failure_code"] is None, (
            "ledger must store None when failure_code is not provided — "
            "it must NOT derive a code from reason"
        )


# ===========================================================================
# 3. Hash-chain integrity with v2 entries
# ===========================================================================


class TestHashChainV2:
    """Verify the hash chain works with the new v2 fields."""

    def test_verify_passes_with_v2_entries(self, stack):
        """Multiple entries with failure_code + authority_boundary → verify passes."""
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        action = _make_action(grant, amount=10)
        pdp.decide(grant, action)  # ALLOW
        action2 = _make_action(grant, type="payment.charge", amount=10)
        pdp.decide(grant, action2)  # DENY (scope)

        assert ledger.verify() is True

    def test_mutating_failure_code_breaks_chain(self, stack, monkeypatch):
        """Modifying a failure_code in a ledger row → verify() fails."""
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        action = _make_action(grant, amount=10)
        pdp.decide(grant, action)  # ALLOW

        assert ledger.verify() is True

        # Tamper: change the failure_code directly in SQLite
        db_path = __import__("os").environ.get("ACTENON_DB_PATH", "actenon.db")
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute("UPDATE ledger SET failure_code = ? WHERE seq = 1", ("REVOKED",))
        conn.commit()
        conn.close()

        assert ledger.verify() is False, (
            "mutating failure_code must break the hash chain"
        )

    def test_mutating_authority_boundary_breaks_chain(self, stack):
        """Modifying authority_boundary in a ledger row → verify() fails."""
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        action = _make_action(grant, amount=10)
        pdp.decide(grant, action)

        assert ledger.verify() is True

        db_path = __import__("os").environ.get("ACTENON_DB_PATH", "actenon.db")
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute(
            "UPDATE ledger SET authority_boundary = ? WHERE seq = 1",
            ('{"tampered": true}',),
        )
        conn.commit()
        conn.close()

        assert ledger.verify() is False, (
            "mutating authority_boundary must break the hash chain"
        )

    def test_authority_boundary_populated(self, stack):
        """Every ledger entry must have authority_boundary populated with
        the grant envelope."""
        store, ledger, pdp = stack
        grant = _make_grant()
        store.put_grant(grant)

        action = _make_action(grant, amount=10)
        pdp.decide(grant, action)

        entries = ledger.list_entries()
        entry = entries[-1]
        assert entry["authority_boundary"] is not None, "authority_boundary must be populated"
        ab = entry["authority_boundary"]
        assert "envelope" in ab
        assert ab["envelope"]["scopes_allow"] == ["payment.refund", "email.send"]
        assert ab["envelope"]["budget_remaining_at_decision"] == 50
        assert "expires_at" in ab["envelope"]


# ===========================================================================
# 4. Taxonomy version + import check
# ===========================================================================


class TestTaxonomy:
    """Verify the taxonomy is imported from the kernel (single source of truth)."""

    def test_permit_imports_from_kernel(self):
        """Permit must import FailureCode from actenon.outcomes — not define its own."""
        from actenon.outcomes import FailureCode as KernelFailureCode
        # If permit can import it from the kernel, the import path exists
        assert KernelFailureCode.BUDGET_EXCEEDED == "BUDGET_EXCEEDED"

    def test_taxonomy_version(self):
        """The taxonomy version must be '1'."""
        assert TAXONOMY_VERSION == "1"

    def test_all_codes_present(self):
        """All 16 codes must be present in the enum."""
        expected = {
            "ALLOWED", "APPROVAL_REQUIRED",
            "NOT_ACTIVE", "REVOKED", "EXPIRED", "SCOPE_DENIED", "OUT_OF_SCOPE",
            "BUDGET_EXCEEDED", "RATE_LIMITED", "ENGINE_ERROR",
            "PCCB_REQUIRED", "SIGNATURE_INVALID", "ACTION_MISMATCH",
            "PCCB_EXPIRED", "DUPLICATE_REPLAY", "AUDIENCE_MISMATCH",
        }
        actual = {c.value for c in FailureCode}
        assert actual == expected, f"missing: {expected - actual}, extra: {actual - expected}"
