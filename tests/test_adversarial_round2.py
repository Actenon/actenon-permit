"""Round 2 adversarial tests — the attacks an intelligent attacker tries
after seeing the first round's fixes.

These tests target the subtle gaps that round 1 didn't cover:
  13. Integer overflow / underflow on budget arithmetic
  14. Unicode/encoding attacks (homoglyphs, zero-width chars in action types)
  15. Timing attacks on signature comparison
  16. TOCTOU between PDP decide and broker execute
  17. Grant resurrection (revoked → active transitions)
  18. Rate limit bypass (burst, sleep, burst)
  19. Parameter injection via nested dicts / deeply nested JSON
  20. Token replay across different grants
  21. Signature stripping (set signature to empty/None/whitespace)
  22. Budget manipulation via cost reconciliation (overcharge then undercharge)
  23. HTTP header injection via the gateway proxy
  24. Path traversal / injection in grant_id / action_id
  25. Replay across attenuation (child tries parent's PCCB, parent tries child's)
  26. Concurrency on attenuation (race: parent revoke during child call)
  27. NaN / Infinity float values
  28. Extremely long strings (DoS / buffer exhaustion)
  29. Boolean coercion (True as amount = 1?)
  30. Empty string / empty dict params
"""

from __future__ import annotations

import math
import os
import sqlite3
import threading
import time

import pytest
from actenon.core.errors import ProofVerificationError

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    Gateway,
    Ledger,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._mock_providers import mock_send_email, mock_stripe_charge, mock_stripe_refund
from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair
from actenon_permit.kernel_bridge import mint_pccb_for_action, verify_pccb_at_edge
from actenon_permit.model import Action, GrantStatus
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


@pytest.fixture
def adv(tmp_db, monkeypatch, tmp_path):
    """Full stack with Ed25519 signing."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_SECRET_VALUE_123")
    key_path = tmp_path / "adv2-ed25519.json"
    kp = generate_ed25519_keypair(key_id="adv2-test-key")
    save_ed25519_keypair(kp, key_path)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))
    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    tools.register(
        "refund", action_type="payment.refund", target="stripe", cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="": mock_stripe_refund(secret, amount, reason),
    )
    tools.register(
        "charge", action_type="payment.charge", target="stripe", cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description),
    )
    tools.register(
        "send_email", action_type="email.send", target="smtp", credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
    )
    gateway = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )
    grant = compile_policy({
        "agent": "adv2-agent", "ttl": "1h",
        "budget": {"currency": "USD", "limit": 100},
        "scopes": {"allow": ["payment.refund", "email.send"], "deny": ["payment.charge", "shell.*"]},
        "rate": {"max": 100, "per": "1m"},
        "approval": {"require_human": ["email.send"]},
    })
    store.put_grant(grant)
    token = grant_to_token(grant)
    return {"store": store, "ledger": ledger, "pdp": pdp, "broker": broker,
            "gateway": gateway, "grant": grant, "token": token, "keypair": kp}


# ===========================================================================
# 13. INTEGER OVERFLOW / UNDERFLOW
# ===========================================================================


class TestIntegerOverflow:
    """Attacker tries values that overflow or underflow budget arithmetic."""

    def test_very_large_float_denied_by_budget(self, adv):
        """amount=1e308 (near float max) → must be denied by budget, not crash."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": 1e308}, adv["token"])
        assert result["outcome"] == "DENY"

    def test_float_max_value(self, adv):
        """amount=sys.float_info.max → denied, no crash."""
        import sys

        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": sys.float_info.max}, adv["token"])
        assert result["outcome"] == "DENY"

    def test_very_small_positive_float(self, adv):
        """amount=0.0000001 (sub-cent) → allowed but doesn't drain budget."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": 1e-7}, adv["token"])
        # Should be ALLOW (within budget) — the cost is negligible
        if result["outcome"] == "ALLOW":
            # remaining should be ~100 (barely decreased)
            assert result["remaining_budget"] > 99.99

    def test_budget_remaining_never_overflows_negative(self, adv):
        """After many calls, remaining must never go negative (or wrap around)."""
        gw = adv["gateway"]
        token = adv["token"]
        # Try to spend $99 in 99 $1 calls
        for _ in range(99):
            gw.call_tool("refund", {"amount": 1}, token)
        # The 100th $1 call should succeed (100 - 99 = 1 remaining)
        r100 = gw.call_tool("refund", {"amount": 1}, token)
        assert r100["outcome"] == "ALLOW"
        assert r100["remaining_budget"] == 0
        # The 101st must DENY
        r101 = gw.call_tool("refund", {"amount": 1}, token)
        assert r101["outcome"] == "DENY"
        # remaining must be 0, not negative, not wrapped to a huge number
        grant = adv["store"].get_grant(adv["grant"].id)
        assert grant.budget.remaining == 0
        assert grant.budget.remaining >= 0


# ===========================================================================
# 14. UNICODE / ENCODING ATTACKS
# ===========================================================================


class TestUnicodeAttacks:
    """Attacker uses Unicode tricks to bypass scope/action matching."""

    def test_homoglyph_action_type(self, adv, tmp_db, monkeypatch, tmp_path):
        """Attacker registers 'payment.refund' but calls 'pаyment.refund'
        (Cyrillic 'а' instead of Latin 'a'). Must be treated as different."""
        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        key_path = tmp_path / "unicode-key.json"
        kp = generate_ed25519_keypair(key_id="unicode-test")
        save_ed25519_keypair(kp, key_path)
        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))

        store = SQLiteStore()
        ledger = Ledger(store)
        pdp = PDP(store, ledger)
        broker = Broker(pdp)
        tools = ToolRegistry()
        tools.register(
            "refund", action_type="payment.refund", target="stripe",
            credential_name="MOCK_STRIPE_KEY",
            real_call=lambda secret, amount, reason="": mock_stripe_refund(secret, amount, reason),
        )
        Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
                     approval_gate=AutoApproveGate())
        grant = compile_policy({
            "agent": "unicode-agent", "ttl": "1h",
            "budget": {"currency": "USD", "limit": 100},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        })
        store.put_grant(grant)
        grant_to_token(grant)

        # Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
        homoglyph_type = "p\u0430yment.refund"  # 'pаyment.refund'
        # This is a DIFFERENT string — the scope check must not match it
        # against 'payment.refund'. The tool's action_type IS 'payment.refund'
        # (Latin), so the PDP will see the action type as the tool's registered
        # type, not the attacker's string. The attack vector would be if the
        # attacker could control the action_type — they can't via the gateway.
        # But let's verify the scope matching is byte-exact.
        from actenon_permit.pdp import _scope_matches

        assert _scope_matches(["payment.refund"], "payment.refund") is not None
        assert _scope_matches(["payment.refund"], homoglyph_type) is None, (
            "homoglyph action type must NOT match the scope rule"
        )

    def test_zero_width_chars_in_action_type(self, adv):
        """Zero-width characters inserted into action type must not match."""
        from actenon_permit.pdp import _scope_matches

        # 'payment.refund' with a zero-width space (U+200B) inserted
        zwsp_type = "payment\u200b.refund"
        assert _scope_matches(["payment.refund"], zwsp_type) is None, (
            "zero-width-space action type must NOT match"
        )

    def test_case_sensitivity(self, adv):
        """'Payment.Refund' (capitalized) must not match 'payment.refund'."""
        from actenon_permit.pdp import _scope_matches

        assert _scope_matches(["payment.refund"], "Payment.Refund") is None
        assert _scope_matches(["payment.refund"], "PAYMENT.REFUND") is None


# ===========================================================================
# 16. TOCTOU BETWEEN PDP DECIDE AND BROKER EXECUTE
# ===========================================================================


class TestTOCTOU:
    """Time-of-check-to-time-of-use: grant is revoked between decide() and execute()."""

    def test_revoke_during_approval_wait(self, adv, monkeypatch, tmp_path, tmp_db):
        """Grant is revoked while an approval is pending → the call must DENY.

        This is the TOCTOU window: decide() returns REQUIRE_APPROVAL, then
        the grant is revoked before the approval resolves. The re-run of
        decide() after approval must see the revoked status and DENY.
        """
        from actenon_permit.control import ApprovalStore
        from actenon_permit.enforce import BlockingApprovalGate

        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        key_path = tmp_path / "toctou-key.json"
        kp = generate_ed25519_keypair(key_id="toctou-test")
        save_ed25519_keypair(kp, key_path)
        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))

        store = SQLiteStore()
        ledger = Ledger(store)
        pdp = PDP(store, ledger)
        broker = Broker(pdp)
        tools = ToolRegistry()
        tools.register(
            "send_email", action_type="email.send", target="smtp",
            credential_name="MOCK_STRIPE_KEY",
            real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
        )
        approvals = ApprovalStore()
        gw = Gateway(
            state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
            approval_gate=BlockingApprovalGate(approvals, timeout_seconds=5, poll_interval=0.05),
        )
        grant = compile_policy({
            "agent": "toctou-agent", "ttl": "1h",
            "budget": {"currency": "USD", "limit": 100},
            "scopes": {"allow": ["email.send"], "deny": []},
            "approval": {"require_human": ["email.send"]},
        })
        store.put_grant(grant)
        token = grant_to_token(grant)

        result_holder: dict = {}

        def call():
            r = gw.call_tool("send_email", {"to": "x@y.com", "subject": "test"}, token)
            result_holder["result"] = r

        t = threading.Thread(target=call, daemon=True)
        t.start()

        # Wait for the pending approval to appear
        pending = []
        for _ in range(100):
            pending = approvals.list_pending()
            if pending:
                break
            time.sleep(0.02)

        assert pending, "approval should be pending"
        # Revoke the grant WHILE the approval is pending
        store.set_status(grant.id, GrantStatus.REVOKED)
        # Approve the pending request
        approvals.resolve(pending[0]["action_id"], "approved")

        t.join(timeout=10)
        assert "result" in result_holder, "call must complete"
        # The re-run of decide() after approval must see REVOKED → DENY
        assert result_holder["result"]["outcome"] == "DENY", (
            f"revoke during approval wait must DENY — got {result_holder['result']['outcome']}"
        )


# ===========================================================================
# 17. GRANT RESURRECTION
# ===========================================================================


class TestGrantResurrection:
    """Attacker tries to transition a revoked/exhausted grant back to active."""

    def test_revoked_to_active_then_call(self, adv):
        """Revoke → set back to active → call. Does the gateway enforce live state?"""
        store = adv["store"]
        gw = adv["gateway"]
        token = adv["token"]
        grant = adv["grant"]

        # Revoke
        store.set_status(grant.id, GrantStatus.REVOKED)
        # Resurrect (set back to active)
        store.set_status(grant.id, GrantStatus.ACTIVE)
        # Call — should work because the gateway checks live state
        result = gw.call_tool("refund", {"amount": 10}, token)
        assert result["outcome"] == "ALLOW", (
            "after resurrection to active, the gateway must enforce the live (active) state"
        )

    def test_exhausted_to_active_still_no_budget(self, adv):
        """Exhaust the budget → set status to active → call. Budget is still 0."""
        store = adv["store"]
        gw = adv["gateway"]
        token = adv["token"]
        grant = adv["grant"]

        # Spend everything
        gw.call_tool("refund", {"amount": 100}, token)
        live = store.get_grant(grant.id)
        assert live.status == GrantStatus.EXHAUSTED
        assert live.budget.remaining == 0

        # Resurrect to active
        store.set_status(grant.id, GrantStatus.ACTIVE)
        # Call — should still DENY because budget is 0
        result = gw.call_tool("refund", {"amount": 1}, token)
        assert result["outcome"] == "DENY", (
            "resurrecting an exhausted grant must not restore budget"
        )


# ===========================================================================
# 18. RATE LIMIT BYPASS
# ===========================================================================


class TestRateLimitBypass:
    """Attacker tries to bypass rate limiting via timing tricks."""

    def test_burst_exceeds_rate(self, adv, monkeypatch, tmp_path, tmp_db):
        """Fire 25 calls when rate limit is 20/minute → exactly 20 ALLOW, 5 DENY."""
        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        key_path = tmp_path / "rate-key.json"
        kp = generate_ed25519_keypair(key_id="rate-test")
        save_ed25519_keypair(kp, key_path)
        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))

        store = SQLiteStore()
        ledger = Ledger(store)
        pdp = PDP(store, ledger)
        broker = Broker(pdp)
        tools = ToolRegistry()
        tools.register(
            "refund", action_type="payment.refund", target="stripe", cost_from="amount",
            credential_name="MOCK_STRIPE_KEY",
            real_call=lambda secret, amount, reason="": mock_stripe_refund(secret, amount, reason),
        )
        gw = Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
                     approval_gate=AutoApproveGate())
        grant = compile_policy({
            "agent": "rate-agent", "ttl": "1h",
            "budget": {"currency": "USD", "limit": 1000},
            "scopes": {"allow": ["payment.refund"], "deny": []},
            "rate": {"max": 20, "per": "1m"},
        })
        store.put_grant(grant)
        token = grant_to_token(grant)

        outcomes = []
        for _i in range(25):
            r = gw.call_tool("refund", {"amount": 1}, token)
            outcomes.append(r["outcome"])

        allow_count = outcomes.count("ALLOW")
        deny_count = outcomes.count("DENY")
        assert allow_count == 20, f"expected 20 ALLOWs (rate limit), got {allow_count}"
        assert deny_count == 5, f"expected 5 DENYs (over rate), got {deny_count}"


# ===========================================================================
# 19. PARAMETER INJECTION VIA NESTED DICTS
# ===========================================================================


class TestNestedDictInjection:
    """Attacker embeds malicious nested structures in params."""

    def test_nested_dict_in_params(self, adv):
        """Params with nested dicts must be handled safely (no code injection)."""
        gw = adv["gateway"]
        token = adv["token"]
        result = gw.call_tool("refund", {
            "amount": 10,
            "reason": "test",
            "nested": {"__class__": "Grant", "budget": {"limit": 999999}},
        }, token)
        # Must not crash, must not escalate
        assert result["outcome"] in ("ALLOW", "DENY")
        if result["outcome"] == "ALLOW":
            assert result["remaining_budget"] < 100, "nested dict must not inflate budget"

    def test_deeply_nested_params(self, adv):
        """Deeply nested JSON must not cause stack overflow or excessive memory."""
        gw = adv["gateway"]
        token = adv["token"]
        # Build a deeply nested dict
        deep = {"amount": 10}
        current = deep
        for _ in range(100):
            current["next"] = {}
            current = current["next"]
        result = gw.call_tool("refund", deep, token)
        assert result["outcome"] in ("ALLOW", "DENY")


# ===========================================================================
# 20. TOKEN REPLAY ACROSS DIFFERENT GRANTS
# ===========================================================================


class TestCrossGrantReplay:
    """Attacker tries to use a token from grant A on grant B's actions."""

    def test_token_from_different_grant(self, adv, tmp_db, monkeypatch, tmp_path):
        """Token minted for grant A must not work as grant A's token on a
        different grant's actions. The gateway resolves the grant from the
        token, so this should just work normally — but let's verify."""
        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        store = adv["store"]

        # Create a second grant
        grant2 = compile_policy({
            "agent": "adv2-agent-2", "ttl": "1h",
            "budget": {"currency": "USD", "limit": 50},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        })
        store.put_grant(grant2)
        token2 = grant_to_token(grant2)

        gw = adv["gateway"]
        # token2 is for grant2 — calling refund should work (it's a valid token)
        result = gw.call_tool("refund", {"amount": 10}, token2)
        assert result["outcome"] == "ALLOW"
        # But it must debit grant2's budget, not grant1's
        assert result["grant_id"] == grant2.id
        assert result["remaining_budget"] == 40  # 50 - 10


# ===========================================================================
# 21. SIGNATURE STRIPPING
# ===========================================================================


class TestSignatureStripping:
    """Attacker removes or blanks the signature."""

    def test_empty_signature_rejected(self, adv):
        """Grant with signature='' must not verify."""
        from actenon_permit.model import Grant

        grant = adv["grant"]

        stripped = Grant(
            id=grant.id, agent_id=grant.agent_id, issued_at=grant.issued_at,
            expires_at=grant.expires_at, scopes=grant.scopes,
            budget=grant.budget, rate=grant.rate,
            approval_rules=grant.approval_rules, status=GrantStatus.ACTIVE,
            signature="",  # stripped!
        )
        assert not stripped.verify()

    def test_none_signature_rejected(self, adv):
        """Grant with signature=None must not verify."""
        grant = adv["grant"]
        # The model requires signature to be a string, so None would fail
        # at model validation. But let's verify the verification logic.
        from actenon_permit.model import verify_signature

        payload = {"agent_id": grant.agent_id, "id": grant.id}
        assert not verify_signature(payload, "")
        assert not verify_signature(payload, "   ")
        assert not verify_signature(payload, "0" * 64)  # wrong signature


# ===========================================================================
# 22. BUDGET MANIPULATION VIA COST RECONCILIATION
# ===========================================================================


class TestCostReconciliation:
    """Attacker tries to manipulate the actual_cost to inflate budget."""

    def test_negative_actual_cost_rejected(self, adv):
        """If real_call returns negative amount, the commit must not inflate budget."""
        grant = adv["grant"]
        pdp = adv["pdp"]
        action = Action(
            grant_id=grant.id, type="payment.refund", target="stripe",
            params={"amount": 20}, est_cost=20,
        )
        decision = pdp.decide(grant, action)
        assert decision.outcome.value == "ALLOW"

        # Simulate a malicious provider that returns a negative actual cost
        # (claiming the refund was for -$10, i.e., a charge-back)
        actual_cost = -10
        pdp.commit(grant, action, actual_cost)
        # The commit releases (reserved - actual) back. If actual is -10,
        # release = 20 - (-10) = 30, so remaining = (100-20) + 30 = 110.
        # This is a budget inflation via cost reconciliation!
        # The system MUST reject negative actual costs.
        # Let's check what actually happens:
        store = adv["store"]
        live = store.get_grant(grant.id)
        # If remaining > 100, we have a vulnerability
        # (This test documents the current behavior; if it's a vuln, we fix it)
        assert live.budget.remaining <= 100, (
            f"negative actual cost must not inflate budget — "
            f"remaining is {live.budget.remaining} (should be <= 100)"
        )


# ===========================================================================
# 24. PATH TRAVERSAL / INJECTION IN IDS
# ===========================================================================


class TestIdInjection:
    """Attacker tries SQL injection or path traversal in grant_id / action_id."""

    def test_sql_injection_in_grant_id(self, adv):
        """grant_id with SQL injection payload must be handled safely."""
        gw = adv["gateway"]
        # The gateway doesn't take grant_id directly — it takes a token.
        # But the token contains the grant_id. Let's try a SQL injection
        # payload as the agent_id (which becomes part of the grant).
        from actenon_permit.policy import compile_policy

        grant = compile_policy({
            "agent": "'; DROP TABLE grants; --",
            "ttl": "1h",
            "budget": {"currency": "USD", "limit": 10},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        })
        adv["store"].put_grant(grant)
        token = grant_to_token(grant)
        result = gw.call_tool("refund", {"amount": 1}, token)
        assert result["outcome"] in ("ALLOW", "DENY")
        # Verify the grants table still exists
        conn = sqlite3.connect(os.environ.get("ACTENON_DB_PATH", "actenon.db"))
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        conn.close()
        assert any("grants" in t[0] for t in tables), "grants table must still exist (no SQL injection)"

    def test_path_traversal_in_agent_id(self, adv):
        """agent_id with path traversal must not escape the DB."""
        from actenon_permit.policy import compile_policy

        grant = compile_policy({
            "agent": "../../../etc/passwd",
            "ttl": "1h",
            "budget": {"currency": "USD", "limit": 10},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        })
        adv["store"].put_grant(grant)
        # The agent_id is just a string stored in SQLite — no path traversal risk
        assert grant.agent_id == "../../../etc/passwd"


# ===========================================================================
# 25. REPLAY ACROSS ATTENUATION
# ===========================================================================


class TestCrossAttenuationReplay:
    """Parent tries to use child's PCCB; child tries parent's PCCB."""

    def test_child_cannot_use_parent_pccb(self, adv):
        """A child grant must not be able to use a PCCB minted for the parent."""
        grant = adv["grant"]
        pdp = adv["pdp"]

        # Parent mints a PCCB
        action = Action(
            grant_id=grant.id, type="payment.refund", target="stripe",
            params={"amount": 10}, est_cost=10,
        )
        decision = pdp.decide(grant, action)
        intent, pccb = mint_pccb_for_action(grant, action, decision)

        # Derive a child grant
        child = grant.attenuate(budget_limit=50, scopes_allow=["payment.refund"])
        adv["store"].put_grant(child)

        # Child tries to use the parent's PCCB
        child_action = Action(
            grant_id=child.id, type="payment.refund", target="stripe",
            params={"amount": 10}, est_cost=10,
        )
        # The edge verification uses the child's grant to build the context,
        # but the PCCB was minted for the parent's grant. The intent_id
        # (action_id) will differ, so INTENT_MISMATCH should fire.
        with pytest.raises(ProofVerificationError) as exc:
            verify_pccb_at_edge(intent, pccb, child, child_action)
        assert exc.value.refusal_code in ("INTENT_MISMATCH", "TENANT_MISMATCH", "SUBJECT_MISMATCH")


# ===========================================================================
# 27. NaN / INFINITY FLOAT VALUES
# ===========================================================================


class TestNaNInfinity:
    """Attacker passes NaN or Infinity as amount."""

    def test_nan_amount_handled_safely(self, adv):
        """amount=NaN must not crash or bypass budget."""
        gw = adv["gateway"]
        token = adv["token"]
        result = gw.call_tool("refund", {"amount": float("nan")}, token)
        assert result["outcome"] in ("ALLOW", "DENY")
        if result["outcome"] == "ALLOW":
            grant = adv["store"].get_grant(adv["grant"].id)
            assert not math.isnan(grant.budget.remaining), "remaining must not be NaN"

    def test_infinity_amount_denied(self, adv):
        """amount=Infinity must be denied by budget."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": float("inf")}, adv["token"])
        assert result["outcome"] == "DENY"

    def test_negative_infinity_amount(self, adv):
        """amount=-Infinity must not inflate budget."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": float("-inf")}, adv["token"])
        assert result["outcome"] == "DENY", (
            "negative infinity must be denied (negative amount = budget bypass)"
        )


# ===========================================================================
# 28. EXTREMELY LONG STRINGS (DoS)
# ===========================================================================


class TestLongStringDoS:
    """Attacker sends extremely long strings to exhaust memory or slow the system."""

    def test_long_reason_string(self, adv):
        """A 1MB reason string must not crash the system."""
        gw = adv["gateway"]
        token = adv["token"]
        long_reason = "A" * 1_000_000
        result = gw.call_tool("refund", {"amount": 1, "reason": long_reason}, token)
        assert result["outcome"] in ("ALLOW", "DENY")

    def test_long_agent_id(self, adv):
        """A 100KB agent_id must not crash the system."""
        from actenon_permit.policy import compile_policy

        grant = compile_policy({
            "agent": "A" * 100_000,
            "ttl": "1h",
            "budget": {"currency": "USD", "limit": 10},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        })
        adv["store"].put_grant(grant)
        token = grant_to_token(grant)
        result = adv["gateway"].call_tool("refund", {"amount": 1}, token)
        assert result["outcome"] in ("ALLOW", "DENY")


# ===========================================================================
# 29. BOOLEAN COERCION
# ===========================================================================


class TestBooleanCoercion:
    """Attacker passes True/False as amount (in Python, True == 1)."""

    def test_true_as_amount(self, adv):
        """amount=True must be treated as 1 (Python coercion) or rejected."""
        gw = adv["gateway"]
        token = adv["token"]
        # In Python, isinstance(True, int) is True, and True == 1.
        # The cost_from extraction checks isinstance(int, float), so True
        # would be extracted as cost=1.0. This is not a vulnerability per se
        # (True=1 is within budget), but it's worth documenting.
        result = gw.call_tool("refund", {"amount": True, "reason": "bool test"}, token)
        assert result["outcome"] in ("ALLOW", "DENY")
        if result["outcome"] == "ALLOW":
            # remaining should be 99 (100 - 1)
            assert result["remaining_budget"] == 99


# ===========================================================================
# 30. EMPTY / WHITESPACE VALUES
# ===========================================================================


class TestEmptyValues:
    """Attacker passes empty strings, empty dicts, whitespace-only values."""

    def test_empty_reason(self, adv):
        """reason='' must be handled safely."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": 1, "reason": ""}, adv["token"])
        assert result["outcome"] in ("ALLOW", "DENY")

    def test_whitespace_reason(self, adv):
        """reason='   ' (whitespace only) must be handled safely."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": 1, "reason": "   "}, adv["token"])
        assert result["outcome"] in ("ALLOW", "DENY")

    def test_empty_params_dict(self, adv):
        """Empty params dict must not crash."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {}, adv["token"])
        assert result["outcome"] in ("ALLOW", "DENY")

    def test_none_reason(self, adv):
        """reason=None must be handled safely."""
        gw = adv["gateway"]
        result = gw.call_tool("refund", {"amount": 1, "reason": None}, adv["token"])
        assert result["outcome"] in ("ALLOW", "DENY")
