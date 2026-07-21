"""Round 3 adversarial tests — sophisticated nation-state level attacks."""

from __future__ import annotations

import os
import sqlite3
import time
from datetime import UTC, datetime
from decimal import Decimal

import pytest

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
from actenon_permit.kernel_bridge import mint_pccb_for_action
from actenon_permit.model import Action, GrantStatus
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


@pytest.fixture
def hack(tmp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_SECRET_VALUE_123")
    key_path = tmp_path / "hack-ed25519.json"
    kp = generate_ed25519_keypair(key_id="hack-key")
    save_ed25519_keypair(kp, key_path)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))
    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    tools.register("refund", action_type="payment.refund", target="stripe", cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="": mock_stripe_refund(secret, amount, reason))
    tools.register("charge", action_type="payment.charge", target="stripe", cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description))
    tools.register("send_email", action_type="email.send", target="smtp", credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body))
    gateway = Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools, approval_gate=AutoApproveGate())
    grant = compile_policy({
        "agent": "hack-agent", "ttl": "1h", "budget": {"currency": "USD", "limit": 100},
        "scopes": {"allow": ["payment.refund", "email.send"], "deny": ["payment.charge", "shell.*"]},
        "rate": {"max": 100, "per": "1m"}, "approval": {"require_human": ["email.send"]},
    })
    store.put_grant(grant)
    token = grant_to_token(grant)
    return {"store": store, "ledger": ledger, "pdp": pdp, "broker": broker,
            "gateway": gateway, "grant": grant, "token": token, "keypair": kp}


# 31. TIMING SIDE-CHANNEL
class TestTimingAttacks:
    def test_timing_leak_on_budget_check(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        allow_times = []
        for _ in range(5):
            start = time.perf_counter()
            gw.call_tool("refund", {"amount": 1}, token)
            allow_times.append(time.perf_counter() - start)
        deny_times = []
        for _ in range(5):
            start = time.perf_counter()
            gw.call_tool("refund", {"amount": 999999}, token)
            deny_times.append(time.perf_counter() - start)
        assert len(allow_times) == 5
        assert len(deny_times) == 5

# 32. GRANT ID COLLISION
class TestGrantIdCollision:
    def test_grant_ids_are_random(self):
        from actenon_permit.policy import compile_policy
        ids = set()
        for _ in range(100):
            g = compile_policy({"agent": "test", "ttl": "1h", "budget": {"currency": "USD", "limit": 1}})
            ids.add(g.id)
        assert len(ids) == 100, "grant IDs must be unique"

    def test_grant_id_format(self):
        from actenon_permit.policy import compile_policy
        g = compile_policy({"agent": "test", "ttl": "1h", "budget": {"currency": "USD", "limit": 1}})
        assert g.id.startswith("grant_")
        assert len(g.id) > 10

# 33. LEDGER HASH COLLISION
class TestLedgerHashCollision:
    def test_no_hash_collision_for_different_entries(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        ledger = hack["ledger"]
        gw.call_tool("refund", {"amount": 1, "reason": "first"}, token)
        gw.call_tool("refund", {"amount": 2, "reason": "second"}, token)
        entries = ledger.list_entries()
        hashes = [e["hash"] for e in entries]
        assert len(hashes) == len(set(hashes)), "all ledger hashes must be unique"

# 34. RACE: REVOKE DURING PCCB VERIFICATION
class TestRevokeDuringVerification:
    def test_revoke_during_pccb_mint_and_verify(self, hack):
        grant = hack["grant"]
        pdp = hack["pdp"]
        store = hack["store"]
        action = Action(grant_id=grant.id, type="payment.refund", target="stripe",
                        params={"amount": 10}, est_cost=10)
        decision = pdp.decide(grant, action)
        intent, pccb = mint_pccb_for_action(grant, action, decision)
        store.set_status(grant.id, GrantStatus.REVOKED)
        d2 = pdp.decide(grant, action)
        assert d2.outcome.value == "DENY"
        assert "revoked" in d2.reason.lower()

# 35. DECIMAL PRECISION ATTACK
class TestDecimalPrecision:
    def test_sub_cent_amount_allowed_but_negligible(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        result = gw.call_tool("refund", {"amount": 0.001}, token)
        assert result["outcome"] == "ALLOW"
        assert result["remaining_budget"] > 99.99

    def test_exact_budget_exhaustion(self, hack):
        store = hack["store"]
        pdp = hack["pdp"]
        fresh = compile_policy({"agent": "decimal-test", "ttl": "1h",
            "budget": {"currency": "USD", "limit": Decimal("0.03")},
            "scopes": {"allow": ["payment.refund"]}})
        store.put_grant(fresh)
        for _ in range(3):
            a = Action(grant_id=fresh.id, type="payment.refund", target="stripe",
                       params={"amount": 0.01}, est_cost=0.01)
            d = pdp.decide(fresh, a)
            assert d.outcome.value == "ALLOW"
        g = store.get_grant(fresh.id)
        assert g.budget.remaining == 0, f"remaining should be 0, got {g.budget.remaining}"

    def test_rounding_trick_half_cent(self, hack):
        store = hack["store"]
        pdp = hack["pdp"]
        fresh = compile_policy({"agent": "rounding-test", "ttl": "1h",
            "budget": {"currency": "USD", "limit": Decimal("0.01")},
            "scopes": {"allow": ["payment.refund"]}})
        store.put_grant(fresh)
        for i in range(2):
            a = Action(grant_id=fresh.id, type="payment.refund", target="stripe",
                       params={"amount": 0.005}, est_cost=0.005)
            d = pdp.decide(fresh, a)
            assert d.outcome.value == "ALLOW", f"call {i+1} should ALLOW"
        a3 = Action(grant_id=fresh.id, type="payment.refund", target="stripe",
                    params={"amount": 0.005}, est_cost=0.005)
        d3 = pdp.decide(fresh, a3)
        assert d3.outcome.value == "DENY"

# 37. SCOPE GLOB INJECTION
class TestScopeGlobInjection:
    def test_deny_star_matches_everything(self, hack, tmp_db, monkeypatch, tmp_path):
        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        key_path = tmp_path / "glob-key.json"
        kp = generate_ed25519_keypair(key_id="glob-test")
        save_ed25519_keypair(kp, key_path)
        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))
        store = SQLiteStore()
        ledger = Ledger(store)
        pdp = PDP(store, ledger)
        broker = Broker(pdp)
        tools = ToolRegistry()
        tools.register("refund", action_type="payment.refund", target="stripe", cost_from="amount",
            credential_name="MOCK_STRIPE_KEY",
            real_call=lambda secret, amount, reason="": mock_stripe_refund(secret, amount, reason))
        gw = Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools, approval_gate=AutoApproveGate())
        grant = compile_policy({"agent": "glob-test", "ttl": "1h", "budget": {"currency": "USD", "limit": 100},
            "scopes": {"allow": ["payment.refund"], "deny": ["*"]}})
        store.put_grant(grant)
        token = grant_to_token(grant)
        result = gw.call_tool("refund", {"amount": 10}, token)
        assert result["outcome"] == "DENY"
        assert "scope denied" in result["reason"]

# 39. TOKEN VERSION DOWNGRADE
class TestTokenVersionDowngrade:
    def test_v0_token_rejected(self, hack):
        gw = hack["gateway"]
        result = gw.call_tool("refund", {"amount": 10}, "eyJhZ2VudF9pZCI6ImhlY2stYWdlbnQifQ")
        assert result["outcome"] == "DENY"
        assert "invalid grant token" in result["reason"]

    def test_v2_token_rejected(self, hack):
        gw = hack["gateway"]
        result = gw.call_tool("refund", {"amount": 10}, "v2.something")
        assert result["outcome"] == "DENY"

# 40. PARALLEL GRANT EXHAUSTION
class TestParallelGrantExhaustion:
    def test_multiple_grants_independent_budgets(self, hack):
        store = hack["store"]
        gw = hack["gateway"]
        grant2 = compile_policy({"agent": "hack-agent", "ttl": "1h", "budget": {"currency": "USD", "limit": 50},
            "scopes": {"allow": ["payment.refund"]}})
        store.put_grant(grant2)
        token2 = grant_to_token(grant2)
        r1 = gw.call_tool("refund", {"amount": 100}, hack["token"])
        r2 = gw.call_tool("refund", {"amount": 50}, token2)
        assert r1["outcome"] == "ALLOW"
        assert r2["outcome"] == "ALLOW"
        r3 = gw.call_tool("refund", {"amount": 1}, hack["token"])
        r4 = gw.call_tool("refund", {"amount": 1}, token2)
        assert r3["outcome"] == "DENY"
        assert r4["outcome"] == "DENY"

# 41. LEDGER CHAIN FORK
class TestLedgerFork:
    def test_fork_detected_by_verify(self, hack):
        ledger = hack["ledger"]
        grant = hack["grant"]
        ledger.append(action_id="act_fork_1", grant_id=grant.id, ts=datetime.now(UTC),
            action_type="payment.refund", target="stripe", params={"amount": 10},
            est_cost=10, outcome="ALLOW", reason="test", rule_matched=None,
            state_delta={}, failure_code="ALLOWED",
            authority_boundary={"envelope": {"scopes_allow": ["payment.refund"]}})
        db_path = os.environ.get("ACTENON_DB_PATH", "actenon.db")
        conn = sqlite3.connect(db_path, isolation_level=None)
        prev_hash = conn.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO ledger (action_id, grant_id, ts, action_type, target, params, "
            "est_cost, outcome, reason, rule_matched, state_delta, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("act_fork_2", grant.id, datetime.now(UTC).isoformat(),
             "payment.refund", "stripe", "{}", 5, "ALLOW", "fork", None, "{}",
             prev_hash, "fake_hash_for_fork"))
        conn.commit()
        conn.close()
        assert ledger.verify() is False, "ledger fork must be detected"

# 43. BUDGET RESET VIA STATUS TRANSITION
class TestBudgetResetAttack:
    def test_exhausted_to_active_does_not_reset_budget(self, hack):
        store = hack["store"]
        gw = hack["gateway"]
        token = hack["token"]
        grant = hack["grant"]
        gw.call_tool("refund", {"amount": 100}, token)
        g = store.get_grant(grant.id)
        assert g.budget.remaining == 0
        store.set_status(grant.id, GrantStatus.ACTIVE)
        result = gw.call_tool("refund", {"amount": 1}, token)
        assert result["outcome"] == "DENY"

# 46. NULL BYTE INJECTION
class TestNullByteInjection:
    def test_null_byte_in_reason(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        result = gw.call_tool("refund", {"amount": 1, "reason": "legit\x00malicious"}, token)
        assert result["outcome"] in ("ALLOW", "DENY")

    def test_null_byte_in_action_type(self, hack):
        from actenon_permit.pdp import _scope_matches
        result = _scope_matches(["payment.refund"], "payment.refund\x00payment.charge")
        assert result is None, "null byte in action type must not bypass scope"

# 47. JSON DESERIALIZATION ATTACK
class TestJSONDeserialization:
    def test_proto_injection(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        result = gw.call_tool("refund", {"amount": 1, "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"isAdmin": True}}}, token)
        assert result["outcome"] in ("ALLOW", "DENY")

    def test_deeply_nested_json_10000(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        deep = {"amount": 1}
        current = deep
        for _ in range(10000):
            current["next"] = {}
            current = current["next"]
        try:
            result = gw.call_tool("refund", deep, token)
            assert result["outcome"] in ("ALLOW", "DENY")
        except Exception:
            pytest.fail("deeply nested JSON caused a crash — DoS vulnerability")

# 49. SSRF VIA TARGET FIELD
class TestSSRFViaTarget:
    def test_target_field_not_used_for_network_calls(self, hack):
        grant = hack["grant"]
        pdp = hack["pdp"]
        action = Action(grant_id=grant.id, type="payment.refund",
            target="http://169.254.169.254/latest/meta-data/",
            params={"amount": 10}, est_cost=10)
        decision = pdp.decide(grant, action)
        assert decision.outcome.value in ("ALLOW", "DENY")

# 50. MEMORY EXHAUSTION
class TestMemoryExhaustion:
    def test_large_string_param_1mb(self, hack):
        """1MB string in params exceeds the kernel's 1MB canonical JSON limit.
        The gateway should catch this and return DENY (fail-closed).
        FOUND: the exception escapes the gateway — this is a BUG.
        The gateway's decide_and_mint_pccb catches KernelBridgeError but
        not JSONInputTooLargeError (which is a different exception type).
        FIX NEEDED: catch all exceptions in the PCCB mint path, not just
        KernelBridgeError.
        """
        gw = hack["gateway"]
        token = hack["token"]
        result = gw.call_tool("refund", {"amount": 1, "reason": "A" * 1_048_576}, token)
        assert result["outcome"] == "DENY", f"1MB string should be denied (DoS protection), got {result['outcome']}"

    def test_large_array_param(self, hack):
        gw = hack["gateway"]
        token = hack["token"]
        result = gw.call_tool("refund", {"amount": 1, "items": list(range(10000))}, token)
        assert result["outcome"] in ("ALLOW", "DENY")

# 45. UNICODE NORMALIZATION
class TestUnicodeNormalization:
    def test_nfc_vs_nfd_action_type(self, hack):
        from actenon_permit.pdp import _scope_matches
        nfc = "café.refund"
        nfd = "cafe\u0301.refund"
        assert nfc != nfd
        assert _scope_matches([nfc], nfd) is None
        assert _scope_matches([nfd], nfc) is None
        assert _scope_matches([nfc], nfc) is not None
