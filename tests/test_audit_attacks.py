"""Adversarial regression tests from the 2026-09 ecosystem audit.

Each test is an attack that SUCCEEDED against main before the matching fix.
A test passes when the attack is blocked (fail closed).
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta

import pytest

from actenon_permit import PDP, Ledger, SQLiteStore
from actenon_permit.model import Action, Budget, DecisionOutcome, Grant, Rate, Scopes


def _grant(**overrides) -> Grant:
    fields = {
        "agent_id": "audit-agent",
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
        "scopes": Scopes(allow=["payment.refund"], deny=["shell.*"]),
        "budget": Budget(currency="USD", limit=50, remaining=50),
        "rate": Rate(max=5, per_seconds=60),
    }
    fields.update(overrides)
    return Grant(**fields).sign()


@pytest.fixture
def stack(tmp_db):
    store = SQLiteStore()
    ledger = Ledger(store)
    return store, PDP(store, ledger)


# ---------------------------------------------------------------------------
# Attenuation must never widen (SPEC §6: "strictly weaker on every dimension")
# ---------------------------------------------------------------------------


class TestAttenuationCannotWiden:
    def test_empty_allow_list_is_not_a_subset(self, stack):
        """scopes_allow=[] means "allow everything not denied" (SPEC §4), so
        an empty child allow-list of a scoped parent is a widening."""
        store, pdp = stack
        parent = _grant()
        with pytest.raises(ValueError):
            child = parent.attenuate(scopes_allow=[])
            # Before the fix the child was accepted and could do anything:
            store.put_grant(child)
            action = Action(
                grant_id=child.id, type="payment.charge", params={"amount": 5}, est_cost=5
            )
            assert pdp.decide(child, action).outcome != DecisionOutcome.ALLOW

    def test_rate_max_zero_does_not_remove_rate_limit(self):
        """rate.max=0 disables rate limiting (SPEC §2), so it is the widest
        possible value, not the narrowest."""
        parent = _grant(rate=Rate(max=5, per_seconds=60))
        with pytest.raises(ValueError):
            parent.attenuate(rate_max=0)

    def test_negative_rate_max_rejected(self):
        parent = _grant(rate=Rate(max=5, per_seconds=60))
        with pytest.raises(ValueError):
            parent.attenuate(rate_max=-1)

    def test_legitimate_narrowing_still_allowed(self):
        parent = _grant(scopes=Scopes(allow=["payment.refund", "email.send"], deny=[]))
        child = parent.attenuate(scopes_allow=["payment.refund"], rate_max=2, budget_limit=10)
        assert child.scopes.allow == ["payment.refund"]
        assert child.rate.max == 2
        assert child.verify()

    def test_unlimited_parent_may_add_a_rate_limit(self):
        parent = _grant(rate=Rate(max=0, per_seconds=60))
        child = parent.attenuate(rate_max=3)
        assert child.rate.max == 3


# ---------------------------------------------------------------------------
# Revocation must reach every descendant of a revoked grant
# ---------------------------------------------------------------------------


def _gateway_with_refund_tool(store):
    from actenon_permit import AutoApproveGate, Broker, Gateway, ToolRegistry
    from actenon_permit._mock_providers import mock_stripe_refund

    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    tools = ToolRegistry()
    tools.register(
        "refund",
        action_type="payment.refund",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="r": mock_stripe_refund(secret, amount, reason),
    )
    gw = Gateway(
        state=store,
        ledger=ledger,
        pdp=pdp,
        broker=Broker(pdp),
        tools=tools,
        approval_gate=AutoApproveGate(),
    )
    return gw, ledger, pdp


class TestRevocationCascade:
    def test_http_revoke_reaches_grandchildren(self, tmp_db):
        from fastapi.testclient import TestClient

        from actenon_permit.control import create_app
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, ledger, pdp = _gateway_with_refund_tool(store)
        client = TestClient(
            create_app(
                state=store, ledger=ledger, pdp=pdp, gateway=gw, wire_gateway_approvals=False
            )
        )
        root = _grant(budget=Budget(currency="USD", limit=100, remaining=100))
        store.put_grant(root)
        child = client.post(f"/grants/{root.id}/attenuate", json={"budget_limit": 50}).json()
        grandchild = client.post(
            f"/grants/{child['id']}/attenuate", json={"budget_limit": 20}
        ).json()
        gc_token = grant_to_token(store.get_grant(grandchild["id"]))
        assert gw.call_tool("refund", {"amount": 1}, gc_token)["outcome"] == "ALLOW"

        assert client.post(f"/grants/{root.id}/revoke").status_code == 200

        result = gw.call_tool("refund", {"amount": 1}, gc_token)
        assert result["outcome"] == "DENY", result
        assert store.get_grant(grandchild["id"]).status.value == "revoked"

    def test_kill_switch_by_agent_reaches_delegated_children(self, tmp_db):
        """`permit revoke <agent>` only flips the agent's own grants; a child
        attenuated to another agent id must still stop working."""
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        root = _grant()
        store.put_grant(root)
        child = root.attenuate(agent_id="sub-agent", budget_limit=10)
        store.put_grant(child)
        token = grant_to_token(child)
        assert gw.call_tool("refund", {"amount": 1}, token)["outcome"] == "ALLOW"

        from actenon_permit.model import GrantStatus

        store.set_status(root.id, GrantStatus.REVOKED)  # what `permit revoke` does

        result = gw.call_tool("refund", {"amount": 1}, token)
        assert result["outcome"] == "DENY", result


# ---------------------------------------------------------------------------
# A cost field that is not a plain number must not reserve $0
# ---------------------------------------------------------------------------


class TestCostTypeConfusion:
    @pytest.mark.parametrize("amount", ["40", "4e1", None, [40], {"value": 40}, True])
    def test_gateway_non_numeric_amount_is_refused(self, tmp_db, amount):
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        token = grant_to_token(grant)
        result = gw.call_tool("refund", {"amount": amount}, token)
        assert result["outcome"] == "DENY", result
        assert store.get_grant(grant.id).budget.remaining == 50

    def test_gateway_string_amounts_cannot_exceed_budget(self, tmp_db):
        """Before the fix: three $40 refunds against a $50 budget, all
        ALLOWed, budget still $50."""
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        token = grant_to_token(grant)
        outcomes = [gw.call_tool("refund", {"amount": "40"}, token)["outcome"] for _ in range(3)]
        assert outcomes.count("ALLOW") == 0, outcomes

    @pytest.mark.parametrize("amount", [float("nan"), float("inf")])
    def test_gateway_non_finite_amount_is_refused(self, tmp_db, amount):
        from actenon_permit.token import grant_to_token

        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        result = gw.call_tool("refund", {"amount": amount}, grant_to_token(grant))
        assert result["outcome"] == "DENY", result

    def test_guard_decimal_amount_is_charged_not_ignored(self, tmp_db, monkeypatch):
        from decimal import Decimal

        from actenon_permit import Broker
        from actenon_permit.enforce import GuardRegistry, guard

        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        store = SQLiteStore()
        pdp = PDP(store, Ledger(store))
        reg = GuardRegistry(store, pdp, Broker(pdp))
        grant = _grant()
        store.put_grant(grant)
        reg.set_grant(grant.id)
        paid = []

        @guard(
            "payment.refund", cost_from="amount", credential_name="MOCK_STRIPE_KEY", registry=reg
        )
        def refund(secret, amount):
            paid.append(amount)
            return {"status": "ok"}

        from actenon_permit.pdp import PermitDenied

        for _ in range(3):
            with contextlib.suppress(PermitDenied):
                refund(amount=Decimal("40"))
        assert sum(paid) <= 50, paid

    def test_guard_string_amount_is_refused(self, tmp_db, monkeypatch):
        from actenon_permit import Broker
        from actenon_permit.enforce import GuardRegistry, guard
        from actenon_permit.pdp import PermitDenied

        monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
        store = SQLiteStore()
        pdp = PDP(store, Ledger(store))
        reg = GuardRegistry(store, pdp, Broker(pdp))
        grant = _grant()
        store.put_grant(grant)
        reg.set_grant(grant.id)

        @guard(
            "payment.refund", cost_from="amount", credential_name="MOCK_STRIPE_KEY", registry=reg
        )
        def refund(secret, amount):
            return {"status": "ok"}

        with pytest.raises(PermitDenied):
            refund(amount="40")


# ---------------------------------------------------------------------------
# A threshold approval rule must not be skipped for an unreadable amount
# ---------------------------------------------------------------------------


class TestApprovalThresholdFailClosed:
    @pytest.mark.parametrize("amount", [float("nan"), "NaN", "abc", [5000]])
    def test_unreadable_amount_requires_approval(self, stack, amount):
        """`payment.refund > 20` compared float(amount) > 20; NaN compares
        False and a parse error returned False, so the rule was skipped and
        the action ALLOWed without the human."""
        store, pdp = stack
        grant = _grant(approval_rules=["payment.refund > 20"])
        store.put_grant(grant)
        action = Action(grant_id=grant.id, type="payment.refund", params={"amount": amount})
        assert pdp.decide(grant, action).outcome == DecisionOutcome.REQUIRE_APPROVAL

    def test_numeric_amounts_still_compare(self, stack):
        store, pdp = stack
        grant = _grant(approval_rules=["payment.refund > 20"])
        store.put_grant(grant)
        small = Action(grant_id=grant.id, type="payment.refund", params={"amount": 5}, est_cost=5)
        big = Action(grant_id=grant.id, type="payment.refund", params={"amount": 25}, est_cost=25)
        assert pdp.decide(grant, small).outcome == DecisionOutcome.ALLOW
        assert pdp.decide(grant, big).outcome == DecisionOutcome.REQUIRE_APPROVAL


# ---------------------------------------------------------------------------
# The broker's own redaction pass must actually run
# ---------------------------------------------------------------------------


class _LeakyAdapter:
    """An adapter whose redact() misses the credential (the case the
    broker's defensive pass exists for)."""

    provider_id = "leaky"
    test_mode = True

    def supported_actions(self):
        return ["leaky.echo"]

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        from actenon_permit.adapters import ProviderResponse

        return ProviderResponse(
            ok=True,
            action=action,
            provider_action_id="x1",
            provider_evidence={
                "debug": f"Authorization: Bearer {credential.value}",
                "nested": {"token": credential.value},
            },
            raw={"request_headers": {"Authorization": credential.value}},
        )


class TestBrokerRedaction:
    def test_broker_scrubs_credential_the_adapter_leaked(self, stack):
        from actenon_permit import Broker, CredentialProviderRegistry, LocalDevSecretProvider

        store, pdp = stack
        secret = "ghp_AUDIT_SECRET_0123456789"
        registry = CredentialProviderRegistry()
        registry.register("TOKEN", LocalDevSecretProvider({"TOKEN": secret}))
        broker = Broker(pdp, credential_providers=registry)
        grant = _grant(scopes=Scopes(allow=["leaky.echo"], deny=[]))
        store.put_grant(grant)
        action = Action(grant_id=grant.id, type="leaky.echo", params={})
        decision = pdp.decide(grant, action)
        assert decision.outcome == DecisionOutcome.ALLOW

        response, _ = broker.execute_via_adapter(
            grant, action, decision, _LeakyAdapter(), credential_ref="TOKEN"
        )

        assert secret not in repr(response.provider_evidence)
        assert response.raw is None

    def test_broker_scrubs_credential_from_adapter_error_text(self, stack):
        from actenon_permit import Broker, CredentialProviderRegistry, LocalDevSecretProvider
        from actenon_permit.adapters import AdapterError
        from actenon_permit.broker import BrokerExecutionError

        class _LeakyErrorAdapter(_LeakyAdapter):
            def execute(self, action, params, credential, **kwargs):
                raise AdapterError(f"401 for token {credential.value}", provider="leaky")

        store, pdp = stack
        secret = "ghp_AUDIT_SECRET_0123456789"
        registry = CredentialProviderRegistry()
        registry.register("TOKEN", LocalDevSecretProvider({"TOKEN": secret}))
        broker = Broker(pdp, credential_providers=registry)
        grant = _grant(scopes=Scopes(allow=["leaky.echo"], deny=[]))
        store.put_grant(grant)
        action = Action(grant_id=grant.id, type="leaky.echo", params={})
        decision = pdp.decide(grant, action)
        with pytest.raises(BrokerExecutionError) as exc:
            broker.execute_via_adapter(
                grant, action, decision, _LeakyErrorAdapter(), credential_ref="TOKEN"
            )
        assert secret not in str(exc.value)


# ---------------------------------------------------------------------------
# A configured Ed25519 key that cannot be loaded must not silently become HMAC
# ---------------------------------------------------------------------------


class TestSignerDowngrade:
    def test_corrupt_configured_key_file_fails_closed(self, tmp_path, monkeypatch):
        from actenon_permit.ed25519_signer import Ed25519KeyError, resolve_signer

        bad = tmp_path / "ed25519.json"
        bad.write_text("{not json")
        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(bad))
        monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)
        # Before the fix: an HmacSha256Signer keyed with the kernel's
        # *public* default local secret.
        with pytest.raises(Ed25519KeyError):
            resolve_signer()

    def test_missing_configured_key_file_fails_closed(self, tmp_path, monkeypatch):
        from actenon_permit.ed25519_signer import Ed25519KeyError, resolve_signer

        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(tmp_path / "nope.json"))
        with pytest.raises(Ed25519KeyError):
            resolve_signer()

    def test_corrupt_key_file_denies_at_the_gateway(self, tmp_db, tmp_path, monkeypatch):
        from actenon_permit.token import grant_to_token

        bad = tmp_path / "ed25519.json"
        bad.write_text('{"algorithm": "EdDSA", "private_key": "AAAA"}')
        monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(bad))
        store = SQLiteStore()
        gw, _, _ = _gateway_with_refund_tool(store)
        grant = _grant()
        store.put_grant(grant)
        result = gw.call_tool("refund", {"amount": 1}, grant_to_token(grant))
        assert result["outcome"] == "DENY", result

    def test_no_key_configured_still_uses_hmac(self, tmp_path, monkeypatch):
        from actenon_permit.ed25519_signer import resolve_signer

        monkeypatch.delenv("ACTENON_ED25519_KEY_FILE", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert resolve_signer(hmac_secret="k").algorithm == "HS256"


# ---------------------------------------------------------------------------
# GitHub adapter: owner/repo are path segments, not URL fragments
# ---------------------------------------------------------------------------


class TestGitHubPathInjection:
    @pytest.mark.parametrize(
        ("owner", "repo"),
        [
            ("Actenon", "example/issues/7/comments#"),  # issue.create -> comment
            ("Actenon", "example/issues/7/comments?x="),
            ("Actenon/example/issues/7/comments#", "x"),
            ("Actenon", ".."),
            ("..", "example"),
            ("Actenon", "exa mple"),
            ("Actenon", ""),
        ],
    )
    def test_path_breaking_owner_or_repo_is_rejected(self, owner, repo):
        from actenon_permit.adapters import InvalidParametersError
        from actenon_permit.adapters.github import GitHubAdapter
        from actenon_permit.credentials import Credential

        adapter = GitHubAdapter(test_mode=False, api_base="https://github.invalid")
        sent = []
        adapter._http_send = lambda req, timeout: sent.append(req.selector) or {}
        cred = Credential(ref="GH", value="ghp_x", source="local")
        with pytest.raises(InvalidParametersError):
            adapter.execute(
                "github.issue.create",
                {"owner": owner, "repo": repo, "title": "t", "body": "b"},
                cred,
            )
        assert sent == [], f"request was sent to {sent}"

    def test_valid_names_still_accepted(self):
        from actenon_permit.adapters.github import GitHubAdapter
        from actenon_permit.credentials import Credential

        adapter = GitHubAdapter(test_mode=False, api_base="https://github.invalid")
        sent = []
        adapter._http_send = lambda req, timeout: (
            sent.append(req.selector)
            or {
                "number": 1,
                "html_url": "https://github.com/a/b/issues/1",
                "node_id": "n",
            }
        )
        adapter.reconcile = lambda action, params, response: response
        cred = Credential(ref="GH", value="ghp_x", source="local")
        adapter.execute(
            "github.issue.create",
            {"owner": "Actenon-Org", "repo": "my_repo.v2", "title": "t"},
            cred,
        )
        assert sent == ["/repos/Actenon-Org/my_repo.v2/issues"]
