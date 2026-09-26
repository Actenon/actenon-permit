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


# ---------------------------------------------------------------------------
# Intent path (Actenon.local(), POST /intents/{id}/execute)
# ---------------------------------------------------------------------------


class _RefundAdapter:
    """Minimal brokered refund adapter (test mode, no network)."""

    provider_id = "test-refunds"
    test_mode = True

    def __init__(self):
        self.calls = []

    def supported_actions(self):
        return ["payment.refund"]

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        from actenon_permit.adapters import InvalidParametersError, ProviderResponse

        unknown = [k for k in params if k not in ("amount", "charge_id")]
        if unknown:
            raise InvalidParametersError(
                [{"field": k, "reason": "unsupported parameter"} for k in unknown],
                provider=self.provider_id,
            )
        self.calls.append(dict(params))
        ref = f"re_{len(self.calls)}"
        return ProviderResponse(
            ok=True,
            action=action,
            provider_action_id=ref,
            provider_evidence={"refund_id": ref, "amount": params.get("amount")},
        )


@pytest.fixture
def local_refunds(tmp_path, monkeypatch):
    import warnings

    from actenon_permit import Actenon

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("ACTENON_ED25519_KEY_FILE", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        client = Actenon.local(
            agent_id="audit-agent",
            scopes=["payment.refund"],
            budget_limit=10,
            signing_key="audit-signing-key",
            intent_store_path=str(tmp_path / "state.db"),
        )
        client.register_credential("STRIPE", "sk_test_AUDIT_SECRET")
    adapter = _RefundAdapter()
    client.register_adapter_tool(
        "refund", action_type="payment.refund", adapter=adapter, credential_ref="STRIPE"
    )
    return client, adapter


def _refund(client, **params):
    return client.authorised_execution_intents.create(
        action="payment.refund", target="stripe", parameters=params
    ).execute()


class TestIntentPath:
    def test_budget_is_enforced(self, local_refunds):
        from actenon_permit import ExecutionRefusedError

        client, adapter = local_refunds
        # Before the fix est_cost was hard-coded to 0 on this path: a $1000
        # refund against a $10 grant succeeded.
        with pytest.raises(ExecutionRefusedError):
            _refund(client, amount=1000, charge_id="ch_1")
        assert _refund(client, amount=4, charge_id="ch_2").state == "succeeded"
        assert _refund(client, amount=4, charge_id="ch_3").state == "succeeded"
        with pytest.raises(ExecutionRefusedError):
            _refund(client, amount=4, charge_id="ch_4")
        assert [c["charge_id"] for c in adapter.calls] == ["ch_2", "ch_3"]

    def test_non_numeric_amount_is_refused(self, local_refunds):
        from actenon_permit import ExecutionRefusedError

        client, adapter = local_refunds
        with pytest.raises(ExecutionRefusedError):
            _refund(client, amount="1000", charge_id="ch_1")
        assert adapter.calls == []

    def test_edge_verification_gates_the_broker(self, local_refunds, monkeypatch):
        """The minted PCCB must be verified before the credential is used."""
        from actenon.core.errors import ProofVerificationError

        from actenon_permit import ExecutionRefusedError, kernel_bridge

        def refuse(*args, **kwargs):
            raise ProofVerificationError("audit: forced", refusal_code="SIGNATURE_INVALID")

        monkeypatch.setattr(kernel_bridge, "verify_pccb_at_edge", refuse)
        client, adapter = local_refunds
        with pytest.raises(ExecutionRefusedError):
            _refund(client, amount=1, charge_id="ch_1")
        assert adapter.calls == []

    def test_refused_execution_does_not_burn_budget(self, local_refunds):
        from actenon_permit import ExecutionRefusedError

        client, adapter = local_refunds
        for _ in range(3):
            with pytest.raises(ExecutionRefusedError):
                _refund(client, amount=4, charge_id="ch_x", bogus="field")
        assert _refund(client, amount=9, charge_id="ch_ok").state == "succeeded"

    def test_success_carries_a_kernel_receipt(self, local_refunds, tmp_path):
        import json
        import subprocess
        import sys

        client, _ = local_refunds
        result = _refund(client, amount=3, charge_id="ch_r")
        assert result.state == "succeeded"
        assert result.receipt_received is True and result.receipt_verified is True
        assert result.receipt is not None and result.proof is not None
        assert result.receipt["correlation"]["pccb_id"] == result.proof["pccb"]["pccb_id"]
        assert "sk_test_AUDIT_SECRET" not in json.dumps([result.receipt, result.proof])
        for name, payload in (
            ("receipt", result.receipt),
            ("intent", result.proof["intent"]),
            ("pccb", result.proof["pccb"]),
        ):
            (tmp_path / f"{name}.json").write_text(json.dumps(payload))
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "actenon.cli",
                "verify-receipt",
                "--receipt",
                str(tmp_path / "receipt.json"),
                "--intent",
                str(tmp_path / "intent.json"),
                "--pccb",
                str(tmp_path / "pccb.json"),
            ],
            capture_output=True,
            text=True,
            cwd=tmp_path,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Boundary Kit: fail closed, and never report checks that did not run
# ---------------------------------------------------------------------------

_BOUNDARY_MANIFEST = {
    "version": "1.0.0",
    "metadata": {"service_name": "audit"},
    "trusted_issuers": [],
    "enforcement": {"mode": "enforce", "proof_header": "X-Actenon-Proof"},
    "boundaries": [
        {
            "id": "refund-api",
            "route": "POST /refunds",
            "action": "payment.refund",
            "target": {"type": "charge", "from": "body.charge_id"},
            "parameters": {"amount": {"from": "body.amount", "type": "integer"}},
            "execution_mode": "resource_owned",
            "audience": "service:payments",
            "proof": {"source": "header", "name": "X-Actenon-Proof"},
        }
    ],
}


class TestBoundaryKit:
    def test_middleware_without_kernel_boundary_verifier_fails_closed(self, monkeypatch):
        """With no actenon.boundary module (kernel 0.1.0, which CI was locked
        to), any token >= 16 chars was accepted as 'verified (structural)'."""
        import sys

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from actenon_permit.boundary import BoundaryManifest, BoundaryMiddleware

        monkeypatch.setitem(sys.modules, "actenon.boundary", None)
        calls = []
        app = FastAPI()

        @app.post("/refunds")
        def refund():
            calls.append(1)
            return {"ok": True}

        app.add_middleware(
            BoundaryMiddleware, manifest=BoundaryManifest.from_dict(_BOUNDARY_MANIFEST)
        )
        resp = TestClient(app).post(
            "/refunds", json={"amount": 5}, headers={"X-Actenon-Proof": "A" * 16}
        )
        assert resp.status_code == 403
        assert calls == []

    def test_protect_test_reports_what_actually_ran(self, tmp_path, monkeypatch):
        """`actenon protect test` printed ten hard-coded ✓ per boundary and
        wrote assurance PASS without sending a single request. Its verdict
        must now follow what the middleware actually does: a middleware
        that lets everything through must FAIL."""
        import json

        from starlette.middleware.base import BaseHTTPMiddleware
        from typer.testing import CliRunner

        from actenon_permit.boundary import middleware as mw
        from actenon_permit.unified_cli import app as cli

        monkeypatch.chdir(tmp_path)
        (tmp_path / "m.json").write_text(json.dumps(_BOUNDARY_MANIFEST))

        result = CliRunner().invoke(cli, ["protect", "test", "--manifest", "m.json"])
        report = json.loads((tmp_path / "actenon_boundary_report.json").read_text())
        assert result.exit_code == 0, result.output
        assert report["assurance"] == "PASS"
        assert {r["status"] for r in report["results"]} <= {"pass", "not_run"}
        assert report["tests_passed"] == sum(r["status"] == "pass" for r in report["results"])
        assert report["production_ready"] is False  # no issuer public_keys configured

        class FailOpen(BaseHTTPMiddleware):
            def __init__(self, app, **kwargs):
                super().__init__(app)

            async def dispatch(self, request, call_next):
                return await call_next(request)

        monkeypatch.setattr(mw, "BoundaryMiddleware", FailOpen)
        result = CliRunner().invoke(cli, ["protect", "test", "--manifest", "m.json"])
        report = json.loads((tmp_path / "actenon_boundary_report.json").read_text())
        assert result.exit_code == 1
        assert report["assurance"] == "FAIL"
        by_name = {r["name"]: r["status"] for r in report["results"]}
        assert by_name["forged proof refuses"] == "fail"
        assert by_name["no proof refuses"] == "fail"

    def test_middleware_binds_the_proof_to_the_request(self):
        """A genuine proof for amount=5 must not authorise amount=5000, and a
        proof from a key the manifest does not trust must not verify."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from actenon_permit.boundary import (
            BoundaryManifest,
            BoundaryMiddleware,
            mint_boundary_proof,
            proof_headers,
        )
        from actenon_permit.ed25519_signer import build_ed25519_signer, generate_ed25519_keypair

        issuer = generate_ed25519_keypair(key_id="issuer-1")
        manifest = dict(_BOUNDARY_MANIFEST)
        manifest["trusted_issuers"] = [{"issuer": "permit", "public_keys": [issuer.public_key_jwk]}]
        calls = []
        app = FastAPI()

        @app.post("/refunds")
        def refund():
            calls.append(1)
            return {"ok": True}

        app.add_middleware(BoundaryMiddleware, manifest=BoundaryManifest.from_dict(manifest))
        client = TestClient(app)

        def proof(signer, amount=5):
            return proof_headers(
                *mint_boundary_proof(
                    signer,
                    action="payment.refund",
                    target="ch_1",
                    parameters={"amount": amount},
                    audience="service:payments",
                )
            )

        signer = build_ed25519_signer(issuer)
        body = {"charge_id": "ch_1", "amount": 5000}
        assert client.post("/refunds", json=body, headers=proof(signer)).status_code == 403
        rogue = build_ed25519_signer(generate_ed25519_keypair(key_id="issuer-1"))
        assert (
            client.post("/refunds", json={**body, "amount": 5}, headers=proof(rogue)).status_code
            == 403
        )
        assert calls == []
        ok = client.post("/refunds", json={**body, "amount": 5}, headers=proof(signer))
        assert ok.status_code == 200 and calls == [1]

    def test_generated_integration_module_imports(self, tmp_path, monkeypatch):
        import importlib.util
        import json

        from fastapi import FastAPI
        from typer.testing import CliRunner

        from actenon_permit.unified_cli import app as cli

        monkeypatch.chdir(tmp_path)
        (tmp_path / "m.json").write_text(json.dumps(_BOUNDARY_MANIFEST))
        assert CliRunner().invoke(cli, ["protect", "apply", "--manifest", "m.json"]).exit_code == 0
        spec = importlib.util.spec_from_file_location(
            "actenon_boundary", tmp_path / "actenon_boundary.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # NameError: name 'app' is not defined, before the fix
        api = FastAPI()
        module.protect(api)
        assert any(m.cls.__name__ == "BoundaryMiddleware" for m in api.user_middleware)


class TestProofBoundParameters:
    def test_bridge_binds_exactly_the_action_params(self):
        """No synthetic "amount" may be added to what the PCCB binds."""
        from actenon_permit.kernel_bridge import _permit_action_to_kernel_intent

        grant = _grant()
        action = Action(grant_id=grant.id, type="payment.refund", params={"cost": 3}, est_cost=3.0)
        intent = _permit_action_to_kernel_intent(grant, action)
        assert dict(intent.action.parameters) == {"cost": 3}

    def test_adapter_tool_cost_from_is_priced(self, tmp_path, monkeypatch):
        import warnings

        from actenon_permit import Actenon, ExecutionRefusedError

        monkeypatch.setenv("HOME", str(tmp_path))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = Actenon.local(scopes=["payment.refund"], budget_limit=100, signing_key="k")
            client.register_credential("STRIPE", "sk_x")

        class MinorUnits(_RefundAdapter):
            def execute(self, action, params, credential, **kwargs):
                return super().execute(action, {"amount": params["amount_minor"]}, credential)

        client.register_adapter_tool(
            "refund",
            action_type="payment.refund",
            adapter=MinorUnits(),
            credential_ref="STRIPE",
            cost_from="amount_minor",
        )
        with pytest.raises(ExecutionRefusedError):
            client.authorised_execution_intents.create(
                action="payment.refund", target="stripe", parameters={"amount_minor": 99_999_999}
            ).execute()
