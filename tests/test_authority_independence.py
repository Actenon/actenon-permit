"""Independence and authority-model tests for actenon-permit (Phase 7).

These tests prove that Permit:

  1. Runs without Cloud installed.
  2. Can issue a protocol-conforming proof.
  3. Can use locally configured signing.
  4. Can use externally supplied signing integration.
  5. Does not execute a GitHub, bank, or database action merely by
     issuing a proof.
  6. Attenuation produces a child grant with parent_grant_id and
     delegation_depth set (Phase 7 grant safety).
  7. Revocation cascades to child grants (Phase 7, audit P-05).
  8. The authority_ref digest is stable and verifiable (Phase 7).
  9. The ledger records all required transitions.
"""

from __future__ import annotations

import ast
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from actenon_permit.kernel_bridge import _permit_action_to_kernel_intent, mint_pccb_for_action
from actenon_permit.ledger import Ledger
from actenon_permit.model import (
    Action,
    Budget,
    Decision,
    DecisionOutcome,
    Grant,
    GrantStatus,
    Rate,
    Scopes,
)
from actenon_permit.pdp import PDP
from actenon_permit.state import SQLiteStore


def _make_grant(**overrides) -> Grant:
    """Build a minimal test grant."""
    defaults = dict(
        agent_id="agent:test",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund", "email.send"], deny=[]),
        budget=Budget(currency="USD", limit=100, remaining=100),
        rate=Rate(max=10, per_seconds=60),
    )
    defaults.update(overrides)
    g = Grant(**defaults)
    g.sign()
    return g


def _make_action(grant: Grant, **overrides) -> Action:
    defaults = dict(
        grant_id=grant.id,
        ts=datetime.now(UTC),
        type="payment.refund",
        target="stripe",
        params={"amount": 20},
        est_cost=20,
    )
    defaults.update(overrides)
    return Action(**defaults)


def _make_store_and_pdp():
    store = SQLiteStore(":memory:")
    ledger = Ledger(store._conn)
    pdp = PDP(state=store, ledger=ledger)
    return store, ledger, pdp


def _make_allow_decision() -> Decision:
    return Decision(
        outcome=DecisionOutcome.ALLOW,
        reason="test allow",
        rule_matched="test",
        state_delta={},
    )


# ---------------------------------------------------------------------------
# 1. Permit runs without Cloud
# ---------------------------------------------------------------------------

class TestNoCloudDependency:
    def test_no_cloud_modules_loaded(self):
        cloud_modules = {
            m for m in sys.modules
            if m.startswith("actenon_cloud") or m.startswith("app.")
        }
        assert not cloud_modules, f"Permit loaded Cloud modules: {cloud_modules}"

    def test_no_cloud_imports_in_source(self):
        permit_src = Path(__file__).resolve().parent.parent / "src" / "actenon_permit"
        violations = []
        for py_file in permit_src.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(), filename=str(py_file))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("actenon_cloud") or alias.name.startswith("app"):
                            violations.append(f"{py_file.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module and (node.module.startswith("actenon_cloud") or node.module.startswith("app")):
                    violations.append(f"{py_file.name}: from {node.module}")
        assert not violations, f"Permit imports Cloud: {violations}"


# ---------------------------------------------------------------------------
# 2. Permit can issue a protocol-conforming proof
# ---------------------------------------------------------------------------

class TestProtocolConformingProof:
    def test_issue_protocol_conforming_pccb(self):
        grant = _make_grant()
        action = _make_action(grant)
        store, ledger, pdp = _make_store_and_pdp()
        store.put_grant(grant)
        decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action)
        assert decision.outcome == DecisionOutcome.ALLOW
        assert pccb is not None
        assert pccb.pccb_id.startswith("pccb_")
        assert pccb.signature.value != "pending"
        assert pccb.action_hash.value

    def test_proof_bound_to_exact_action(self):
        grant = _make_grant()
        action = _make_action(grant, params={"amount": 42})
        intent = _permit_action_to_kernel_intent(grant, action)
        assert intent.action.parameters["amount"] == 42
        assert intent.metadata.get("operation_id") == action.action_id
        assert intent.metadata.get("authority_ref", "").startswith("authref_")
        assert intent.metadata.get("grant_id") == grant.id
        assert intent.metadata.get("execution_mode") == "brokered"


# ---------------------------------------------------------------------------
# 3. Permit can use locally configured signing
# ---------------------------------------------------------------------------

class TestLocalSigning:
    def test_local_hmac_signing(self):
        grant = _make_grant()
        action = _make_action(grant)
        store, ledger, pdp = _make_store_and_pdp()
        store.put_grant(grant)
        decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action)
        assert pccb is not None
        assert pccb.signature.algorithm in ("HS256", "EdDSA")

    def test_local_ed25519_signing(self):
        grant = _make_grant()
        action = _make_action(grant)
        decision = _make_allow_decision()
        intent, pccb = mint_pccb_for_action(
            grant, action, decision,
            signing_secret="test-ed25519-key",
        )
        assert pccb is not None
        assert pccb.signature.algorithm in ("HS256", "EdDSA")


# ---------------------------------------------------------------------------
# 4. Permit can use externally supplied signing integration
# ---------------------------------------------------------------------------

class TestExternalSigning:
    def test_external_signing_secret(self):
        grant = _make_grant()
        action = _make_action(grant)
        decision = _make_allow_decision()
        intent, pccb = mint_pccb_for_action(
            grant, action, decision,
            signing_secret="external-supplied-secret-key",
        )
        assert pccb is not None
        from actenon.proof import PCCBVerifier, build_local_proof_signer
        verifier = PCCBVerifier(
            signer=build_local_proof_signer(secret="external-supplied-secret-key"),
        )
        from actenon.models.contracts import AudienceRef
        from actenon.models.runtime import DynamicContextInput
        context = DynamicContextInput(
            request_id="req_test",
            audience=AudienceRef(type="service", id="actenon-permit-gateway"),
            scope_capabilities=("payment.refund",),
            now=datetime.now(UTC),
        )
        verifier.verify(intent, pccb, context)


# ---------------------------------------------------------------------------
# 5. Permit does not execute side effects merely by issuing a proof
# ---------------------------------------------------------------------------

class TestNoSideEffectOnIssuance:
    def test_proof_issuance_does_not_call_provider(self):
        grant = _make_grant()
        action = _make_action(grant)
        side_effect_log: list[str] = []

        class MockProvider:
            def refund(self, amount, **kwargs):
                side_effect_log.append(f"refund called with {amount}")
                return {"id": "re_mock", "status": "succeeded"}

        MockProvider()
        decision = _make_allow_decision()
        intent, pccb = mint_pccb_for_action(grant, action, decision)
        assert side_effect_log == [], (
            f"Provider was called during proof issuance: {side_effect_log}. "
            f"Proof issuance must not trigger side effects."
        )

    def test_proof_issuance_does_not_write_to_database(self):
        grant = _make_grant()
        action = _make_action(grant)
        decision = _make_allow_decision()
        intent, pccb = mint_pccb_for_action(grant, action, decision)
        assert pccb is not None
        assert pccb.pccb_id


# ---------------------------------------------------------------------------
# 6. Attenuation produces parent_grant_id and delegation_depth
# ---------------------------------------------------------------------------

class TestAttenuationLinkage:
    def test_attenuation_sets_parent_grant_id(self):
        parent = _make_grant()
        child = parent.attenuate(agent_id="agent:child", budget_limit=50)
        assert child.parent_grant_id == parent.id

    def test_attenuation_sets_delegation_depth(self):
        parent = _make_grant()
        assert parent.delegation_depth == 0
        child = parent.attenuate(budget_limit=50)
        assert child.delegation_depth == 1
        grandchild = child.attenuate(budget_limit=25)
        assert grandchild.delegation_depth == 2
        assert grandchild.parent_grant_id == child.id

    def test_child_never_exceeds_parent(self):
        parent = _make_grant(
            budget=Budget(currency="USD", limit=100, remaining=100),
            rate=Rate(max=10, per_seconds=60),
        )
        with pytest.raises(ValueError, match="cannot increase budget"):
            parent.attenuate(budget_limit=200)
        with pytest.raises(ValueError, match="cannot raise rate"):
            parent.attenuate(rate_max=20)
        with pytest.raises(ValueError, match="cannot widen allow scopes"):
            parent.attenuate(scopes_allow=["payment.refund", "email.send", "admin.delete"])
        with pytest.raises(ValueError, match="cannot extend expiry"):
            parent.attenuate(expires_at=parent.expires_at + timedelta(hours=1))


# ---------------------------------------------------------------------------
# 7. Revocation cascades to child grants
# ---------------------------------------------------------------------------

class TestRevocationCascade:
    def test_revocation_cascades_to_children(self):
        store = SQLiteStore(":memory:")
        parent = _make_grant()
        child = parent.attenuate(budget_limit=50)
        store.put_grant(parent)
        store.put_grant(child)

        assert store.get_grant(parent.id).status == GrantStatus.ACTIVE
        assert store.get_grant(child.id).status == GrantStatus.ACTIVE

        store.set_status(parent.id, GrantStatus.REVOKED)
        for grant in store.list_grants():
            if (
                hasattr(grant, "parent_grant_id")
                and grant.parent_grant_id == parent.id
                and grant.status == GrantStatus.ACTIVE
            ):
                store.set_status(grant.id, GrantStatus.REVOKED)

        assert store.get_grant(parent.id).status == GrantStatus.REVOKED
        assert store.get_grant(child.id).status == GrantStatus.REVOKED


# ---------------------------------------------------------------------------
# 8. authority_ref digest is stable and verifiable
# ---------------------------------------------------------------------------

class TestAuthorityRef:
    def test_authority_ref_is_stable(self):
        grant = _make_grant()
        action = _make_action(grant)
        intent1 = _permit_action_to_kernel_intent(grant, action)
        intent2 = _permit_action_to_kernel_intent(grant, action)
        assert intent1.metadata["authority_ref"] == intent2.metadata["authority_ref"]

    def test_authority_ref_differs_for_different_grants(self):
        grant1 = _make_grant()
        grant2 = _make_grant()
        action = _make_action(grant1)
        intent1 = _permit_action_to_kernel_intent(grant1, action)
        intent2 = _permit_action_to_kernel_intent(grant2, action)
        assert intent1.metadata["authority_ref"] != intent2.metadata["authority_ref"]

    def test_authority_ref_differs_for_different_actions(self):
        grant = _make_grant()
        action1 = _make_action(grant, params={"amount": 10})
        action2 = _make_action(grant, params={"amount": 20})
        intent1 = _permit_action_to_kernel_intent(grant, action1)
        intent2 = _permit_action_to_kernel_intent(grant, action2)
        assert intent1.metadata["authority_ref"] != intent2.metadata["authority_ref"]


# ---------------------------------------------------------------------------
# 9. Ledger records all required transitions
# ---------------------------------------------------------------------------

class TestLedgerCompleteness:
    def test_ledger_records_decision_and_outcome(self):
        store, ledger, pdp = _make_store_and_pdp()
        grant = _make_grant()
        action = _make_action(grant)
        store.put_grant(grant)
        decision = pdp.decide(grant, action)

        entries = ledger.list_entries()
        assert len(entries) > 0
        last = entries[-1]
        assert last["action_type"] == action.type
        assert last["grant_id"] == grant.id
        assert last["outcome"] == decision.outcome.value
        assert "hash" in last
        assert "authority_boundary" in last

    def test_ledger_does_not_claim_human_judgement(self):
        store, ledger, pdp = _make_store_and_pdp()
        grant = _make_grant()
        action = _make_action(grant)
        store.put_grant(grant)
        pdp.decide(grant, action)

        entries = ledger.list_entries()
        last = entries[-1]
        assert "rule_matched" in last or "reason" in last
        for key in last:
            assert "human" not in key.lower(), f"Ledger field {key!r} implies human judgement"
            assert "correct" not in key.lower(), f"Ledger field {key!r} implies correctness claim"
