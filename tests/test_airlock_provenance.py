"""Grant verify, exact proofs, and revocation — the contract Airlock PR #3 calls.

Airlock signs a grant, stores it, and reloads it before every decision. Permit
rewrites status and budget.remaining on reserve and set_status. Those live
fields stay out of the HMAC so a second ALLOW still verifies. Scopes and
budget.limit stay inside it. Proofs name one concrete capability. Unknown
capabilities and unknown grants fail closed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from actenon_permit import (
    PDP,
    Action,
    Budget,
    DecisionOutcome,
    Grant,
    GrantStatus,
    Ledger,
    Scopes,
    SQLiteStore,
)
from actenon_permit.kernel_bridge import KernelBridgeError, mint_pccb_for_action, proof_capability
from actenon_permit.model import Decision
from actenon_permit.revocation import PERMIT_ISSUER, RevocationLookupError, StoreRevocationChecker


def _grant(*, allow: list[str] | None = None, deny: list[str] | None = None, limit: int = 100) -> Grant:
    grant = Grant(
        agent_id="airlock:source",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(
            allow=["airlock.http.post"] if allow is None else list(allow),
            deny=[] if deny is None else list(deny),
        ),
        budget=Budget(limit=limit, remaining=limit),
    )
    grant.sign()
    return grant


def _action(grant: Grant, type: str, *, cost: float = 1) -> Action:
    return Action(grant_id=grant.id, type=type, target="https://example.test/a", est_cost=cost)


def _pdp() -> tuple[SQLiteStore, PDP]:
    store = SQLiteStore()
    return store, PDP(store, Ledger(store))


def test_second_allow_keeps_the_signed_authority(tmp_db):
    """The Airlock multi-ALLOW bug: reloading the stored grant must still verify."""
    store, pdp = _pdp()
    grant = _grant()
    store.put_grant(grant)
    authority = grant.model_dump(exclude={"status", "budget"})

    first = pdp.decide(grant, _action(grant, "airlock.http.post"))
    assert first.outcome == DecisionOutcome.ALLOW
    live = store.get_grant(grant.id)
    assert live is not None and live.verify()
    assert live.signature == grant.signature
    assert live.budget.remaining < grant.budget.remaining
    assert live.model_dump(exclude={"status", "budget"}) == authority

    second = pdp.decide(live, _action(grant, "airlock.http.post"))
    assert second.outcome == DecisionOutcome.ALLOW
    again = store.get_grant(grant.id)
    assert again is not None and again.verify()
    assert again.model_dump(exclude={"status", "budget"}) == authority


def test_revocation_denies_without_breaking_the_signature(tmp_db):
    store, pdp = _pdp()
    grant = _grant()
    store.put_grant(grant)
    assert pdp.decide(grant, _action(grant, "airlock.http.post")).outcome == DecisionOutcome.ALLOW
    store.set_status(grant.id, GrantStatus.REVOKED)
    live = store.get_grant(grant.id)
    assert live is not None and live.verify()
    decision = pdp.decide(live, _action(grant, "airlock.http.post"))
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason == "grant status is revoked"


def test_widened_scope_or_budget_fails_verification(tmp_db):
    store, pdp = _pdp()
    grant = _grant()
    store.put_grant(grant)

    widened_scope = store.get_grant(grant.id)
    assert widened_scope is not None
    widened_scope.scopes.allow.append("*")
    store.put_grant(widened_scope)
    denied = pdp.decide(store.get_grant(grant.id), _action(grant, "airlock.http.post"))
    assert denied.outcome == DecisionOutcome.DENY
    assert denied.reason == "grant signature could not be verified"

    store.put_grant(grant)
    widened_budget = store.get_grant(grant.id)
    assert widened_budget is not None
    widened_budget.budget.limit = 10**9
    assert not widened_budget.verify()


def test_unknown_capability_is_out_of_scope(tmp_db):
    store, pdp = _pdp()
    grant = _grant(allow=["airlock.http.post"])
    store.put_grant(grant)
    decision = pdp.decide(grant, _action(grant, "airlock.unresolved.abc"))
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason == "out of scope"


def test_unsigned_grant_is_denied(tmp_db):
    store, pdp = _pdp()
    grant = _grant()
    grant.signature = ""
    store.put_grant(grant)
    decision = pdp.decide(grant, _action(grant, "airlock.http.post"))
    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason == "grant signature could not be verified"


def test_empty_allow_decides_per_spec_but_cannot_mint(tmp_db):
    store, pdp = _pdp()
    grant = _grant(allow=[])
    store.put_grant(grant)
    action = _action(grant, "airlock.http.post", cost=0)
    assert pdp.decide(grant, action).outcome == DecisionOutcome.ALLOW

    decision, intent, proof = pdp.decide_and_mint_pccb(grant, _action(grant, "airlock.http.post", cost=0))
    assert decision.outcome == DecisionOutcome.DENY
    assert intent is None and proof is None
    assert "empty allow-list" in decision.reason
    # The refusal happens before reserve, so the cap is intact.
    assert store.get_grant(grant.id).budget.remaining == grant.budget.limit


def test_proof_names_the_concrete_action_not_the_allow_list(tmp_db, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "airlock-provenance-test")
    store, pdp = _pdp()
    grant = _grant(allow=["payment.*", "email.send"])
    store.put_grant(grant)
    action = _action(grant, "payment.refund", cost=0)
    decision, _intent, proof = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome == DecisionOutcome.ALLOW
    assert proof.scope.capabilities == ("payment.refund",)
    assert "*" not in proof.scope.capabilities
    assert "payment.*" not in proof.scope.capabilities


def test_wildcard_action_cannot_mint(tmp_db):
    store, pdp = _pdp()
    grant = _grant(allow=["*"])
    store.put_grant(grant)
    decision, intent, proof = pdp.decide_and_mint_pccb(grant, _action(grant, "*", cost=0))
    assert decision.outcome == DecisionOutcome.DENY
    assert intent is None and proof is None
    assert "wildcard" in decision.reason
    with pytest.raises(KernelBridgeError, match="wildcard"):
        proof_capability(grant, _action(grant, "shell.*"))


def test_attenuation_cannot_add_a_wildcard(tmp_db):
    grant = _grant(allow=["airlock.http.post"])
    with pytest.raises(ValueError, match="cannot widen allow scopes"):
        grant.attenuate(scopes_allow=["airlock.http.post", "*"])


def test_store_revocation_checker_fail_closed(tmp_db):
    store, _ = _pdp()
    grant = _grant()
    child = grant.attenuate(scopes_allow=["airlock.http.post"], budget_limit=10)
    store.put_grant(grant)
    store.put_grant(child)
    checker = StoreRevocationChecker(store)

    def proof_for(grant_id: str, issuer: str = PERMIT_ISSUER):
        return SimpleNamespace(
            extensions={"authority": {"issuer": issuer, "grant_id": grant_id, "revocable": True}}
        )

    assert checker(proof_for(grant.id), None) is True
    assert checker(proof_for(child.id), None) is True

    store.set_status(grant.id, GrantStatus.REVOKED)
    assert checker(proof_for(grant.id), None) is False
    assert checker(proof_for(child.id), None) is False

    with pytest.raises(RevocationLookupError, match="unknown"):
        checker(proof_for("grant_missing"), None)
    with pytest.raises(RevocationLookupError, match="no Permit authority"):
        checker(SimpleNamespace(extensions={}), None)
    with pytest.raises(RevocationLookupError, match="different issuer"):
        checker(proof_for(child.id, issuer="service:other"), None)


def test_mint_refuses_an_unverified_grant():
    grant = _grant()
    grant.scopes.allow.append("email.send")
    action = _action(grant, "airlock.http.post", cost=0)
    decision = Decision(outcome=DecisionOutcome.ALLOW, reason="allowed")
    with pytest.raises(KernelBridgeError, match="could not be verified"):
        mint_pccb_for_action(grant, action, decision)
