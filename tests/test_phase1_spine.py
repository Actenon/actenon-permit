"""Phase 1 gate: prove permit's PCCB emission uses the real kernel spine.

This test is the concrete implementation of ARCHITECTURE.md §3's invariant:
"the PCCB is built and signed by kernel code, not by parallel implementations."

It verifies:
  1. permit's decide_and_mint_pccb() produces a real kernel PCCB
  2. The PCCB verifies at the kernel's own PCCBVerifier
  3. Mutating any bound field (amount, target, action type) fails verification
  4. The action-hash in permit's PCCB matches what the kernel's own
     build_action_hash_input produces for the same intent — i.e., the bridge
     doesn't silently diverge from the kernel's canonicalization.
"""

from __future__ import annotations

import pytest

from actenon_permit import (
    PDP,
    DecisionOutcome,
    Grant,
    Ledger,
    SQLiteStore,
)
from actenon_permit.model import Action
from actenon_permit.policy import compile_policy


def _make_grant() -> Grant:
    policy = {
        "agent": "phase1-gate-agent",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 50},
        "scopes": {"allow": ["payment.refund", "email.send"], "deny": ["payment.charge"]},
        "rate": {"max": 20, "per": "1m"},
        "approval": {"require_human": ["email.send"]},
    }
    return compile_policy(policy)


def _make_action(grant: Grant, *, type: str = "payment.refund", amount: float = 20, **params) -> Action:
    p = dict(params)
    if amount is not None:
        p["amount"] = amount
    return Action(
        grant_id=grant.id,
        type=type,
        target=type,
        params=p,
        est_cost=amount,
    )


@pytest.fixture
def setup(tmp_db, monkeypatch):
    """Fresh store + ledger + PDP with a grant issued."""
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "phase1-gate-test-key")
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    grant = _make_grant()
    store.put_grant(grant)
    return store, ledger, pdp, grant


def test_permit_mints_real_kernel_pccb(setup):
    """permit's decide_and_mint_pccb returns a real kernel PCCB that the
    kernel's own PCCBVerifier accepts."""
    from actenon.proof.service import PCCBVerifier
    from actenon.proof.signers.local import build_local_proof_signer

    _, _, pdp, grant = setup
    action = _make_action(grant, amount=20)

    decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome == DecisionOutcome.ALLOW
    assert intent is not None, "intent must be returned on ALLOW"
    assert pccb is not None, "PCCB must be returned on ALLOW"

    # The PCCB must verify with the kernel's own verifier (same signer).
    signer = build_local_proof_signer(secret="phase1-gate-test-key")
    verifier = PCCBVerifier(signer=signer)
    from actenon_permit.kernel_bridge import _build_context

    context = _build_context(grant, action)
    verifier.verify(intent, pccb, context)  # raises on failure
    # If we get here, the PCCB is real and kernel-valid.


def test_pccb_action_hash_matches_kernel_canonicalization(setup):
    """The action-hash in permit's PCCB must equal the kernel's own
    build_action_hash_input for the same intent — proving no parallel
    canonicalization."""
    from actenon.proof.canonical import sha256_hex
    from actenon.proof.service import build_action_hash_input

    _, _, pdp, grant = setup
    action = _make_action(grant, amount=20)
    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Recompute the action hash using the kernel's own function.
    expected_hash = sha256_hex(build_action_hash_input(intent))
    assert pccb.action_hash.value == expected_hash, (
        "permit's PCCB action-hash must match the kernel's own canonicalization. "
        f"got {pccb.action_hash.value}, expected {expected_hash}"
    )


def test_mutation_amount_detected_at_edge(setup):
    """If the agent tries to execute with a different amount than the PCCB
    was issued for, the kernel's verifier rejects it (ACTION_MISMATCH)."""
    from actenon.core.errors import ProofVerificationError

    from actenon_permit.kernel_bridge import verify_pccb_at_edge

    _, _, pdp, grant = setup
    # Issue PCCB for $20
    action = _make_action(grant, amount=20)
    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Now try to execute with $99999 (simulated injection / confused agent)
    mutated_action = _make_action(grant, amount=99999)
    with pytest.raises(ProofVerificationError) as exc_info:
        verify_pccb_at_edge(intent, pccb, grant, mutated_action)
    assert exc_info.value.refusal_code in ("ACTION_MISMATCH", "ACTION_HASH_MISMATCH", "INTENT_MISMATCH")


def test_mutation_target_detected_at_edge(setup):
    """Changing the target between issuance and execution is refused."""
    from actenon.core.errors import ProofVerificationError

    from actenon_permit.kernel_bridge import verify_pccb_at_edge

    _, _, pdp, grant = setup
    action = _make_action(grant, amount=20)
    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Mutate the target
    mutated_action = Action(
        action_id=action.action_id,
        grant_id=grant.id,
        type=action.type,
        target="different-target",
        params=action.params,
        est_cost=action.est_cost,
    )
    with pytest.raises(ProofVerificationError) as exc_info:
        verify_pccb_at_edge(intent, pccb, grant, mutated_action)
    assert exc_info.value.refusal_code in ("TARGET_MISMATCH", "INTENT_MISMATCH")


def test_mutation_action_type_detected_at_edge(setup):
    """Changing the action type (e.g. from refund to charge) is refused.
    The refusal code is SCOPE_CAPABILITY_MISMATCH (the PCCB's scope only
    includes payment.refund, not payment.charge) — either way, the edge
    refuses and the credential is not released."""
    from actenon.core.errors import ProofVerificationError

    from actenon_permit.kernel_bridge import verify_pccb_at_edge

    _, _, pdp, grant = setup
    action = _make_action(grant, amount=20, type="payment.refund")
    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Try to use the refund PCCB for a charge
    mutated_action = _make_action(grant, amount=20, type="payment.charge")
    with pytest.raises(ProofVerificationError) as exc_info:
        verify_pccb_at_edge(intent, pccb, grant, mutated_action)
    assert exc_info.value.refusal_code in (
        "ACTION_MISMATCH",
        "SCOPE_CAPABILITY_MISMATCH",
        "ACTION_HASH_MISMATCH",
        "INTENT_MISMATCH",
    )


def test_cross_signer_rejected(setup):
    """A PCCB minted with signer A is rejected by signer B's verifier."""
    from actenon.core.errors import ProofVerificationError
    from actenon.proof.service import PCCBVerifier
    from actenon.proof.signers.local import build_local_proof_signer

    from actenon_permit.kernel_bridge import _build_context

    _, _, pdp, grant = setup
    action = _make_action(grant, amount=20)
    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Verify with a DIFFERENT signer
    wrong_signer = build_local_proof_signer(secret="wrong-key")
    wrong_verifier = PCCBVerifier(signer=wrong_signer)
    context = _build_context(grant, action)
    with pytest.raises(ProofVerificationError) as exc_info:
        wrong_verifier.verify(intent, pccb, context)
    assert exc_info.value.refusal_code == "SIGNATURE_INVALID"


def test_pccb_not_minted_on_deny(setup):
    """On DENY, no PCCB is minted — the credential cannot be released."""
    _, _, pdp, grant = setup
    # Charge is denied by scope
    action = _make_action(grant, amount=100, type="payment.charge")
    decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome == DecisionOutcome.DENY
    assert intent is None
    assert pccb is None
