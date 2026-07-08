"""Phase 4 tests: Ed25519 asymmetric signing for PCCBs.

Proves the production hardening works:
  - Ed25519 keypair generation + persistence
  - PCCBs signed with Ed25519 verify correctly
  - Wrong key rejected (SIGNATURE_INVALID)
  - Save/load roundtrip preserves key identity
  - resolve_signer prefers Ed25519 over HMAC when both are available
"""

from __future__ import annotations

import os
import stat

import pytest

from actenon_permit import (
    PDP,
    Ledger,
    SQLiteStore,
)
from actenon_permit.ed25519_signer import (
    generate_ed25519_keypair,
    load_ed25519_keypair,
    resolve_signer,
    save_ed25519_keypair,
)
from actenon_permit.model import Action
from actenon_permit.policy import compile_policy


@pytest.fixture
def ed25519_keyfile(tmp_path, monkeypatch):
    """Generate an Ed25519 keypair, point the env at it, yield the path."""
    key_path = tmp_path / "ed25519-key.json"
    kp = generate_ed25519_keypair()
    save_ed25519_keypair(kp, key_path)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_path))
    # Clear the HMAC key so we're testing the Ed25519 path only.
    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)
    yield key_path, kp


def test_ed25519_keypair_generation():
    """generate_ed25519_keypair produces a valid 32-byte keypair."""
    kp = generate_ed25519_keypair()
    assert len(kp.private_key_bytes) == 32
    assert len(kp.public_key_bytes) == 32
    assert kp.key_id.startswith("ed25519-")
    assert kp.key.algorithm == "EdDSA"
    assert kp.key.provider == "pilot_local_eddsa"
    # JWK shape
    jwk = kp.public_key_jwk
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"


def test_ed25519_keypair_persistence(tmp_path):
    """save + load preserves the keypair exactly."""
    key_path = tmp_path / "key.json"
    kp = generate_ed25519_keypair()
    save_ed25519_keypair(kp, key_path)

    # File mode must be 0600
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600

    # Load and compare
    loaded = load_ed25519_keypair(key_path)
    assert loaded.private_key_bytes == kp.private_key_bytes
    assert loaded.public_key_bytes == kp.public_key_bytes
    assert loaded.key_id == kp.key_id


def test_permit_mints_ed25519_signed_pccb(ed25519_keyfile, tmp_db, monkeypatch):
    """When an Ed25519 key is available, permit's PCCBs are EdDSA-signed."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    _, kp = ed25519_keyfile

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    policy = {
        "agent": "ed25519-test-agent",
        "ttl": "15m",
        "budget": {"currency": "USD", "limit": 5000},
        "scopes": {"allow": ["payment.refund"], "deny": []},
    }
    grant = compile_policy(policy)
    store.put_grant(grant)
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="stripe",
        params={"amount": 100},
        est_cost=100,
    )

    decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action)
    assert decision.outcome.value == "ALLOW"
    assert pccb is not None
    assert pccb.signature.algorithm == "EdDSA", f"expected EdDSA, got {pccb.signature.algorithm}"
    assert pccb.signature.key_id == kp.key_id


def test_ed25519_pccb_verifies_with_correct_key(ed25519_keyfile, tmp_db, monkeypatch):
    """An Ed25519-signed PCCB verifies with the correct keypair."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    _, kp = ed25519_keyfile

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    grant = compile_policy({
        "agent": "ed25519-verify-test",
        "ttl": "15m",
        "budget": {"currency": "USD", "limit": 5000},
        "scopes": {"allow": ["payment.refund"], "deny": []},
    })
    store.put_grant(grant)
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="stripe",
        params={"amount": 50},
        est_cost=50,
    )

    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Verify with the kernel's own verifier, using the same keypair
    from actenon.proof.service import PCCBVerifier

    from actenon_permit.ed25519_signer import build_ed25519_signer
    from actenon_permit.kernel_bridge import _build_context

    signer = build_ed25519_signer(kp)
    verifier = PCCBVerifier(signer=signer)
    context = _build_context(grant, action)
    verifier.verify(intent, pccb, context)  # raises on failure


def test_ed25519_pccb_rejected_by_wrong_key(ed25519_keyfile, tmp_db, monkeypatch):
    """An Ed25519-signed PCCB is rejected by a different keypair."""
    from actenon.core.errors import ProofVerificationError
    from actenon.proof.service import PCCBVerifier

    from actenon_permit.ed25519_signer import build_ed25519_signer
    from actenon_permit.kernel_bridge import _build_context

    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    _, _ = ed25519_keyfile

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    grant = compile_policy({
        "agent": "ed25519-wrong-key-test",
        "ttl": "15m",
        "budget": {"currency": "USD", "limit": 5000},
        "scopes": {"allow": ["payment.refund"], "deny": []},
    })
    store.put_grant(grant)
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="stripe",
        params={"amount": 50},
        est_cost=50,
    )

    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)

    # Verify with a DIFFERENT keypair
    wrong_kp = generate_ed25519_keypair()
    wrong_signer = build_ed25519_signer(wrong_kp)
    wrong_verifier = PCCBVerifier(signer=wrong_signer)
    context = _build_context(grant, action)
    with pytest.raises(ProofVerificationError) as exc_info:
        wrong_verifier.verify(intent, pccb, context)
    assert exc_info.value.refusal_code == "SIGNATURE_INVALID"


def test_resolve_signer_prefers_ed25519_over_hmac(ed25519_keyfile, monkeypatch):
    """When both an Ed25519 key and HMAC secret are available, Ed25519 wins."""
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "some-hmac-secret")
    signer = resolve_signer()
    assert signer.algorithm == "EdDSA", f"expected EdDSA, got {signer.algorithm}"


def test_resolve_signer_falls_back_to_hmac(tmp_path, monkeypatch):
    """Without an Ed25519 key, resolve_signer falls back to HMAC."""
    monkeypatch.delenv("ACTENON_ED25519_KEY_FILE", raising=False)
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "fallback-hmac-secret")
    # Point the default Ed25519 path at a non-existent file
    monkeypatch.setenv("HOME", str(tmp_path))
    signer = resolve_signer()
    assert signer.algorithm == "HS256"


def test_ed25519_pccb_survives_process_restart(ed25519_keyfile, tmp_db, monkeypatch):
    """A PCCB minted in one process validates in another using the same key file.

    This is the Phase 4 production property: Ed25519 keys persist to disk,
    so PCCBs validate across process restarts — unlike ephemeral HMAC keys.
    """
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    key_path, kp = ed25519_keyfile

    # Process 1: mint a PCCB
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    grant = compile_policy({
        "agent": "restart-test",
        "ttl": "15m",
        "budget": {"currency": "USD", "limit": 5000},
        "scopes": {"allow": ["payment.refund"], "deny": []},
    })
    store.put_grant(grant)
    action = Action(
        grant_id=grant.id,
        type="payment.refund",
        target="stripe",
        params={"amount": 25},
        est_cost=25,
    )
    _, intent, pccb = pdp.decide_and_mint_pccb(grant, action)
    pccb_dict = pccb.to_dict()

    # Process 2: reload the key from disk and verify the PCCB
    from actenon.models.contracts import PCCB
    from actenon.proof.service import PCCBVerifier

    from actenon_permit.ed25519_signer import build_ed25519_signer, load_ed25519_keypair
    from actenon_permit.kernel_bridge import _build_context

    loaded_kp = load_ed25519_keypair(key_path)
    assert loaded_kp.key_id == kp.key_id  # same key

    signer2 = build_ed25519_signer(loaded_kp)
    verifier2 = PCCBVerifier(signer=signer2)
    pccb2 = PCCB.from_dict(pccb_dict)
    context2 = _build_context(grant, action)
    verifier2.verify(intent, pccb2, context2)  # raises on failure
