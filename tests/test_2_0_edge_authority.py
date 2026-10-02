"""2.0.0 candidate: Permit-minted proofs at a kernel protected edge.

- Glob-scoped grants (``payments.*``) yield proofs the kernel edge accepts:
  the proof names the exact capability, not the grant's pattern (E2E E0).
- Every proof carries a signed, revocable authority reference, and a revoked
  grant (or a revoked ancestor) cannot execute at the edge (E2E E8b).
- No signing configuration means no proof outside explicit development
  intent; the kernel floor admits only the secure kernel.
"""

from __future__ import annotations

import importlib.metadata
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon_permit.ed25519_signer import (
    Ed25519KeyError,
    generate_ed25519_keypair,
    resolve_signer,
    save_ed25519_keypair,
)
from actenon_permit.ledger import Ledger
from actenon_permit.model import Action, Budget, Grant, GrantStatus, Scopes
from actenon_permit.pdp import PDP
from actenon_permit.state import SQLiteStore

AUDIENCE = "service:actenon-permit-gateway"


@pytest.fixture
def issuer(tmp_path, monkeypatch):
    keypair = generate_ed25519_keypair(key_id="permit-test-key")
    key_file = tmp_path / "ed25519.json"
    save_ed25519_keypair(keypair, key_file)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(key_file))
    return keypair


@pytest.fixture
def store(tmp_path):
    return SQLiteStore(str(tmp_path / "state.db"))


def _grant(store, allow, parent=None) -> Grant:
    grant = Grant(
        agent_id="agent-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        scopes=Scopes(allow=allow),
        budget=Budget(currency="EUR", limit=Decimal("1000"), remaining=Decimal("1000")),
        parent_grant_id=parent.id if parent else None,
        delegation_depth=1 if parent else 0,
    ).sign()
    store.put_grant(grant)
    return grant


def _mint(store, grant):
    action = Action(grant_id=grant.id, type="payments.refund", target="ch_1", params={"amount_minor": 2500})
    decision, intent, pccb = PDP(store, Ledger(store)).decide_and_mint_pccb(grant, action)
    assert pccb is not None, decision.reason
    return intent, pccb


def _edge(tmp_path, keypair, **kwargs) -> ActenonGate:
    from actenon_permit.boundary.proofs import Ed25519PublicKeyVerifier

    return ActenonGate(
        verifier=Ed25519PublicKeyVerifier([keypair.public_key_jwk]),
        audience=AUDIENCE,
        issuer="service:actenon-permit",
        replay_protector=ReplayProtector(SqliteReplayStore(tmp_path / "edge-replay.sqlite3")),
        **kwargs,
    )


def test_glob_scoped_grant_proof_names_the_exact_capability(issuer, store, tmp_path):
    from actenon_permit.revocation import StoreRevocationChecker

    intent, pccb = _mint(store, _grant(store, ["payments.*"]))
    assert list(pccb.scope.capabilities) == ["payments.refund"]
    calls: list[int] = []
    out = _edge(tmp_path, issuer, revocation_checker=StoreRevocationChecker(store)).protect(
        intent, pccb, lambda: calls.append(1)
    )
    assert out.ok, out.reason_code
    assert calls == [1]


def test_minted_proof_carries_a_signed_revocable_authority(issuer, store):
    grant = _grant(store, ["payments.refund"])
    _, pccb = _mint(store, grant)
    assert pccb.extensions["authority"] == {
        "issuer": "service:actenon-permit",
        "grant_id": grant.id,
        "revocable": True,
    }


def test_revoked_grant_cannot_execute_at_the_edge(issuer, store, tmp_path):
    from actenon_permit.revocation import StoreRevocationChecker

    grant = _grant(store, ["payments.refund"])
    intent, pccb = _mint(store, grant)
    store.set_status(grant.id, GrantStatus.REVOKED)
    calls: list[int] = []
    out = _edge(tmp_path, issuer, revocation_checker=StoreRevocationChecker(store)).protect(
        intent, pccb, lambda: calls.append(1)
    )
    assert out.reason_code == "AUTHORITY_REVOKED"
    assert calls == []


def test_revoked_ancestor_cascades_to_a_delegated_proof(issuer, store, tmp_path):
    from actenon_permit.revocation import StoreRevocationChecker

    parent = _grant(store, ["payments.*"])
    child = _grant(store, ["payments.refund"], parent=parent)
    intent, pccb = _mint(store, child)
    store.set_status(parent.id, GrantStatus.REVOKED)
    calls: list[int] = []
    out = _edge(tmp_path, issuer, revocation_checker=StoreRevocationChecker(store)).protect(
        intent, pccb, lambda: calls.append(1)
    )
    assert out.reason_code == "AUTHORITY_REVOKED"
    assert calls == []


def test_unknown_grant_or_store_failure_refuses(issuer, store, tmp_path):
    from actenon_permit.revocation import StoreRevocationChecker

    grant = _grant(store, ["payments.refund"])
    intent, pccb = _mint(store, grant)
    other_store = SQLiteStore(str(tmp_path / "other.db"))  # does not know the grant
    out = _edge(tmp_path, issuer, revocation_checker=StoreRevocationChecker(other_store)).protect(
        intent, pccb, lambda: None
    )
    assert out.reason_code == "AUTHORITY_REVOKED"

    class Broken:
        def get_grant(self, grant_id):
            raise ConnectionError("state store unreachable")

    out = _edge(tmp_path, issuer, revocation_checker=StoreRevocationChecker(Broken())).protect(
        intent, pccb, lambda: None
    )
    assert out.reason_code == "AUTHORITY_REVOKED"


def test_edge_without_a_revocation_source_refuses_permit_proofs(issuer, store, tmp_path):
    intent, pccb = _mint(store, _grant(store, ["payments.refund"]))
    calls: list[int] = []
    out = _edge(tmp_path, issuer).protect(intent, pccb, lambda: calls.append(1))
    assert out.reason_code == "AUTHORITY_REVOKED"
    assert calls == []


def test_permit_own_edge_refuses_a_revoked_grant(issuer, store):
    from actenon.core import ProofVerificationError
    from actenon_permit.kernel_bridge import verify_pccb_at_edge

    grant = _grant(store, ["payments.*"])
    action = Action(grant_id=grant.id, type="payments.refund", target="ch_1", params={"amount_minor": 2500})
    decision, intent, pccb = PDP(store, Ledger(store)).decide_and_mint_pccb(grant, action)
    verify_pccb_at_edge(intent, pccb, grant, action, store=store)
    store.set_status(grant.id, GrantStatus.REVOKED)
    with pytest.raises(ProofVerificationError) as raised:
        verify_pccb_at_edge(intent, pccb, grant, action, store=store)
    assert raised.value.refusal_code == "AUTHORITY_REVOKED"


@pytest.mark.parametrize("env", [None, "prd", "production"])
def test_no_signing_configuration_refuses_outside_development(monkeypatch, tmp_path, env):
    from actenon_permit import model

    for name in ("ACTENON_ED25519_KEY_FILE", "ACTENON_SIGNING_KEY", "ACTENON_SIGNING_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(model, "_DEV_KEY", None)
    if env is None:
        monkeypatch.delenv("ACTENON_ENV", raising=False)
    else:
        monkeypatch.setenv("ACTENON_ENV", env)
    with pytest.raises(Ed25519KeyError):
        resolve_signer()
    with pytest.raises(RuntimeError, match="ACTENON_SIGNING_KEY"):
        model._get_signing_key()


def test_development_intent_keeps_local_signing(monkeypatch, tmp_path):
    from actenon_permit import model

    for name in ("ACTENON_ED25519_KEY_FILE", "ACTENON_SIGNING_KEY", "ACTENON_SIGNING_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(model, "_DEV_KEY", None)
    monkeypatch.setenv("ACTENON_ENV", "development")
    assert resolve_signer().algorithm == "HS256"
    assert model._get_signing_key()


def test_kernel_floor_is_the_secure_kernel():
    requires = importlib.metadata.requires("actenon-permit") or []
    kernel = [r for r in requires if r.startswith("actenon-kernel")]
    assert kernel and all(">=1.3.0" in r for r in kernel), kernel


def test_exhausted_by_its_own_reservation_is_not_revoked(issuer, store, tmp_path):
    # The minting reservation exhausts a budget-sized grant; that is budget
    # state, not revocation, so the proof minted under it still executes once.
    from actenon_permit.revocation import StoreRevocationChecker

    grant = _grant(store, ["payments.refund"])
    intent, pccb = _mint(store, grant)
    store.set_status(grant.id, GrantStatus.EXHAUSTED)
    out = _edge(tmp_path, issuer, revocation_checker=StoreRevocationChecker(store)).protect(intent, pccb, lambda: None)
    assert out.ok, out.reason_code
    store.set_status(grant.id, GrantStatus.EXPIRED)
    out = _edge(tmp_path / "x", issuer, revocation_checker=StoreRevocationChecker(store)).protect(intent, pccb, lambda: None)
    assert out.reason_code == "AUTHORITY_REVOKED"
