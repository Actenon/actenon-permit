"""Actenon-Permit local Ed25519 signing backend.

This module implements the kernel's ``ExternalManagedSigningBackend``
Protocol using a local Ed25519 keypair. It's the "pilot_local_eddsa" path
the kernel anticipates — real asymmetric signing (Ed25519 via the
``cryptography`` library), not dev-HMAC.

This is NOT a substitute for KMS/HSM in production — the private key lives
on disk. But it's the real asymmetric signature algorithm, with real key
generation, real signing, and real verification. It's what a pilot uses
before wiring a cloud KMS.

The kernel's production guardrail (``validate_signing_backend_for_environment``)
allows ``pilot_local_eddsa`` in production only when
``ACTENON_ALLOW_PILOT_LOCAL_EDDSA_IN_PRODUCTION=1`` is set — an explicit
"unsafe emergency/demo override" flag. Without that flag, production
requires ``external_managed`` (real KMS/HSM).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from actenon.proof.signers.base import b64url_decode, b64url_encode
from actenon.proof.signers.external_managed import (
    ACTIVE_KEY_STATUS,
    PILOT_LOCAL_EDDSA_BACKEND,
    ManagedKeyReference,
    ManagedSigningResult,
)


class Ed25519KeyError(RuntimeError):
    """Raised when the Ed25519 key is missing, invalid, or the wrong type."""


def _load_crypto():
    """Lazy-load cryptography; raise a clear error if not installed."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:
        raise Ed25519KeyError(
            "Ed25519 signing requires the 'cryptography' package. "
            "Install with: pip install 'actenon-kernel[asymmetric]' or pip install cryptography>=42"
        ) from e
    return ed25519, serialization


@dataclass(frozen=True)
class Ed25519KeyPair:
    """A local Ed25519 keypair with its kernel key reference."""

    private_key_bytes: bytes  # 32 raw bytes
    public_key_bytes: bytes  # 32 raw bytes
    key_id: str
    key: ManagedKeyReference

    @property
    def public_key_jwk(self) -> dict[str, Any]:
        """The public key as a JWK (for well-known key verification)."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.key_id,
            "alg": "EdDSA",
            "x": b64url_encode(self.public_key_bytes),
        }


def generate_ed25519_keypair(
    *,
    key_id: str | None = None,
    tenant_id: str | None = None,
) -> Ed25519KeyPair:
    """Generate a fresh Ed25519 keypair."""
    ed25519, _ = _load_crypto()
    private = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.Raw,
        encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
    )
    public = private.public_key()
    public_bytes = public.public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    kid = key_id or f"ed25519-{uuid4().hex[:12]}"
    key = ManagedKeyReference(
        provider=PILOT_LOCAL_EDDSA_BACKEND,
        provider_key_ref=f"local:{kid}",
        key_id=kid,
        algorithm="EdDSA",
        purpose="proof_issuance",
        tenant_id=tenant_id,
        public_key_ref=b64url_encode(public_bytes),
        key_version="1",
        status=ACTIVE_KEY_STATUS,
    )
    return Ed25519KeyPair(
        private_key_bytes=private_bytes,
        public_key_bytes=public_bytes,
        key_id=kid,
        key=key,
    )


def save_ed25519_keypair(keypair: Ed25519KeyPair, path: Path) -> None:
    """Persist an Ed25519 keypair to disk (JSON, mode 0600).

    The file contains both the private and public key in raw base64url.
    The private key is the root of trust — protect the file.
    """
    import os as _os

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "key_id": keypair.key_id,
        "algorithm": "EdDSA",
        "private_key": b64url_encode(keypair.private_key_bytes),
        "public_key": b64url_encode(keypair.public_key_bytes),
        "tenant_id": keypair.key.tenant_id,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = _os.open(str(path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    try:
        _os.write(fd, data)
    finally:
        _os.close(fd)
    _os.chmod(path, 0o600)


def load_ed25519_keypair(path: Path) -> Ed25519KeyPair:
    """Load an Ed25519 keypair from disk."""
    ed25519, _ = _load_crypto()
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("algorithm") != "EdDSA":
        raise Ed25519KeyError(f"expected EdDSA, got {data.get('algorithm')}")
    private_bytes = b64url_decode(data["private_key"])
    public_bytes = b64url_decode(data["public_key"])
    if len(private_bytes) != 32 or len(public_bytes) != 32:
        raise Ed25519KeyError("Ed25519 keys must be 32 bytes")
    key_id = data["key_id"]
    key = ManagedKeyReference(
        provider=PILOT_LOCAL_EDDSA_BACKEND,
        provider_key_ref=f"local:{key_id}",
        key_id=key_id,
        algorithm="EdDSA",
        purpose="proof_issuance",
        tenant_id=data.get("tenant_id"),
        public_key_ref=b64url_encode(public_bytes),
        key_version="1",
        status=ACTIVE_KEY_STATUS,
    )
    return Ed25519KeyPair(
        private_key_bytes=private_bytes,
        public_key_bytes=public_bytes,
        key_id=key_id,
        key=key,
    )


@dataclass(frozen=True)
class LocalEd25519Backend:
    """Implements ``ExternalManagedSigningBackend`` using a local Ed25519 key.

    This is the "pilot_local_eddsa" backend: real Ed25519 signing, but the
    private key is on local disk rather than in a KMS/HSM. The kernel's
    production guardrail allows this only with an explicit override flag.
    """

    keypair: Ed25519KeyPair

    def get_key_status(self, *, key: ManagedKeyReference) -> str:
        """Return the key's status (always 'active' for a local keypair)."""
        if key.key_id != self.keypair.key_id:
            return "unknown"
        return ACTIVE_KEY_STATUS

    def sign_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        audit_metadata: Mapping[str, object],
    ) -> ManagedSigningResult:
        """Sign canonical bytes with the local Ed25519 private key."""
        if key.key_id != self.keypair.key_id:
            raise Ed25519KeyError(f"key_id mismatch: {key.key_id} != {self.keypair.key_id}")
        ed25519, _ = _load_crypto()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self.keypair.private_key_bytes)
        signature = private_key.sign(payload)
        return ManagedSigningResult(
            algorithm="EdDSA",
            key_id=self.keypair.key_id,
            signature=signature,
            public_key_ref=b64url_encode(self.keypair.public_key_bytes),
            provider_operation_id=str(audit_metadata.get("operation_id", "")),
        )

    def verify_canonical_bytes(
        self,
        *,
        key: ManagedKeyReference,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        """Verify a signature against the local Ed25519 public key."""
        if key.key_id != self.keypair.key_id:
            return False
        ed25519, _ = _load_crypto()
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(self.keypair.public_key_bytes)
            public_key.verify(signature, payload)
            return True
        except Exception:  # noqa: BLE001 — InvalidSignature + anything else
            return False


def build_ed25519_signer(keypair: Ed25519KeyPair):
    """Build an ``ExternalManagedSigner`` backed by a local Ed25519 key.

    The returned signer conforms to the kernel's ``Signer`` protocol and
    can be passed directly to ``PCCBMinter(signer=...)`` and
    ``PCCBVerifier(signer=...)``.
    """
    from actenon.proof.signers.external_managed import ExternalManagedSigner

    backend = LocalEd25519Backend(keypair=keypair)
    return ExternalManagedSigner(backend=backend, key=keypair.key)


def resolve_signer(
    *,
    ed25519_key_path: str | Path | None = None,
    hmac_secret: bytes | str | None = None,
):
    """Resolve a signer for PCCB minting, preferring Ed25519 over HMAC.

    Resolution order:
      1. Ed25519 key file (from ``ed25519_key_path`` or
         ``ACTENON_ED25519_KEY_FILE`` env var or
         ``~/.actenon-permit/ed25519-key.json``)
      2. HMAC secret (from ``hmac_secret`` or ``ACTENON_SIGNING_KEY``)

    Ed25519 is the production-preferred path. HMAC is the dev fallback.
    """
    from actenon.proof.signers.local import build_local_proof_signer

    # Try Ed25519 first
    key_path = ed25519_key_path
    if key_path is None:
        env_path = os.environ.get("ACTENON_ED25519_KEY_FILE", "").strip()
        if env_path:
            key_path = Path(env_path)
        else:
            default_path = Path.home() / ".actenon-permit" / "ed25519-key.json"
            if default_path.is_file():
                key_path = default_path

    if key_path is not None:
        try:
            path = Path(key_path)
            if path.is_file():
                keypair = load_ed25519_keypair(path)
                return build_ed25519_signer(keypair)
        except Exception:
            pass  # fall through to HMAC

    # Fall back to HMAC
    secret = hmac_secret
    if secret is None:
        env_key = os.environ.get("ACTENON_SIGNING_KEY", "").strip()
        if env_key:
            secret = env_key
    return build_local_proof_signer(secret=secret) if secret is not None else build_local_proof_signer()


__all__ = [
    "Ed25519KeyError",
    "Ed25519KeyPair",
    "LocalEd25519Backend",
    "generate_ed25519_keypair",
    "save_ed25519_keypair",
    "load_ed25519_keypair",
    "build_ed25519_signer",
    "resolve_signer",
]
