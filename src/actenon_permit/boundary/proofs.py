"""Boundary proofs: what the Boundary Kit verifies, and how to trust and mint them.

A request to a protected route carries two headers:

* ``X-Actenon-Proof`` (name configurable per boundary): the kernel PCCB,
  encoded as ``"v1." + base64url(JSON)`` (raw JSON and bare base64url are
  also accepted).
* ``X-Actenon-Intent``: the exact kernel Action Intent the PCCB was minted
  for, in the same encoding.

The middleware binds the intent to the HTTP request (the route's action,
the target and every mapped parameter must match what the request actually
carries), then has the kernel verify the PCCB against that intent and the
boundary's audience (signature, time window, action hash, audience), and
enforces single use. The trust root is a kernel ``PCCBVerifier``: pass one
to ``BoundaryMiddleware(pccb_verifier=...)``, or list the issuer's Ed25519
public keys (JWKs) under ``trusted_issuers[].public_keys`` in the manifest.
Without a trust root, an audience, or an intent, every request is refused.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from actenon.models.contracts import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import DynamicContextInput, PolicyDecision, RuleEvaluation
from actenon.proof.service import PCCBMinter, PCCBVerifier
from actenon.proof.signers.base import b64url_decode

from ..kernel_bridge import _canonicalize_params

INTENT_HEADER = "X-Actenon-Intent"
TOKEN_PREFIX = "v1."
MAX_TOKEN_CHARS = 64 * 1024


def encode_token(payload: Mapping[str, Any]) -> str:
    """Encode a PCCB or Action Intent dict as ``"v1." + base64url(JSON)``."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return TOKEN_PREFIX + base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")


def decode_token(token: str) -> dict[str, Any]:
    """Decode a token back to a JSON object. Raises ValueError on anything else."""
    if len(token) > MAX_TOKEN_CHARS:
        raise ValueError("token too large")
    text = token.strip()
    if not text.startswith("{"):
        text = text.removeprefix(TOKEN_PREFIX)
        try:
            text = base64.b64decode(
                (text + "=" * (-len(text) % 4)).encode("ascii"), altchars=b"-_", validate=True
            ).decode("utf-8")
        except (binascii.Error, UnicodeError) as exc:
            raise ValueError("token is neither JSON nor base64url-encoded JSON") from exc
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("token must decode to a JSON object")
    return payload


def canonical_parameters(params: Mapping[str, Any]) -> dict[str, Any]:
    """The parameter form bound into intents (floats as repr strings), so a
    request's extracted values compare equal to what the issuer minted."""
    return _canonicalize_params(dict(params))


def parse_audience(raw: str) -> AudienceRef:
    """``"type:id"`` or a bare service id."""
    audience_type, sep, audience_id = raw.partition(":")
    if not sep:
        return AudienceRef(type="service", id=raw)
    if not audience_type or not audience_id:
        raise ValueError("audience must be 'type:id' or a bare service id")
    return AudienceRef(type=audience_type, id=audience_id)


class Ed25519PublicKeyVerifier:
    """Kernel ``SignatureVerifier`` over a set of trusted Ed25519 public keys.

    Keys are JWKs (``{"kty": "OKP", "crv": "Ed25519", "kid": ..., "x": ...}``)
    and are selected by the signature's ``key_id``. Verify-only: it holds no
    private key.
    """

    algorithm = "EdDSA"

    def __init__(self, jwks: Iterable[Mapping[str, Any]]):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        self._keys: dict[str, Any] = {}
        for jwk in jwks:
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                raise ValueError(
                    f"unsupported trusted key (need an Ed25519 JWK): {jwk.get('kid')!r}"
                )
            kid, x = jwk.get("kid"), jwk.get("x")
            if not isinstance(kid, str) or not kid or not isinstance(x, str):
                raise ValueError("an Ed25519 JWK needs a string 'kid' and 'x'")
            raw = b64url_decode(x)
            if len(raw) != 32:
                raise ValueError(f"Ed25519 public key {kid!r} must be 32 bytes")
            self._keys[kid] = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        if not self._keys:
            raise ValueError("no trusted public keys")
        self.key_id = next(iter(self._keys))

    def verify(self, payload: bytes, signature: Any) -> bool:
        key = self._keys.get(getattr(signature, "key_id", None))
        if (
            key is None
            or getattr(signature, "algorithm", None) != self.algorithm
            or getattr(signature, "encoding", None) != "base64url"
        ):
            return False
        try:
            key.verify(b64url_decode(signature.value), payload)
            return True
        except Exception:  # noqa: BLE001 - InvalidSignature, bad encoding
            return False


def trust_root_from_issuers(trusted_issuers: Iterable[Any]) -> PCCBVerifier | None:
    """Build a PCCBVerifier from the manifest's trusted issuers' public keys.

    Returns None when no issuer lists ``public_keys`` (``jwks_uri`` is not
    fetched). A malformed key raises ValueError rather than being skipped.
    """
    jwks = [jwk for issuer in trusted_issuers for jwk in getattr(issuer, "public_keys", ())]
    if not jwks:
        return None
    return PCCBVerifier(signer=Ed25519PublicKeyVerifier(jwks))


def mint_boundary_proof(
    signer: Any,
    *,
    action: str,
    target: str,
    parameters: Mapping[str, Any],
    audience: str,
    subject: str = "agent",
    tenant_id: str = "default",
    issuer_id: str = "actenon-permit",
    ttl_seconds: int = 120,
    now: datetime | None = None,
) -> tuple[ActionIntent, Any]:
    """Mint ``(intent, pccb)`` for one exact request to a protected route.

    ``parameters`` are the values the route's manifest mapping extracts from
    the request; ``audience`` is the boundary's audience. Send the result
    with ``proof_headers()``. This is the issuer side: call it only after
    your own policy decision allowed the action.
    """
    issued = now or datetime.now(UTC)
    intent = ActionIntent(
        intent_id=f"act_{uuid4().hex[:16]}",
        issued_at=issued,
        expires_at=issued + timedelta(seconds=ttl_seconds),
        tenant=TenantRef(tenant_id=tenant_id),
        requester=PartyRef(type="agent", id=subject),
        action=ActionSpec(
            name=action, capability=action, parameters=canonical_parameters(parameters)
        ),
        target=TargetRef(resource_type="resource", resource_id=target),
        metadata={"execution_mode": "resource_owned"},
    )
    decision = PolicyDecision(
        outcome="allow",
        summary="allowed by issuer policy",
        rule_evaluations=(
            RuleEvaluation(
                rule_id="boundary-issuer",
                outcome="allow",
                reason_code="ALLOWED",
                summary="allowed by issuer policy",
            ),
        ),
    )
    context = DynamicContextInput(
        request_id=f"req_{uuid4().hex[:8]}",
        audience=parse_audience(audience),
        scope_capabilities=(action,),
        now=issued,
        max_ttl_seconds=ttl_seconds,
    )
    pccb = PCCBMinter(signer=signer, issuer=PartyRef(type="service", id=issuer_id)).mint(
        intent, decision, context
    )
    return intent, pccb


def proof_headers(
    intent: ActionIntent, pccb: Any, *, proof_header: str = "X-Actenon-Proof"
) -> dict[str, str]:
    """The request headers that carry a boundary proof."""
    return {
        proof_header: encode_token(pccb.to_dict()),
        INTENT_HEADER: encode_token(intent.to_dict()),
    }


__all__ = [
    "INTENT_HEADER",
    "Ed25519PublicKeyVerifier",
    "canonical_parameters",
    "decode_token",
    "encode_token",
    "mint_boundary_proof",
    "parse_audience",
    "proof_headers",
    "trust_root_from_issuers",
]
