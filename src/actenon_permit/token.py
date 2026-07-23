"""Actenon-Permit grant token wire format.

A Grant token is a compact, self-contained, signed string representation of a
Grant, suitable for transport in an HTTP header (``X-Actenon-Grant``) or as
an MCP ``_meta`` field. The format is:

    v2.<base64url(canonical_json(signed_grant_dict))>   # post-2.0.0 (current)
    v1.<base64url(json(signed_grant_dict))>             # pre-2.0.0 (deprecated)

The grant dict is the full signed grant (including the ``signature`` field).
Verifiers recompute the HMAC over the dict minus the signature field and
compare. A token is valid iff:

  1. It starts with ``v1.`` or ``v2.``.
  2. The base64url payload decodes to a JSON object.
  3. The JSON object is a valid Grant.
  4. The signature verifies against the verifier's signing key, using the
     canonicaliser appropriate to the token's version prefix.

Tokens are bearer tokens — anyone holding one can present it. Transport
security (TLS, localhost-only, or unix socket) is the deployment's
responsibility. v1's gateway binds to 127.0.0.1 by default.

Versioning and the deprecation window
-------------------------------------
Pre-2.0.0 tokens (``v1.`` prefix) carry signatures computed with Permit's
home-grown canonicaliser (``json.dumps(sort_keys=True, default=str)``).
Post-2.0.0 tokens (``v2.`` prefix) carry signatures computed with
ACTENON-JCS-STRICT-1 (via ``actenon_protocol.canonicalize_json``).

``token_to_grant`` accepts both during the deprecation window. The window
ends with actenon-permit 3.0.0, at which point ``v1.`` tokens will be
rejected. Callers holding long-lived ``v1.`` tokens should re-mint them
with ``grant_to_token`` (which always mints ``v2.`` as of 2.0.0) before
upgrading to 3.0.0.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from .model import (
    Grant,
    _legacy_verify_signature,
    sign,
    verify_signature,
)

# Token format versions. New tokens are always minted as V2.
V1 = "v1"  # pre-2.0.0 wire format; accepted for verification during deprecation window
V2 = "v2"  # post-2.0.0 wire format; signed with ACTENON-JCS-STRICT-1
VERSION = V2  # the version this code MINTS (token_to_grant accepts both)

_PREFIX_V1 = f"{V1}."
_PREFIX_V2 = f"{V2}."


class TokenError(ValueError):
    """Raised when a token is malformed, expired, or fails signature verification."""


def grant_to_token(grant: Grant) -> str:
    """Encode a signed Grant as a compact bearer token.

    The grant MUST already be signed (``grant.sign()`` or ``compile_policy``).

    Always mints a ``v2.`` token (signed with ACTENON-JCS-STRICT-1) as of
    actenon-permit 2.0.0. Pre-2.0.0 ``v1.`` tokens are still accepted by
    ``token_to_grant`` during the deprecation window (ends with 3.0.0).
    """
    if not grant.signature:
        raise TokenError("grant is not signed — call grant.sign() first")
    payload = grant.model_dump(mode="json")
    # v2 tokens use the ACTENON-JCS-STRICT-1 canonicaliser for the wire
    # encoding too (not just the signature). This gives cross-language
    # byte-parity with the TypeScript SDK's JSON.stringify output.
    from actenon_protocol import canonicalize_json

    from .model import _coerce_decimals

    body = canonicalize_json(_coerce_decimals(payload)).encode("utf-8")
    encoded = base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")
    return f"{_PREFIX_V2}{encoded}"


def token_to_grant(token: str, *, verify: bool = True) -> Grant:
    """Decode a bearer token to a Grant.

    If ``verify=True`` (default), the signature is checked against the local
    signing key and a ``TokenError`` is raised on mismatch. If ``verify=False``,
    the signature is checked structurally (present and well-formed) but not
    cryptographically — useful for inspection tooling.

    Accepts both ``v1.`` and ``v2.`` token prefixes during the deprecation
    window (ends with actenon-permit 3.0.0). ``v1.`` tokens are verified
    with the pre-2.0.0 canonicaliser (``_legacy_verify_signature``);
    ``v2.`` tokens are verified with ACTENON-JCS-STRICT-1.
    """
    if not isinstance(token, str):
        raise TokenError("token must be a string")

    # Dispatch on version prefix.
    if token.startswith(_PREFIX_V2):
        version = V2
        encoded = token[len(_PREFIX_V2) :]
    elif token.startswith(_PREFIX_V1):
        version = V1
        encoded = token[len(_PREFIX_V1) :]
    else:
        raise TokenError(f"unsupported token version (expected '{_PREFIX_V1}' or '{_PREFIX_V2}')")

    # Restore padding
    pad = "=" * (-len(encoded) % 4)
    try:
        body = base64.urlsafe_b64decode(encoded + pad)
    except Exception as e:
        raise TokenError(f"invalid base64 payload: {e}") from e
    # body is bytes; json.loads accepts bytes but raises UnicodeDecodeError
    # (a ValueError subclass, NOT JSONDecodeError) if the bytes aren't valid
    # UTF-8. Catch both so malformed tokens don't crash the gateway.
    try:
        payload: dict[str, Any] = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
        raise TokenError(f"invalid JSON payload: {e}") from e
    if not isinstance(payload, dict):
        raise TokenError("invalid grant payload: not a JSON object")
    try:
        grant = Grant.model_validate(payload)
    except Exception as e:
        raise TokenError(f"invalid grant payload: {e}") from e
    if verify:
        signing_payload = {k: v for k, v in payload.items() if k != "signature"}
        if version == V2:
            if not verify_signature(signing_payload, grant.signature):
                raise TokenError(
                    "signature verification failed — token is forged or was "
                    "signed with a different key"
                )
        else:  # V1 — verify with the legacy canonicaliser
            if not _legacy_verify_signature(signing_payload, grant.signature):
                raise TokenError(
                    "signature verification failed (v1 token) — token is "
                    "forged or was signed with a different key"
                )
    return grant


def recompute_signature(payload: dict[str, Any]) -> str:
    """Recompute the HMAC signature for a grant payload dict (public helper).

    Always uses the new (ACTENON-JCS-STRICT-1) canonicaliser. Pre-2.0.0
    tokens that need their legacy signature recomputed should call
    ``actenon_permit.model._legacy_sign`` directly (private API).
    """
    return sign({k: v for k, v in payload.items() if k != "signature"})


__all__ = [
    "V1",
    "V2",
    "VERSION",
    "TokenError",
    "grant_to_token",
    "token_to_grant",
    "recompute_signature",
]
