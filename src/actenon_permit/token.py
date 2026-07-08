"""Actenon-Permit grant token wire format.

A Grant token is a compact, self-contained, signed string representation of a
Grant, suitable for transport in an HTTP header (``X-Actenon-Grant``) or as
an MCP ``_meta`` field. The format is:

    v1.<base64url(canonical_json(signed_grant_dict))>

The grant dict is the full signed grant (including the ``signature`` field).
Verifiers recompute the HMAC over the dict minus the signature field and
compare. A token is valid iff:

  1. It starts with ``v1.``.
  2. The base64url payload decodes to a JSON object.
  3. The JSON object is a valid Grant.
  4. The signature verifies against the verifier's signing key.

Tokens are bearer tokens — anyone holding one can present it. Transport
security (TLS, localhost-only, or unix socket) is the deployment's
responsibility. v1's gateway binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from .model import Grant, sign, verify_signature

VERSION = "v1"
_PREFIX = f"{VERSION}."


class TokenError(ValueError):
    """Raised when a token is malformed, expired, or fails signature verification."""


def grant_to_token(grant: Grant) -> str:
    """Encode a signed Grant as a compact bearer token.

    The grant MUST already be signed (``grant.sign()`` or ``compile_policy``).
    """
    if not grant.signature:
        raise TokenError("grant is not signed — call grant.sign() first")
    payload = grant.model_dump(mode="json")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")
    return f"{_PREFIX}{encoded}"


def token_to_grant(token: str, *, verify: bool = True) -> Grant:
    """Decode a bearer token to a Grant.

    If ``verify=True`` (default), the signature is checked against the local
    signing key and a ``TokenError`` is raised on mismatch. If ``verify=False``,
    the signature is checked structurally (present and well-formed) but not
    cryptographically — useful for inspection tooling.
    """
    if not isinstance(token, str):
        raise TokenError("token must be a string")
    if not token.startswith(_PREFIX):
        raise TokenError(f"unsupported token version (expected '{_PREFIX}')")
    encoded = token[len(_PREFIX):]
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
        if not verify_signature(signing_payload, grant.signature):
            raise TokenError("signature verification failed — token is forged or was signed with a different key")
    return grant


def recompute_signature(payload: dict[str, Any]) -> str:
    """Recompute the HMAC signature for a grant payload dict (public helper)."""
    return sign({k: v for k, v in payload.items() if k != "signature"})


__all__ = ["VERSION", "TokenError", "grant_to_token", "token_to_grant", "recompute_signature"]
