"""Tests for the v1 grant token wire format."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from actenon_permit import Budget, Grant, GrantStatus, Rate, Scopes, grant_to_token, token_to_grant
from actenon_permit.token import TokenError


def _make_grant() -> Grant:
    g = Grant(
        agent_id="token-test-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"], deny=["shell.*"]),
        budget=Budget(currency="USD", limit=50, remaining=50),
        rate=Rate(max=20, per_seconds=60),
        approval_rules=["email.send"],
        status=GrantStatus.ACTIVE,
    )
    g.sign()
    return g


def test_token_roundtrip():
    g = _make_grant()
    token = grant_to_token(g)
    # As of actenon-permit 2.0.0, new tokens are minted as v2.
    # (signed with ACTENON-JCS-STRICT-1 via actenon_protocol.canonicalize_json).
    # v1. tokens are still accepted by token_to_grant during the deprecation
    # window — see test_token_v1_legacy_token_still_verifies.
    assert token.startswith("v2.")
    decoded = token_to_grant(token, verify=True)
    assert decoded.id == g.id
    assert decoded.agent_id == g.agent_id
    assert decoded.scopes.allow == g.scopes.allow
    assert decoded.signature == g.signature


def test_token_tamper_detection():
    g = _make_grant()
    token = grant_to_token(g)
    # Flip a character in the middle of the base64 payload.
    prefix_len = len("v1.")
    tampered = (
        token[: prefix_len + 10]
        + ("A" if token[prefix_len + 10] != "A" else "B")
        + token[prefix_len + 11 :]
    )
    with pytest.raises(TokenError):
        token_to_grant(tampered, verify=True)


def test_token_wrong_signing_key(monkeypatch):
    # Mint a token with one key, then change the key and try to verify.
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "key-one")

    # Force regeneration of the cached dev key (if any)
    import actenon_permit.model as model_mod

    monkeypatch.setattr(model_mod, "_DEV_KEY", None)
    monkeypatch.setattr(model_mod, "_WARNED_ABOUT_DEV_KEY", False)

    g = _make_grant()
    token = grant_to_token(g)

    # Switch to a different key.
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "key-two-different")
    monkeypatch.setattr(model_mod, "_DEV_KEY", None)
    with pytest.raises(TokenError, match="signature verification failed"):
        token_to_grant(token, verify=True)


def test_token_unsigned_grant_rejected():
    g = _make_grant()
    g.signature = ""
    with pytest.raises(TokenError, match="not signed"):
        grant_to_token(g)


def test_token_bad_version():
    with pytest.raises(TokenError, match="unsupported token version"):
        token_to_grant("v0.something", verify=False)


def test_token_no_verify_skips_crypto():
    g = _make_grant()
    token = grant_to_token(g)
    decoded = token_to_grant(token, verify=False)
    assert decoded.id == g.id


# ===========================================================================
# WO-4: v1 legacy token verification (deprecation window)
# ===========================================================================


def test_token_v1_legacy_token_still_verifies(monkeypatch):
    """WO-4: grant tokens signed under the old (pre-2.0.0) canonicaliser
    must still verify during the deprecation window.

    A v1. token carries a signature computed with _legacy_canonical_json
    (json.dumps + sort_keys + default=str). token_to_grant must accept
    v1. tokens and verify them with _legacy_verify_signature.

    This test mints a v1. token by hand (using the legacy sign path),
    then verifies it round-trips through token_to_grant.
    """
    import base64
    import json

    from actenon_permit.model import _legacy_sign

    monkeypatch.setenv("ACTENON_SIGNING_KEY", "legacy-token-test-key")
    import actenon_permit.model as model_mod

    monkeypatch.setattr(model_mod, "_DEV_KEY", None)
    monkeypatch.setattr(model_mod, "_WARNED_ABOUT_DEV_KEY", False)

    g = _make_grant()
    # Re-sign the grant with the LEGACY canonicaliser to simulate a
    # pre-2.0.0 token.
    payload = g.model_dump(mode="json")
    signing_payload = {k: v for k, v in payload.items() if k != "signature"}
    g.signature = _legacy_sign(signing_payload)

    # Manually construct a v1. token (pre-2.0.0 wire format: json.dumps,
    # NOT canonicalize_json).
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")
    v1_token = f"v1.{encoded}"

    # token_to_grant must accept the v1. token and verify it with the
    # legacy canonicaliser.
    decoded = token_to_grant(v1_token, verify=True)
    assert decoded.id == g.id
    assert decoded.signature == g.signature


def test_token_v2_token_rejected_with_legacy_signature(monkeypatch):
    """WO-4: a v2. token whose signature was computed with the LEGACY
    canonicaliser must FAIL verification when the two canonicalisers
    produce different bytes — the version prefix and the canonicaliser
    must agree.

    This guards against a subtle attack: an attacker takes a v1. token,
    changes the prefix to v2., and re-submits. The v2. verifier uses
    ACTENON-JCS-STRICT-1, which produces a different signature than the
    legacy canonicaliser (for any payload containing non-ASCII, Decimal,
    or other values the two canonicalisers handle differently), so
    verification fails.

    To make the divergence observable, the grant's agent_id contains
    non-ASCII ('café'). The legacy canonicaliser escapes this to
    \\u00e9; ACTENON-JCS-STRICT-1 emits raw UTF-8. Different bytes ->
    different HMAC -> verification fails.
    """
    import base64

    from actenon_protocol import canonicalize_json

    from actenon_permit.model import _legacy_sign

    monkeypatch.setenv("ACTENON_SIGNING_KEY", "version-mismatch-test-key")
    import actenon_permit.model as model_mod

    monkeypatch.setattr(model_mod, "_DEV_KEY", None)
    monkeypatch.setattr(model_mod, "_WARNED_ABOUT_DEV_KEY", False)

    # Use a grant with non-ASCII in agent_id so the two canonicalisers
    # produce different bytes (legacy escapes to \u00e9, JCS emits raw 'é').
    g = Grant(
        agent_id="café-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=["payment.refund"], deny=["shell.*"]),
        budget=Budget(currency="USD", limit=50, remaining=50),
        rate=Rate(max=20, per_seconds=60),
        approval_rules=["email.send"],
        status=GrantStatus.ACTIVE,
    )
    payload = g.model_dump(mode="json")
    signing_payload = {k: v for k, v in payload.items() if k != "signature"}
    # Sign with LEGACY canonicaliser...
    g.signature = _legacy_sign(signing_payload)
    payload["signature"] = g.signature

    # ...but encode as v2. (using canonicalize_json for the wire format).
    from actenon_permit.model import _coerce_decimals

    body = canonicalize_json(_coerce_decimals(payload)).encode("utf-8")
    encoded = base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")
    mismatched_token = f"v2.{encoded}"

    # Verification must fail: the v2. verifier uses the new canonicaliser,
    # which produces a different signature than the legacy one embedded
    # in this token (because the agent_id 'café-agent' canonicalises
    # differently under the two canonicalisers).
    with pytest.raises(TokenError, match="signature verification failed"):
        token_to_grant(mismatched_token, verify=True)
