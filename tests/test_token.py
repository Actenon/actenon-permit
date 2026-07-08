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
    assert token.startswith("v1.")
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
    tampered = token[:prefix_len + 10] + ("A" if token[prefix_len + 10] != "A" else "B") + token[prefix_len + 11:]
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
