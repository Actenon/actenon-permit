"""Cross-language grant-token vectors (ts-sdk/tests/vectors/grant_tokens.json).

The same file is verified by the TypeScript SDK's tests. v1 tokens come from
the released actenon-permit 1.4.0; v2 from the 2.0.0 candidate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from actenon_permit import grant_to_token, token_to_grant
from actenon_permit.token import TokenError

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "ts-sdk" / "tests" / "vectors" / "grant_tokens.json").read_text(encoding="utf-8")
)


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", VECTORS["signing_key"])


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["name"])
def test_valid_tokens_verify(vector):
    grant = token_to_grant(vector["token"])
    assert grant.id == vector["grant_id"]
    assert grant.agent_id == vector["agent_id"]


@pytest.mark.parametrize("vector", VECTORS["tampered"], ids=lambda v: v["name"])
def test_tampered_tokens_refused(vector):
    with pytest.raises(TokenError):
        token_to_grant(vector["token"])


def _vector(name):
    return next(v for v in VECTORS["valid"] if v["name"] == name)


def test_remint_v1_as_v2_requires_resigning():
    # CHANGELOG 2.0.0 migration: a v1 grant carries a signature over the
    # ASCII-escaped encoding. Re-encoding it without re-signing yields a v2
    # token that fails closed for non-ASCII content; re-signing fixes it.
    grant = token_to_grant(_vector("v1_non_ascii")["token"])
    with pytest.raises(TokenError):
        token_to_grant(grant_to_token(grant))
    grant.sign()
    assert token_to_grant(grant_to_token(grant)).id == "grant_non_ascii"
