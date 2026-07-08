"""Actenon-Permit domain model.

Four objects: Grant (the capability), Action (the attempt), Decision (the
outcome), and the supporting Scope/Budget/Rate types. Grants are signed and
attenuable — an agent can derive a weaker sub-grant, never a stronger one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Signing key handling
# ---------------------------------------------------------------------------

_DEV_KEY: str | None = None
_WARNED_ABOUT_DEV_KEY = False


def _get_signing_key() -> bytes:
    """Return the HMAC signing key.

    Reads ``ACTENON_SIGNING_KEY`` from the environment. If unset, generates a
    random dev key for the lifetime of the process and warns once. The dev
    key is useful for local demos but means grants do not survive a restart.
    """
    global _DEV_KEY, _WARNED_ABOUT_DEV_KEY
    env_val = os.environ.get("ACTENON_SIGNING_KEY", "").strip()
    if env_val:
        return env_val.encode("utf-8")
    if _DEV_KEY is None:
        _DEV_KEY = secrets.token_hex(32)
    if not _WARNED_ABOUT_DEV_KEY:
        import sys

        print(
            "[actenon-permit] WARNING: ACTENON_SIGNING_KEY is not set. "
            "Using a generated dev key — grants will not validate after "
            "this process exits. Set ACTENON_SIGNING_KEY in production.",
            file=sys.stderr,
        )
        _WARNED_ABOUT_DEV_KEY = True
    return _DEV_KEY.encode("utf-8")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON for signing/hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sign(payload: dict[str, Any]) -> str:
    """HMAC-SHA256 hex digest over canonical JSON of ``payload``."""
    return hmac.new(_get_signing_key(), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(payload: dict[str, Any], signature: str) -> bool:
    expected = sign(payload)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# ---------------------------------------------------------------------------
# Supporting types
# ---------------------------------------------------------------------------


class Scopes(BaseModel):
    """Allowed and denied action patterns. Glob-style (``shell.*``)."""

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class Budget(BaseModel):
    currency: str = "USD"
    limit: float = 0.0
    remaining: float = 0.0

    @field_validator("limit", "remaining")
    @classmethod
    def _non_negative(cls, v: float) -> float:
        if v < 0:
            raise ValueError("budget values must be non-negative")
        return v


class Rate(BaseModel):
    max: int = 0  # 0 means "no rate limit"
    per_seconds: int = 60


# ---------------------------------------------------------------------------
# Core objects
# ---------------------------------------------------------------------------


class Grant(BaseModel):
    """A signed, scoped, expiring capability issued to an agent."""

    id: str = Field(default_factory=lambda: f"grant_{uuid.uuid4().hex[:16]}")
    agent_id: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    scopes: Scopes = Field(default_factory=Scopes)
    budget: Budget = Field(default_factory=Budget)
    rate: Rate = Field(default_factory=Rate)
    approval_rules: list[str] = Field(default_factory=list)
    status: GrantStatus = GrantStatus.ACTIVE
    signature: str = ""

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def _signing_payload(self) -> dict[str, Any]:
        """Return the dict that gets signed — everything except the signature itself."""
        d = self.model_dump(mode="json")
        d.pop("signature", None)
        return d

    def sign(self) -> Grant:
        """Compute and attach the HMAC signature. Returns self for chaining."""
        self.signature = sign(self._signing_payload())
        return self

    def verify(self) -> bool:
        """True iff the signature matches the current contents."""
        if not self.signature:
            return False
        return verify_signature(self._signing_payload(), self.signature)

    # ------------------------------------------------------------------
    # Attenuation
    # ------------------------------------------------------------------

    def attenuate(
        self,
        *,
        agent_id: str | None = None,
        expires_at: datetime | None = None,
        scopes_allow: list[str] | None = None,
        scopes_deny: list[str] | None = None,
        budget_limit: float | None = None,
        rate_max: int | None = None,
        rate_per_seconds: int | None = None,
        extra_approval_rules: list[str] | None = None,
    ) -> Grant:
        """Return a NEW grant that is equal-or-weaker than this one.

        Attenuation rules (any attempt to widen is rejected with ValueError):
        - ``expires_at`` must be <= this grant's expires_at
        - ``scopes_allow`` must be a subset of this grant's allow list
        - ``scopes_deny`` may only add entries (union), never remove
        - ``budget_limit`` must be <= this grant's remaining budget
        - ``rate_max`` must be <= this grant's rate.max
        - ``rate_per_seconds`` must be >= this grant's rate.per_seconds
        - ``extra_approval_rules`` may only add rules
        """
        now = datetime.now(UTC)

        new_expires = expires_at or self.expires_at
        if new_expires > self.expires_at:
            raise ValueError("attenuation cannot extend expiry")

        new_allow = list(scopes_allow) if scopes_allow is not None else list(self.scopes.allow)
        if not set(new_allow).issubset(set(self.scopes.allow)):
            raise ValueError("attenuation cannot widen allow scopes")

        new_deny = set(self.scopes.deny)
        if scopes_deny is not None:
            new_deny |= set(scopes_deny)
        new_deny_list = sorted(new_deny)

        new_limit = budget_limit if budget_limit is not None else self.budget.remaining
        if new_limit > self.budget.remaining:
            raise ValueError("attenuation cannot increase budget")
        new_remaining = min(new_limit, self.budget.remaining)

        new_rate_max = rate_max if rate_max is not None else self.rate.max
        if self.rate.max > 0 and new_rate_max > self.rate.max:
            raise ValueError("attenuation cannot raise rate.max")

        new_rate_per = rate_per_seconds if rate_per_seconds is not None else self.rate.per_seconds
        if new_rate_per < self.rate.per_seconds:
            raise ValueError("attenuation cannot shorten rate window")

        new_rules = list(self.approval_rules)
        if extra_approval_rules:
            for r in extra_approval_rules:
                if r not in new_rules:
                    new_rules.append(r)

        child = Grant(
            id=f"grant_{uuid.uuid4().hex[:16]}",
            agent_id=agent_id or f"{self.agent_id}+child",
            issued_at=now,
            expires_at=new_expires,
            scopes=Scopes(allow=new_allow, deny=new_deny_list),
            budget=Budget(
                currency=self.budget.currency,
                limit=new_limit,
                remaining=new_remaining,
            ),
            rate=Rate(max=new_rate_max, per_seconds=new_rate_per),
            approval_rules=new_rules,
            status=GrantStatus.ACTIVE,
        )
        child.sign()
        return child


class Action(BaseModel):
    """A single attempted action by an agent."""

    action_id: str = Field(default_factory=lambda: f"act_{uuid.uuid4().hex[:16]}")
    grant_id: str
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    type: str  # e.g. "payment.refund", "email.send", "shell.exec"
    target: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    est_cost: float | None = None


class Decision(BaseModel):
    """The outcome of running an Action through the PDP."""

    outcome: DecisionOutcome
    reason: str
    rule_matched: str | None = None
    state_delta: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Small helpers used across the package
# ---------------------------------------------------------------------------


def parse_duration(s: str | int | float) -> int:
    """Parse a human duration string into seconds.

    Accepts ``"1h"``, ``"30m"``, ``"45s"``, ``"2d"``, or a bare integer
    (interpreted as seconds). Raises ValueError on anything else.
    """
    if isinstance(s, (int, float)):
        return int(s)
    s = str(s).strip().lower()
    if not s:
        raise ValueError("empty duration")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s[-1] in units:
        n = float(s[:-1])
        return int(n * units[s[-1]])
    # bare integer-as-string
    return int(s)


def parse_duration_to_timedelta(s: str | int | float) -> timedelta:
    return timedelta(seconds=parse_duration(s))
