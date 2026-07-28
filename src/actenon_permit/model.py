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
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Signing key handling
# ---------------------------------------------------------------------------

_DEV_KEY: str | None = None
_WARNED_ABOUT_DEV_KEY = False
_SUPPRESS_DEV_KEY_WARNING = False


def _default_key_file_path() -> Path:
    """The default location for a persisted dev signing key.

    ``~/.actenon-permit/signing-key`` — user-level, persists across projects
    and process restarts. Created by ``permit init-key``.
    """
    return Path.home() / ".actenon-permit" / "signing-key"


def _load_persisted_key() -> str | None:
    """Load a persisted dev key from disk, if one exists.

    Checks (in order):
      1. ``ACTENON_SIGNING_KEY_FILE`` env var — explicit path override
      2. ``~/.actenon-permit/signing-key`` — default location from ``permit init-key``

    Returns the key as a hex string, or None if no file exists.
    """
    env_path = os.environ.get("ACTENON_SIGNING_KEY_FILE", "").strip()
    candidates = (
        [env_path, str(_default_key_file_path())] if env_path else [str(_default_key_file_path())]
    )
    for p in candidates:
        if not p:
            continue
        try:
            path = Path(p)
            if path.is_file():
                key = path.read_text(encoding="utf-8").strip()
                if key:
                    return key
        except OSError:
            continue
    return None


def suppress_dev_key_warning(suppress: bool = True) -> None:
    """Suppress the 'ACTENON_SIGNING_KEY is not set' warning.

    Used by CLI commands with ``--quiet`` so the warning doesn't pollute
    shell-pipeline output. The warning is a hygiene nudge for interactive
    use; in scripts it's just noise.
    """
    global _SUPPRESS_DEV_KEY_WARNING
    _SUPPRESS_DEV_KEY_WARNING = suppress


def _get_signing_key() -> bytes:
    """Return the HMAC signing key.

    Resolution order:
      1. ``ACTENON_SIGNING_KEY`` env var (production)
      2. ``ACTENON_SIGNING_KEY_FILE`` env var → read key from that file
      3. ``~/.actenon-permit/signing-key`` (created by ``permit init-key``)
      4. Ephemeral in-memory dev key + warning (the demo default)

    The ephemeral key (step 4) is regenerated on every process start, so
    grants minted in one process won't validate in another. Run
    ``permit init-key`` to persist a stable dev key and avoid this.
    """
    global _DEV_KEY, _WARNED_ABOUT_DEV_KEY
    env_val = os.environ.get("ACTENON_SIGNING_KEY", "").strip()
    if env_val:
        return env_val.encode("utf-8")
    persisted = _load_persisted_key()
    if persisted:
        return persisted.encode("utf-8")
    if _DEV_KEY is None:
        _DEV_KEY = secrets.token_hex(32)
    if not _WARNED_ABOUT_DEV_KEY and not _SUPPRESS_DEV_KEY_WARNING:
        import sys

        print(
            "[actenon-permit] WARNING: ACTENON_SIGNING_KEY is not set and no "
            "persisted key was found. Using an EPHEMERAL dev key — grants "
            "will NOT validate after this process exits. "
            "Run `permit init-key` to persist a stable local key, or set "
            "ACTENON_SIGNING_KEY in production.",
            file=sys.stderr,
        )
        _WARNED_ABOUT_DEV_KEY = True
    return _DEV_KEY.encode("utf-8")


def canonical_json(obj: Any) -> str:
    """DEPRECATED: use ``actenon_protocol.canonicalize_json`` directly.

    Retained as an alias for backward compatibility. Delegates to
    ACTENON-JCS-STRICT-1 (RFC 8785 subset, as implemented by
    ``actenon_protocol.canonicalize_json``) as of actenon-permit 2.0.0.

    Migrating callers should ``from actenon_protocol import canonicalize_json``
    and pre-coerce ``Decimal`` themselves. This wrapper exists so the public
    export (see ``actenon_permit/__init__.py``) keeps working for downstream
    consumers without a major-version bump on their side.

    The wrapper applies ``_coerce_decimals`` first, so ``Decimal`` values are
    normalised (via ``Decimal.normalize()``) to a canonical string form
    before canonicalisation. See ``_coerce_decimals`` for details.

    Floats are NOT coerced — they raise ``CanonicalisationError`` from the
    protocol layer. The error message names ACTENON-JCS-STRICT-1 so callers
    know which canonicaliser rejected the input. This is intentional: floats
    in signing payloads are a defect (WO-4 constraint C3); the protocol
    rejects them, and so does this wrapper.

    Returns the canonical JSON as a ``str`` (the protocol canonicaliser
    returns ``str``, not ``bytes``; the WO-4 spec's ``.decode("utf-8")``
    in the example code is therefore a no-op against the actual return
    type and is omitted here).
    """
    from actenon_protocol import canonicalize_json

    return canonicalize_json(_coerce_decimals(obj))


def _coerce_decimals(obj: Any) -> Any:
    """Recursively convert ``Decimal`` to a canonical string for ACTENON-JCS-STRICT-1.

    The protocol canonicaliser (``actenon_protocol.canonicalize_json``)
    rejects ``Decimal`` and ``float`` outright — both raise
    ``CanonicalisationError`` with a message naming ACTENON-JCS-STRICT-1.

    Permit's domain model uses ``Decimal`` for monetary amounts (correct —
    ``Budget.limit`` and ``Budget.remaining`` are ``Decimal``). Before
    delegating to the protocol, this helper walks the payload and converts
    every ``Decimal`` via ``Decimal.normalize()`` then ``str()``.

    ``Decimal.normalize()`` strips trailing zeros and adjusts the exponent
    so numerically equal Decimals produce identical bytes::

        Decimal("50.0").normalize()  == Decimal("5E+1")
        Decimal("50.00").normalize() == Decimal("5E+1")
        str(Decimal("5E+1"))         == "5E+1"

    This is the fix for WO-4 defect (b): previously, ``Decimal("50.0")`` and
    ``Decimal("50.00")`` produced different signing bytes despite being
    numerically equal. They now canonicalise identically.

    Floats are NOT coerced here — they pass through to the protocol
    canonicaliser, which raises ``CanonicalisationError`` with a message
    naming ACTENON-JCS-STRICT-1. This is the fix for WO-4 constraint C3:
    raw floats in signing payloads are a defect, not something to paper
    over with ``str()``.

    Any other unsupported type raises ``TypeError``. The previous
    ``_json_default`` used ``str()`` as a catch-all default, which caused
    type confusion (defect (b)) — that path is gone.
    """
    from decimal import Decimal

    if isinstance(obj, Decimal):
        # normalize() so Decimal("50.0") and Decimal("50.00") produce
        # identical canonical bytes (both normalize to Decimal("5E+1")).
        # str() of that is "5E+1" — ugly but unambiguous and stable.
        return str(obj.normalize())
    if isinstance(obj, bool):
        # bool is a subclass of int but must be checked first; the protocol
        # canonicaliser accepts bool natively (JSON true/false).
        return obj
    if isinstance(obj, (int, str)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {k: _coerce_decimals(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_coerce_decimals(item) for item in obj]
    if isinstance(obj, float):
        # Defer to the protocol's rejection (its error message names
        # ACTENON-JCS-STRICT-1, which is more informative than what we'd
        # produce here).
        return obj
    raise TypeError(
        f"_coerce_decimals: unsupported type {type(obj).__name__!r} for "
        f"ACTENON-JCS-STRICT-1 canonicalisation. Convert to str/int/Decimal "
        f"before signing."
    )


def sign(payload: dict[str, Any]) -> str:
    """HMAC-SHA256 hex digest over canonical JSON of ``payload``."""
    return hmac.new(
        _get_signing_key(), canonical_json(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_signature(payload: dict[str, Any], signature: str) -> bool:
    expected = sign(payload)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Legacy canonicalisation — kept PRIVATE, for ledger chain verification only
# ---------------------------------------------------------------------------

# Prior to 2.0.0, Permit used its own canonicaliser (json.dumps with
# sort_keys=True, separators=(",", ":"), default=str). Ledger entries
# written by <2.0.0 are verified against this function. New entries use
# the ACTENON-JCS-STRICT-1 canonicaliser via canonical_json above.
#
# DO NOT use this for new code. It exists solely so that ledgers written
# before the 2.0.0 cut-over can still be verified. See ledger.py for the
# chain_version discrimination logic.


def _legacy_canonical_json(obj: Any) -> str:
    """Pre-2.0.0 canonical JSON, for verifying legacy ledger entries only.

    Reproduces the exact bytes that ``canonical_json`` produced before the
    2.0.0 cut-over:
      - ``json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_legacy_default)``
      - ``_legacy_default`` coerces Decimal via ``str()`` (the pre-2.0.0 defect (b))

    This is PRIVATE (leading underscore) on purpose. New code must use
    ``canonical_json`` (which delegates to ACTENON-JCS-STRICT-1). Exporting
    this would invite callers to keep using the broken canonicaliser.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_legacy_default)


def _legacy_default(obj: Any) -> Any:
    """Pre-2.0.0 fallback for non-JSON-native types. Decimal -> str(obj)."""
    from decimal import Decimal

    if isinstance(obj, Decimal):
        return str(obj)
    return str(obj)


def _legacy_sign(payload: dict[str, Any]) -> str:
    """HMAC-SHA256 over ``_legacy_canonical_json`` — for verifying pre-2.0.0 tokens.

    Grant tokens minted by actenon-permit <2.0.0 carry signatures computed
    with the old ``canonical_json`` (json.dumps + sort_keys + default=str).
    ``token_to_grant`` must still verify those tokens during the
    deprecation window (see ``token.py`` for the window's stated end).

    This function is PRIVATE (leading underscore). New code must use
    ``sign()``, which delegates to ACTENON-JCS-STRICT-1.
    """
    return hmac.new(
        _get_signing_key(),
        _legacy_canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _legacy_verify_signature(payload: dict[str, Any], signature: str) -> bool:
    """Verify a pre-2.0.0 signature. Companion to ``_legacy_sign``."""
    expected = _legacy_sign(payload)
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
    model_config = ConfigDict(validate_assignment=True)

    currency: str = "USD"
    limit: Decimal = Decimal("0")
    remaining: Decimal = Decimal("0")

    @field_validator("limit", "remaining", mode="before")
    @classmethod
    def _to_decimal(cls, v):
        """Convert float/int/str to Decimal for exact monetary arithmetic.

        This fixes F2: 3 x $0.10 against $0.30 should be 3 ALLOWs, but
        with floats 0.30 - 0.10 - 0.10 = 0.09999999999999998, so the
        third $0.10 was wrongly DENIED.
        """
        if isinstance(v, Decimal):
            return v
        if isinstance(v, float):
            return Decimal(str(v))
        return Decimal(v)

    @field_validator("limit", "remaining")
    @classmethod
    def _non_negative(cls, v: Decimal) -> Decimal:
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
    # ── Phase 7: authority-decision linkage ────────────────────────
    # parent_grant_id records the grant from which this grant was
    # attenuated. This enables revocation cascade: revoking the parent
    # can revoke all children. (Audit finding P-05.)
    parent_grant_id: str | None = None
    # delegation_depth records how many attenuation hops from the root
    # grant. 0 = root grant, 1 = first child, etc. This enables
    # delegation-depth limits. (Phase 7 grant safety.)
    delegation_depth: int = 0

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
        budget_limit: Decimal | float | int | None = None,
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
            parent_grant_id=self.id,
            delegation_depth=self.delegation_depth + 1,
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
    est_cost: Decimal | float | int | None = None


class Decision(BaseModel):
    """The outcome of running an Action through the PDP.

    ``failure_code`` is the structured, stable enum imported from the kernel
    (actenon.outcomes.FailureCode). It is set at the SAME branch where
    ``reason`` is set — never reconstructed or parsed from ``reason``.
    The ledger records it as a first-class field (not derived from prose).
    """

    outcome: DecisionOutcome
    reason: str
    rule_matched: str | None = None
    state_delta: dict[str, Any] = Field(default_factory=dict)
    failure_code: str | None = None  # FailureCode enum value, imported from kernel


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
