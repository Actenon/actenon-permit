"""Actenon-Permit policy compiler.

Turns a declarative YAML/dict policy into a signed Grant. The policy format
is intentionally minimal and declarative — no Turing-complete DSL. (OPA/Rego
is an explicit non-goal for v0 and is documented as a later escape hatch.)

Example policy (YAML)::

    agent: refund-bot
    ttl: 1h
    budget: { currency: USD, limit: 50 }
    scopes:
      allow: [ payment.refund, email.send ]
      deny:  [ payment.charge, shell.* ]
    rate: { max: 20, per: 1m }
    approval: { require_human: [ email.send ] }
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .model import (
    Budget,
    Grant,
    GrantStatus,
    Rate,
    Scopes,
    parse_duration,
)


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load a YAML policy file from disk."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise PolicyError(f"policy file {path} did not parse to a dict")
    return data


def compile_policy(policy: dict[str, Any], *, agent_id: str | None = None) -> Grant:
    """Compile a policy dict into a signed, active Grant.

    Accepted keys (all optional except ``agent``/``agent_id``):

    - ``agent`` or ``agent_id``: the principal this grant is issued to
    - ``ttl``: human duration (``"1h"``, ``"30m"``) — added to ``issued_at``
    - ``expires_at``: explicit ISO datetime (overrides ttl)
    - ``budget``: ``{currency, limit}`` (remaining defaults to limit)
    - ``scopes``: ``{allow: [...], deny: [...]}``
    - ``rate``: ``{max, per}`` (``per`` is a human duration)
    - ``approval``: ``{require_human: [...]}`` — list of rules
    """
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a dict")

    agent = agent_id or policy.get("agent") or policy.get("agent_id")
    if not agent:
        raise PolicyError("policy must specify 'agent' (or 'agent_id')")

    now = datetime.now(UTC)

    expires_at: datetime
    if "expires_at" in policy:
        v = policy["expires_at"]
        expires_at = v if isinstance(v, datetime) else datetime.fromisoformat(str(v))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
    else:
        ttl = policy.get("ttl", "1h")
        expires_at = now + timedelta(seconds=parse_duration(ttl))

    # Budget
    budget_dict = policy.get("budget") or {}
    currency = str(budget_dict.get("currency", "USD"))
    limit = float(budget_dict.get("limit", 0.0))
    remaining = float(budget_dict.get("remaining", limit))
    budget = Budget(currency=currency, limit=limit, remaining=remaining)

    # Scopes
    scopes_dict = policy.get("scopes") or {}
    allow = list(scopes_dict.get("allow") or [])
    deny = list(scopes_dict.get("deny") or [])
    if not isinstance(allow, list) or not isinstance(deny, list):
        raise PolicyError("scopes.allow and scopes.deny must be lists")
    scopes = Scopes(allow=allow, deny=deny)

    # Rate
    rate_dict = policy.get("rate") or {}
    rate_max = int(rate_dict.get("max", 0))
    rate_per_raw = rate_dict.get("per", 60)
    rate_per_seconds = parse_duration(rate_per_raw)
    rate = Rate(max=rate_max, per_seconds=rate_per_seconds)

    # Approval rules (flat list of strings)
    approval_dict = policy.get("approval") or {}
    approval_rules = list(approval_dict.get("require_human") or [])
    if not isinstance(approval_rules, list):
        raise PolicyError("approval.require_human must be a list")

    grant = Grant(
        agent_id=str(agent),
        issued_at=now,
        expires_at=expires_at,
        scopes=scopes,
        budget=budget,
        rate=rate,
        approval_rules=approval_rules,
        status=GrantStatus.ACTIVE,
    )
    grant.sign()
    return grant
