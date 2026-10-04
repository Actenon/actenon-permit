"""Revocation source for Permit-minted proofs at a protected edge.

Every PCCB Permit mints on a kernel that can sign extensions carries
``extensions.authority = {"issuer", "grant_id", "revocable": true}``.
actenon-protocol protocol/13-edge-binding.md E5 requires the edge to consult
the authority's revocation source before executing. Airlock passes a
``StoreRevocationChecker`` as the kernel ``revocation_checker`` (for
``ActenonGate``).

The checker answers "not revoked" only for a grant this store knows that is
neither REVOKED nor EXPIRED (by status or by ``expires_at``) and has no such
ancestor. EXHAUSTED is not revocation: budget is enforced by the PDP's
reservation when the proof is minted. It raises when the authority
reference is not one of ours or the store cannot be read, which the kernel
treats as "status unknown" and refuses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .model import GrantStatus

PERMIT_ISSUER = "service:actenon-permit"


class RevocationLookupError(RuntimeError):
    """The authority reference cannot be resolved against this store."""


class StoreRevocationChecker:
    def __init__(self, store: Any, *, issuer: str = PERMIT_ISSUER, max_depth: int = 64) -> None:
        self._store = store
        self._issuer = issuer
        self._max_depth = max_depth

    def __call__(self, pccb: Any, context: Any) -> bool:
        authority = (getattr(pccb, "extensions", None) or {}).get("authority")
        if not isinstance(authority, dict):
            raise RevocationLookupError("proof carries no Permit authority reference")
        if authority.get("issuer") != self._issuer:
            raise RevocationLookupError("authority reference names a different issuer")
        grant_id = authority.get("grant_id")
        if not isinstance(grant_id, str) or not grant_id:
            raise RevocationLookupError("authority reference has no grant_id")
        now = datetime.now(UTC)
        seen: set[str] = set()
        current: str | None = grant_id
        while current is not None:
            if current in seen or len(seen) >= self._max_depth:
                raise RevocationLookupError("grant ancestry is cyclic or too deep")
            seen.add(current)
            grant = self._store.get_grant(current)
            if grant is None:
                raise RevocationLookupError(f"grant {current} is unknown to this store")
            if grant.status in (GrantStatus.REVOKED, GrantStatus.EXPIRED) or grant.expires_at <= now:
                return False
            current = grant.parent_grant_id
        return True


__all__ = ["PERMIT_ISSUER", "RevocationLookupError", "StoreRevocationChecker"]
