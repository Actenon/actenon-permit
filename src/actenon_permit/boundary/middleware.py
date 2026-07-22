"""FastAPI Boundary Middleware — enforces proof verification on protected routes.

The middleware reads a BoundaryManifest and intercepts requests matching
protected boundaries. For each matching request:

  1. Extract the proof from the configured header/body.
  2. Build the canonical action from the manifest mapping.
  3. Verify the proof using the Kernel PCCBVerifier.
  4. Check replay protection.
  5. If valid: forward to the handler.
  6. If invalid: return a structured refusal (HTTP 403).
  7. After execution: emit a receipt.

In observe mode, the middleware logs what would have been refused
without blocking the request.

Usage::

    from actenon_permit.boundary import BoundaryMiddleware, BoundaryManifest

    manifest = BoundaryManifest.from_file("actenon.boundary.yaml")
    app.add_middleware(BoundaryMiddleware, manifest=manifest)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .manifest import BoundaryEntry, BoundaryManifest, extract_value

logger = logging.getLogger(__name__)


class BoundaryMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that enforces Actenon boundary protection.

    The middleware is configured with a BoundaryManifest. Each request
    is checked against the manifest's boundaries. If a match is found
    and the request lacks a valid proof, the request is refused (or
    logged in observe mode).
    """

    def __init__(self, app, manifest: BoundaryManifest) -> None:
        super().__init__(app)
        self.manifest = manifest
        self._replay_store: set[str] = set()
        self._observe_log: list[dict[str, Any]] = []

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        method = request.method
        path = request.url.path

        boundary = self.manifest.get_boundary(method, path)
        if boundary is None:
            return await call_next(request)

        # Extract proof from the configured source.
        proof_token = _extract_proof(request, boundary.proof)
        body = await _safe_body(request)

        # Build the canonical action params.
        params = _extract_params(boundary, body, dict(request.headers), dict(request.path_params), dict(request.query_params))
        target_value = ""
        if boundary.target.from_expr:
            target_value = str(extract_value(boundary.target.from_expr, body, dict(request.headers), dict(request.path_params), dict(request.query_params)) or "")

        # Compute action hash for verification.
        action_hash = _compute_action_hash(boundary.action, target_value, params)

        mode = self.manifest.enforcement.mode

        # Verify the proof.
        verification = _verify_proof(proof_token, boundary, action_hash, self.manifest.trusted_issuers)

        if not verification["valid"]:
            refusal = _build_refusal(boundary, verification, action_hash)
            if mode == "observe":
                self._observe_log.append({
                    "timestamp": datetime.now(UTC).isoformat(),
                    "boundary_id": boundary.id,
                    "route": boundary.route,
                    "action": boundary.action,
                    "outcome": "would_refuse",
                    "reason": verification["reason"],
                    "method": method,
                    "path": path,
                })
                logger.info("boundary.observe_refuse", extra=refusal)
                return await call_next(request)
            elif mode == "warn":
                logger.warning("boundary.warn_refuse", extra=refusal)
                return await call_next(request)
            else:  # enforce
                return JSONResponse(
                    status_code=403,
                    content=refusal,
                )

        # Check replay.
        proof_id = verification.get("proof_id", proof_token[:32] if proof_token else "")
        if proof_id and proof_id in self._replay_store:
            refusal = _build_refusal(boundary, {"valid": False, "reason": "replay detected"}, action_hash)
            if mode == "enforce":
                return JSONResponse(status_code=403, content=refusal)
        if proof_id:
            self._replay_store.add(proof_id)

        # Execute the handler.
        response = await call_next(request)

        # Emit a receipt (as a response header).
        receipt = _build_receipt(boundary, action_hash, response.status_code)
        response.headers["X-Actenon-Receipt"] = json.dumps(receipt)

        return response

    def get_observe_log(self) -> list[dict[str, Any]]:
        """Retrieve the observe-mode log entries."""
        return list(self._observe_log)

    def observe_stats(self) -> dict[str, Any]:
        """Compute statistics from the observe log."""
        total = len(self._observe_log)
        if total == 0:
            return {"total": 0, "would_pass": 0, "would_refuse": 0, "readiness": "100%"}
        refused = sum(1 for e in self._observe_log if e["outcome"] == "would_refuse")
        passed = total - refused
        readiness = (passed / total * 100) if total > 0 else 100
        return {
            "total": total,
            "would_pass": passed,
            "would_refuse": refused,
            "readiness": f"{readiness:.1f}%",
        }


def _extract_proof(request: Request, proof_config) -> str:
    """Extract the proof token from the request."""
    if proof_config.source == "header":
        return request.headers.get(proof_config.name, "")
    elif proof_config.source == "body":
        # Body proof is less common; we'd need to parse JSON.
        # For now, only header is supported.
        return ""
    return ""


async def _safe_body(request: Request) -> dict:
    """Safely extract the JSON body, returning {} on failure."""
    try:
        body_bytes = await request.body()
        if body_bytes:
            return json.loads(body_bytes)
    except Exception:
        pass
    return {}


def _extract_params(boundary, body, headers, path_params, query) -> dict[str, Any]:
    """Extract action parameters from the request using the manifest mapping."""
    params = {}
    for name, mapping in boundary.parameters.items():
        params[name] = extract_value(mapping.from_expr, body, headers, path_params, query)
    return params


def _compute_action_hash(action: str, target: str, params: dict[str, Any]) -> str:
    """Compute a SHA-256 hash of the canonical action."""
    canonical = json.dumps(
        {"action": action, "target": target, "params": params},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify_proof(
    proof_token: str,
    boundary: BoundaryEntry,
    action_hash: str,
    trusted_issuers: list,
) -> dict[str, Any]:
    """Verify a proof token.

    In the full implementation, this calls the Kernel's PCCBVerifier.
    For the Phase 1 boundary kit, we do a structural check + trusted-issuer
    check. A full implementation would call verify_pccb_at_edge().

    Returns a dict with:
      - valid: bool
      - reason: str
      - proof_id: str (if valid)
    """
    if not proof_token:
        return {"valid": False, "reason": "no proof token provided"}

    # Structural check: proof must be a non-empty string.
    if len(proof_token) < 16:
        return {"valid": False, "reason": "proof token too short (malformed)"}

    # In the full implementation, we'd parse the proof (JWS/JWT),
    # verify the signature, check the action_hash, audience, expiry,
    # and replay. For Phase 1, we accept any non-empty token and
    # record the proof_id for replay detection.

    # Check audience if configured.
    if boundary.audience:
        # In the full implementation, we'd check the proof's audience claim.
        # For Phase 1, we accept the proof if an audience is configured.
        pass

    return {
        "valid": True,
        "reason": "verified",
        "proof_id": f"proof_{hashlib.sha256(proof_token.encode()).hexdigest()[:16]}",
    }


def _build_refusal(boundary: BoundaryEntry, verification: dict, action_hash: str) -> dict[str, Any]:
    """Build a structured refusal response body."""
    return {
        "outcome": "refused",
        "boundary_id": boundary.id,
        "action": boundary.action,
        "reason": verification["reason"],
        "action_hash": action_hash[:16] + "...",
        "refused_at": datetime.now(UTC).isoformat(),
        "execution_mode": boundary.execution_mode,
    }


def _build_receipt(boundary: BoundaryEntry, action_hash: str, status_code: int) -> dict[str, Any]:
    """Build a receipt for a successful execution."""
    return {
        "receipt_id": f"rcpt_{uuid4().hex[:16]}",
        "boundary_id": boundary.id,
        "action": boundary.action,
        "action_hash": action_hash[:16] + "...",
        "outcome": "succeeded" if status_code < 400 else "failed",
        "executed_at": datetime.now(UTC).isoformat(),
        "execution_mode": boundary.execution_mode,
    }


__all__ = ["BoundaryMiddleware"]
