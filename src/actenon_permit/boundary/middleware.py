"""FastAPI Boundary Middleware — enforces proof verification on protected routes.

The middleware reads a BoundaryManifest and intercepts requests matching
protected boundaries. For each matching request:

  1. Extract the proof (PCCB) and the Action Intent from the request.
  2. Extract the target and parameters via the manifest mapping, and
     require the intent to match them exactly.
  3. Verify the proof against the intent and the boundary's audience with
     the Kernel (signature, time window, action hash) and a trust root.
  4. Check replay protection (single use).
  5. If valid: forward to the handler.
  6. If invalid: return a structured refusal (HTTP 403).
  7. After execution: emit a receipt.

Every missing piece (proof, intent, audience, trust root, kernel verifier)
refuses. In observe mode, the middleware logs what would have been refused
without blocking the request.

Usage::

    from actenon_permit.boundary import BoundaryMiddleware, BoundaryManifest

    manifest = BoundaryManifest.from_file("actenon.boundary.yaml")
    # Trust root: trusted_issuers[].public_keys in the manifest, or
    # pccb_verifier=PCCBVerifier(signer=...) here.
    app.add_middleware(BoundaryMiddleware, manifest=manifest)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .manifest import BoundaryEntry, BoundaryManifest, extract_value
from .proofs import INTENT_HEADER, canonical_parameters, decode_token, parse_audience

logger = logging.getLogger(__name__)


class BoundaryMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that enforces Actenon boundary protection.

    The middleware is configured with a BoundaryManifest. Each request
    matching a boundary must carry a kernel PCCB (``X-Actenon-Proof``) and
    the exact Action Intent it was minted for (``X-Actenon-Intent``); see
    ``actenon_permit.boundary.proofs`` for the wire format. The request is
    refused (or logged, in observe/warn mode) unless:

      * the intent's action is the boundary's action, its target is the
        target the request carries, and its parameters equal every mapped
        parameter the request carries;
      * the kernel verifies the PCCB against that intent and the boundary's
        audience with the configured trust root (signature, time window,
        action hash, audience);
      * the proof has not been used before (single use, per process).

    The trust root is ``pccb_verifier`` (a kernel ``PCCBVerifier``) or, if
    omitted, the Ed25519 ``public_keys`` of the manifest's trusted issuers.
    With no trust root, no audience, or no intent, every request is refused.
    ``verifier`` injects a kernel ``BoundaryVerifier`` instead; it must be
    one that binds proofs to intents (kernel releases that do not are
    refused rather than trusted).
    """

    def __init__(
        self,
        app,
        manifest: BoundaryManifest,
        *,
        verifier: Any = None,
        pccb_verifier: Any = None,
    ) -> None:
        super().__init__(app)
        self.manifest = manifest
        self._observe_log: list[dict[str, Any]] = []
        self._explicit_verifier = verifier
        self._trust_root = pccb_verifier
        if self._trust_root is None and verifier is None:
            from .proofs import trust_root_from_issuers

            self._trust_root = trust_root_from_issuers(manifest.trusted_issuers)
        self._kernel_verifier: Any = None
        self._replay_lock = threading.Lock()
        self._replay_keys: set[str] = set()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        method = request.method
        path = request.url.path

        boundary = self.manifest.get_boundary(method, path)
        if boundary is None:
            return await call_next(request)

        proof_token = _extract_proof(request, boundary.proof)
        body = await _safe_body(request)
        headers = dict(request.headers)
        # Routing has not run yet inside middleware, so request.path_params is
        # empty here; derive them from the boundary's route pattern.
        path_params = _path_params(boundary.path, path)
        query = dict(request.query_params)

        params = _extract_params(boundary, body, headers, path_params, query)
        target_value: Any = None
        if boundary.target.from_expr:
            target_value = extract_value(boundary.target.from_expr, body, headers, path_params, query)

        # Display digest for refusals/receipts (not the kernel action hash).
        action_hash = _compute_action_hash(boundary.action, str(target_value or ""), params)

        mode = self.manifest.enforcement.mode

        verification = self._verify(
            boundary,
            proof_token,
            request.headers.get(INTENT_HEADER, ""),
            target_value,
            params,
        )

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
            else:  # enforce (and any unknown mode): refuse
                return JSONResponse(status_code=403, content=refusal)

        # Execute the handler.
        response = await call_next(request)

        # Emit a receipt (as a response header).
        receipt = _build_receipt(boundary, action_hash, response.status_code)
        receipt["proof_id"] = verification.get("proof_id")
        response.headers["X-Actenon-Receipt"] = json.dumps(receipt)

        return response

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def _verify(
        self,
        boundary: BoundaryEntry,
        proof_token: str,
        intent_token: str,
        target_value: Any,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Return ``{"valid": bool, "reason": str, ...}``. Never raises."""
        try:
            return self._verify_inner(boundary, proof_token, intent_token, target_value, params)
        except Exception:  # noqa: BLE001 - never fail open
            logger.exception("boundary.verification_error")
            return _invalid("boundary verification failed unexpectedly", "OUTCOME_UNKNOWN")

    def _verify_inner(
        self,
        boundary: BoundaryEntry,
        proof_token: str,
        intent_token: str,
        target_value: Any,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        if not proof_token:
            return _invalid("no proof token provided", "PROOF_MISSING")
        if not boundary.audience:
            return _invalid("boundary has no audience configured; refusing", "AUDIENCE_REQUIRED")
        if self._trust_root is None and self._explicit_verifier is None:
            return _invalid(
                "no trust root configured (pass pccb_verifier= or list the issuer's "
                "public_keys under trusted_issuers); refusing",
                "ISSUER_UNTRUSTED",
            )
        if not intent_token:
            return _invalid(f"no Action Intent provided ({INTENT_HEADER} header)", "INTENT_MISSING")

        from actenon.models.contracts import ActionIntent

        try:
            intent = ActionIntent.from_dict(decode_token(intent_token))
        except Exception:  # noqa: BLE001
            return _invalid("the Action Intent is malformed", "MALFORMED_REQUEST")

        # Bind the intent to THIS request. The kernel checks the proof
        # against the intent; only the boundary can check the intent
        # against what the request actually asks the handler to do.
        if intent.action.name != boundary.action:
            return _invalid("the intent's action does not match this boundary's action", "ACTION_MISMATCH")
        if boundary.target.from_expr:
            if target_value is None or target_value == "":
                return _invalid("the request carries no target for this boundary", "TARGET_MISSING")
            if intent.target.resource_id != str(target_value):
                return _invalid("the intent's target does not match this request", "TARGET_MISMATCH")
        if dict(intent.action.parameters) != canonical_parameters(params):
            return _invalid("the intent's parameters do not match this request", "PARAMETER_MISMATCH")

        kernel_api = _kernel_boundary_api()
        if self._explicit_verifier is not None or kernel_api is not None:
            if kernel_api is None:
                return _invalid(
                    "the installed actenon-kernel BoundaryVerifier cannot bind proofs to "
                    "intents; pass pccb_verifier= instead of verifier=",
                    "VERIFIER_UNSUPPORTED",
                )
            verifier_cls, request_cls = kernel_api
            verifier = self._explicit_verifier
            if verifier is None:
                if self._kernel_verifier is None:
                    self._kernel_verifier = verifier_cls(pccb_verifier=self._trust_root)
                verifier = self._kernel_verifier
            result = verifier.verify_boundary(
                request_cls(
                    proof_token=proof_token,
                    action_type=boundary.action,
                    action_hash="",
                    audience=boundary.audience,
                    boundary_id=boundary.id,
                    target=intent.target.resource_id,
                    intent=intent,
                )
            )
            if result.valid:
                return {"valid": True, "reason": "verified", "proof_id": result.proof_id}
            return _invalid(result.reason, result.refusal_code)

        # Kernels whose BoundaryVerifier cannot take an intent (<= 1.2.1):
        # verify with the kernel's PCCBVerifier directly, same checks.
        return self._verify_with_pccb_verifier(boundary, proof_token, intent)

    def _verify_with_pccb_verifier(
        self, boundary: BoundaryEntry, proof_token: str, intent: Any
    ) -> dict[str, Any]:
        from actenon.core.errors import ProofVerificationError
        from actenon.models.contracts import PCCB
        from actenon.models.runtime import DynamicContextInput

        try:
            pccb = PCCB.from_dict(decode_token(proof_token))
            audience = parse_audience(boundary.audience)
        except Exception:  # noqa: BLE001
            return _invalid("proof token is not a well-formed PCCB", "PROOF_INVALID")
        context = DynamicContextInput(
            request_id=f"req_boundary_{uuid4().hex}",
            audience=audience,
            scope_capabilities=(intent.action.capability,),
            now=datetime.now(UTC),
        )
        try:
            self._trust_root.verify(intent, pccb, context)
        except ProofVerificationError as e:
            return _invalid(f"proof verification failed: {e.refusal_code}", e.refusal_code)
        replay_key = hashlib.sha256(
            json.dumps(
                {
                    "pccb_id": pccb.pccb_id,
                    "nonce": pccb.nonce,
                    "action_hash": pccb.action_hash.to_dict(),
                    "audience": pccb.audience.to_dict(),
                },
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        with self._replay_lock:
            if replay_key in self._replay_keys:
                return _invalid("replay detected: proof has already been used", "REPLAY_DETECTED")
            self._replay_keys.add(replay_key)
        return {"valid": True, "reason": "verified", "proof_id": pccb.pccb_id}

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


def _invalid(reason: str, code: str) -> dict[str, Any]:
    return {"valid": False, "reason": reason, "refusal_code": code}


def _kernel_boundary_api() -> tuple[Any, Any] | None:
    """The kernel's (BoundaryVerifier, BoundaryVerificationRequest) if that
    kernel binds proofs to Action Intents, else None."""
    try:
        from actenon.boundary import BoundaryVerificationRequest, BoundaryVerifier
    except ImportError:
        return None
    fields = getattr(BoundaryVerificationRequest, "__dataclass_fields__", {})
    if "intent" not in fields:
        return None
    return BoundaryVerifier, BoundaryVerificationRequest


def _path_params(pattern: str, actual: str) -> dict[str, str]:
    """Extract ``{name}`` path parameters by matching the route pattern."""
    regex = ""
    for literal, name in re.findall(r"([^{]*)(?:\{([^}]+)\})?", pattern):
        regex += re.escape(literal)
        if name:
            regex += f"(?P<{re.sub(r'[^0-9A-Za-z_]', '_', name)}>[^/]+)"
    m = re.fullmatch(regex, actual)
    if m is None:
        return {}
    names = re.findall(r"\{([^}]+)\}", pattern)
    return {name: m.group(re.sub(r"[^0-9A-Za-z_]", "_", name)) for name in names}


def _extract_proof(request: Request, proof_config) -> str:
    """Extract the proof token from the request (header source only)."""
    if proof_config.source == "header":
        return request.headers.get(proof_config.name, "")
    return ""


async def _safe_body(request: Request) -> dict:
    """Safely extract the JSON object body, returning {} on failure."""
    try:
        body_bytes = await request.body()
        if body_bytes:
            parsed = json.loads(body_bytes)
            if isinstance(parsed, dict):
                return parsed
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
    """A display digest of the canonical action (not the kernel action hash)."""
    canonical = json.dumps(
        {"action": action, "target": target, "params": params},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def reset_verifier() -> None:
    """Kept for compatibility: there is no process-wide verifier any more
    (each middleware instance owns its verifier and replay state)."""


def _build_refusal(boundary: BoundaryEntry, verification: dict, action_hash: str) -> dict[str, Any]:
    """Build a structured refusal response body."""
    return {
        "outcome": "refused",
        "boundary_id": boundary.id,
        "action": boundary.action,
        "reason": verification["reason"],
        "refusal_code": verification.get("refusal_code", ""),
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
