"""IAM control plane resource-owned reference (Prompt 9 follow-up).

This module provides a stub IAM control plane that demonstrates the
resource-owned execution mode end-to-end. It is a self-contained
in-process HTTP server (using Python's stdlib) that:

  1. Receives a request + proof at ``POST /iam/submit``.
  2. Verifies the proof is present and well-formed (stub: real
     implementations would use the Kernel PCCBVerifier).
  3. Executes the IAM action (``iam.grant_role``) — in the stub,
     this just records the grant in memory.
  4. Returns a signed resource receipt (HMAC-SHA256 over the
     canonical body) that the Permit-side ``ResourceOwnedSubmissionClient``
     can cryptographically verify.

This proves the resource-owned contract generalises beyond the test
stub in ``tests/test_execution_modes.py``: a real (well, stubbed but
non-trivial) resource boundary that issues its own receipts.

The stub is NOT for production. It uses an in-process HTTP server on
an ephemeral port and an in-memory role store. Real IAM control
planes would use a real database, asymmetric signing (Ed25519), and
a Kernel deployment for proof verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class IAMStubConfig:
    """Configuration for the IAM stub server."""

    signing_key_id: str = "iam-stub-key-1"
    signing_key_secret: bytes = b"iam-stub-secret-not-for-production"
    resource_id: str = "iam-control-plane-stub"
    # When True, the stub refuses all requests (simulates a resource
    # policy denial). Used to test the refused state.
    refuse_all: bool = False
    # When True, the stub returns succeeded WITHOUT a receipt (used
    # to test the missing-receipt -> outcome_unknown path).
    omit_receipt: bool = False
    # When True, the stub returns succeeded with a FORGED receipt
    # (signed with the wrong key). Used to test the forged-receipt
    # -> outcome_unknown path.
    forge_receipt: bool = False


# ---------------------------------------------------------------------------
# In-memory role store
# ---------------------------------------------------------------------------


@dataclass
class IAMStubState:
    """In-memory state for the IAM stub."""

    # (subject, role) -> granted_at timestamp
    granted_roles: dict[tuple[str, str], float] = field(default_factory=dict)
    # All submissions received, for audit
    submissions: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class _IAMStubHandler(BaseHTTPRequestHandler):
    """HTTP handler for the IAM stub.

    Endpoints:
      POST /iam/submit  — receive a request + proof, execute, return receipt
      GET  /iam/health  — liveness probe
      GET  /iam/roles   — list granted roles (for test inspection)
    """

    # silence default request logging
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib convention
        path = urlparse(self.path).path
        if path == "/iam/health":
            self._respond(200, {"status": "ok"})
        elif path == "/iam/roles":
            state: IAMStubState = self.server.iam_state  # type: ignore[attr-defined]
            roles = [
                {"subject": s, "role": r, "granted_at": t}
                for (s, r), t in state.granted_roles.items()
            ]
            self._respond(200, {"roles": roles})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib convention
        path = urlparse(self.path).path
        if path != "/iam/submit":
            self._respond(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body)
        except Exception as e:
            self._respond(400, {"status": "refused", "reason": f"bad request: {type(e).__name__}"})
            return

        config: IAMStubConfig = self.server.iam_config  # type: ignore[attr-defined]
        state: IAMStubState = self.server.iam_state  # type: ignore[attr-defined]

        # Record the submission for audit.
        state.submissions.append({
            "received_at": time.time(),
            "attempt_id": payload.get("attempt_id"),
            "action": payload.get("action", {}),
        })

        # Verify the proof is present (stub — real impl would use PCCBVerifier).
        proof = payload.get("proof")
        if not isinstance(proof, dict) or "proof_id" not in proof:
            self._respond(200, {"status": "refused", "reason": "proof missing or malformed"})
            return

        # Honour the refuse_all flag.
        if config.refuse_all:
            self._respond(200, {"status": "refused", "reason": "resource policy denial (refuse_all=True)"})
            return

        # Execute the IAM action.
        action = payload.get("action", {})
        action_type = action.get("type", "")
        if action_type != "iam.grant_role":
            self._respond(200, {"status": "refused", "reason": f"unsupported action: {action_type}"})
            return

        params = action.get("params", {})
        subject = params.get("subject", "")
        role = params.get("role", "")
        if not subject or not role:
            self._respond(200, {"status": "refused", "reason": "subject and role required"})
            return

        # Grant the role (in memory).
        state.granted_roles[(subject, role)] = time.time()

        # Build the resource receipt.
        receipt_body = {
            "resource_id": config.resource_id,
            "attempt_id": payload.get("attempt_id"),
            "action": action_type,
            "subject": subject,
            "role": role,
            "granted_at": state.granted_roles[(subject, role)],
            "signing_key_id": config.signing_key_id,
        }

        if config.omit_receipt:
            # Return succeeded but no receipt — used to test missing-receipt
            # -> outcome_unknown.
            self._respond(200, {"status": "succeeded", "submission_reference": f"sub_{payload.get('attempt_id', 'x')}"})
            return

        if config.forge_receipt:
            # Sign with the WRONG secret.
            receipt = dict(receipt_body)
            receipt["signature"] = _sign(receipt_body, b"wrong-secret")
            self._respond(200, {
                "status": "succeeded",
                "submission_reference": f"sub_{payload.get('attempt_id', 'x')}",
                "receipt": receipt,
            })
            return

        # Normal path: sign with the real secret.
        receipt = dict(receipt_body)
        receipt["signature"] = _sign(receipt_body, config.signing_key_secret)
        self._respond(200, {
            "status": "succeeded",
            "submission_reference": f"sub_{payload.get('attempt_id', 'x')}",
            "receipt": receipt,
        })

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _sign(body: dict[str, Any], secret: bytes) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Server wrapper
# ---------------------------------------------------------------------------


class IAMStubServer:
    """In-process IAM stub server.

    Usage::

        stub = IAMStubServer()
        stub.start()
        try:
            # use stub.endpoint_url, stub.config, stub.state
            ...
        finally:
            stub.stop()

    The server listens on 127.0.0.1:<ephemeral port>. The port is
    chosen by the OS to avoid conflicts.
    """

    def __init__(self, config: IAMStubConfig | None = None) -> None:
        self.config = config or IAMStubConfig()
        self.state = IAMStubState()
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port: int = 0

    @property
    def endpoint_url(self) -> str:
        return f"http://127.0.0.1:{self._port}/iam/submit"

    def start(self) -> None:
        if self._httpd is not None:
            return
        # Port 0 = OS chooses an ephemeral port.
        self._httpd = HTTPServer(("127.0.0.1", 0), _IAMStubHandler)
        self._httpd.iam_config = self.config  # type: ignore[attr-defined]
        self._httpd.iam_state = self.state  # type: ignore[attr-defined]
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    # convenience for tests
    def reset(self) -> None:
        self.state = IAMStubState()


__all__ = [
    "IAMStubConfig",
    "IAMStubServer",
    "IAMStubState",
]
