"""Actenon-Permit control plane — a localhost-only FastAPI app.

Endpoints:

    POST   /grants                  issue a grant from a policy dict
    GET    /grants                  list grants (optional ?agent_id=...)
    GET    /grants/{id}             get a single grant
    POST   /grants/{id}/revoke      kill switch — status -> revoked
    GET    /approvals               list pending approvals
    POST   /approvals/{id}/approve  approve a pending request
    POST   /approvals/{id}/deny     deny a pending request
    GET    /approvals/stream        SSE stream of pending-approval events
    GET    /ledger                  read the action log
    GET    /ledger/verify           verify the hash chain
    GET    /health                  liveness

Every endpoint above except /health is the operator's: it requires
``Authorization: Bearer <admin token>`` (constant-time compare) and refuses
(401 missing, 403 wrong or none configured) otherwise. Agents never need it:
the gateway routes mounted alongside (/proxy/*, /intents/*) authenticate each
call with the agent's own grant token. Without this, an agent on the same
port could issue itself grants, mint tokens, approve its own requests and read
every grant's signature. The app binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .ledger import Ledger
from .model import GrantStatus
from .pdp import PDP
from .policy import compile_policy
from .state import SQLiteStore, StateStore

# ---------------------------------------------------------------------------
# Pending-approval store (in-process; v0 is single-user local)
# ---------------------------------------------------------------------------


class ApprovalStore:
    """In-memory pending-approval store with SSE broadcast."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._pending: dict[str, dict[str, Any]] = {}
        self._decisions: dict[str, str] = {}  # action_id -> "approved"|"denied"
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []

    def create_pending(
        self, *, action_id: str, grant_id: str, action_type: str, reason: str
    ) -> None:
        evt = {
            "action_id": action_id,
            "grant_id": grant_id,
            "action_type": action_type,
            "reason": reason,
            "status": "pending",
            "ts": datetime.now(UTC).isoformat(),
        }
        with self._lock:
            self._pending[action_id] = evt
        self._broadcast({"event": "pending", **evt})

    def get_status(self, action_id: str) -> str | None:
        with self._lock:
            if action_id in self._decisions:
                return self._decisions[action_id]
            if action_id in self._pending:
                return "pending"
            return None

    def resolve(self, action_id: str, decision: str) -> None:
        if decision not in ("approved", "denied"):
            raise ValueError(f"decision must be approved/denied, got {decision}")
        with self._lock:
            evt = self._pending.pop(action_id, None)
            self._decisions[action_id] = decision
        if evt:
            self._broadcast({"event": "resolved", "action_id": action_id, "decision": decision, **evt})

    def list_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._pending.values())

    # --- SSE ---
    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast(self, msg: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(msg)


# ---------------------------------------------------------------------------
# Admin token (control-plane authentication)
# ---------------------------------------------------------------------------

ADMIN_TOKEN_ENV = "ACTENON_ADMIN_TOKEN"
ADMIN_TOKEN_FILE_ENV = "ACTENON_ADMIN_TOKEN_FILE"
ADMIN_TOKEN_FILENAME = "admin-token"


def default_state_dir() -> Path:
    return Path.home() / ".actenon-permit"


def _read_token_file(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError(f"admin token file is empty: {path}")
    return token


def load_or_create_admin_token(
    token_file: str | Path | None = None, *, state_dir: str | Path | None = None
) -> tuple[str, Path | None]:
    """Resolve the control plane's admin token for a server.

    Order: ``token_file`` / ``ACTENON_ADMIN_TOKEN_FILE``, then
    ``ACTENON_ADMIN_TOKEN``, else a fresh random 32-byte token written to
    ``<state_dir>/admin-token`` (default ``~/.actenon-permit``). The file is
    created 0600 atomically (O_EXCL temp file + rename; never chmod after
    writing) and rotated on every start. Returns ``(token, path_or_None)``.
    """
    explicit = token_file or os.environ.get(ADMIN_TOKEN_FILE_ENV, "").strip()
    if explicit:
        path = Path(explicit)
        return _read_token_file(path), path
    env_token = os.environ.get(ADMIN_TOKEN_ENV, "").strip()
    if env_token:
        return env_token, None
    directory = Path(state_dir) if state_dir is not None else default_state_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = secrets.token_hex(32)
    path = directory / ADMIN_TOKEN_FILENAME
    tmp = directory / f".{ADMIN_TOKEN_FILENAME}.{secrets.token_hex(8)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (token + "\n").encode("ascii"))
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return token, path


def read_admin_token(
    token_file: str | Path | None = None, *, state_dir: str | Path | None = None
) -> str | None:
    """Resolve the admin token for a client (same order; never generates)."""
    explicit = token_file or os.environ.get(ADMIN_TOKEN_FILE_ENV, "").strip()
    if explicit:
        return _read_token_file(Path(explicit))
    env_token = os.environ.get(ADMIN_TOKEN_ENV, "").strip()
    if env_token:
        return env_token
    path = (Path(state_dir) if state_dir is not None else default_state_dir()) / ADMIN_TOKEN_FILENAME
    return _read_token_file(path) if path.is_file() else None


def _admin_guard(admin_token: str | None):
    """FastAPI dependency: require ``Authorization: Bearer <admin token>``."""
    expected = (admin_token or "").encode("utf-8")

    def require_admin(authorization: str | None = Header(default=None)) -> None:
        scheme, _, presented = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not presented.strip():
            raise HTTPException(
                status_code=401,
                detail="admin token required (Authorization: Bearer <token>)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Compare even when no token is configured, then refuse regardless.
        matches = hmac.compare_digest(presented.strip().encode("utf-8"), expected)
        if not expected or not matches:
            raise HTTPException(status_code=403, detail="invalid admin token")

    return require_admin


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class IssueRequest(BaseModel):
    policy: dict[str, Any]


class AttenuateRequest(BaseModel):
    """Request body for POST /grants/{id}/attenuate.

    All fields optional; absent fields inherit from the parent. Any field
    present must be equal-or-weaker than the parent (enforced by
    ``Grant.attenuate()``).
    """

    agent_id: str | None = None
    expires_at: str | None = None
    scopes_allow: list[str] | None = None
    scopes_deny: list[str] | None = None
    budget_limit: float | None = None
    rate_max: int | None = None
    rate_per_seconds: int | None = None
    extra_approval_rules: list[str] | None = None


class RevokeResponse(BaseModel):
    grant_id: str
    status: str


class ApprovalResponse(BaseModel):
    action_id: str
    decision: str


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    state: StateStore | None = None,
    ledger: Ledger | None = None,
    pdp: PDP | None = None,
    approval_store: ApprovalStore | None = None,
    gateway: Any = None,
    wire_gateway_approvals: bool = True,
    admin_token: str | None = None,
) -> FastAPI:
    """Build the FastAPI app. Defaults to a fresh SQLiteStore + Ledger.

    If ``gateway`` is provided, the v1 HTTP proxy endpoints (``/proxy/*``)
    are mounted on the same app so a single ``permit serve`` can host both
    the control plane and the gateway.

    If ``wire_gateway_approvals`` is True (default) and a ``gateway`` is
    provided, the gateway's ``approval_gate`` is REPLACED with a
    ``BlockingApprovalGate`` backed by this app's ``ApprovalStore``. This
    means REQUIRE_APPROVAL decisions made inside the gateway will create
    pending-approval entries visible at ``/approvals`` and resolvable via
    ``/approvals/{id}/approve`` and ``/approvals/{id}/deny`` — so
    ``permit watch`` can approve them. Pass ``wire_gateway_approvals=False``
    to keep the gateway's existing gate (e.g. AutoApproveGate for tests).

    ``admin_token`` protects every control-plane route (all but /health and
    the gateway's /proxy/* and /intents/*). With ``None`` those routes
    refuse every request: the control plane is never open.
    """
    state = state or SQLiteStore()
    ledger = ledger or Ledger(state)
    pdp = pdp or PDP(state, ledger)
    approvals = approval_store or ApprovalStore()

    # Wire the gateway's approval gate to this app's ApprovalStore so that
    # REQUIRE_APPROVAL flows through /approvals and is visible to `permit watch`.
    if gateway is not None and wire_gateway_approvals:
        from .enforce import BlockingApprovalGate

        gateway.approval_gate = BlockingApprovalGate(approvals)

    app = FastAPI(title="Actenon-Permit Control Plane", version="0.1.0")
    app.state.state = state
    app.state.ledger = ledger
    app.state.pdp = pdp
    app.state.approvals = approvals
    admin = [Depends(_admin_guard(admin_token))]

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ------------------------------------------------------------------
    # Grants
    # ------------------------------------------------------------------
    @app.post("/grants", response_model=dict, dependencies=admin)
    def issue_grant(req: IssueRequest) -> dict[str, Any]:
        try:
            grant = compile_policy(req.policy)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"policy compile error: {e}") from e
        state.put_grant(grant)
        return json.loads(grant.model_dump_json())

    @app.get("/grants", response_model=list, dependencies=admin)
    def list_grants(agent_id: str | None = None) -> list[dict[str, Any]]:
        grants = state.list_grants(agent_id=agent_id)
        return [json.loads(g.model_dump_json()) for g in grants]

    @app.get("/grants/{grant_id}", response_model=dict, dependencies=admin)
    def get_grant(grant_id: str) -> dict[str, Any]:
        g = state.get_grant(grant_id)
        if g is None:
            raise HTTPException(status_code=404, detail="grant not found")
        return json.loads(g.model_dump_json())

    @app.post("/grants/{grant_id}/revoke", response_model=RevokeResponse, dependencies=admin)
    def revoke_grant(grant_id: str) -> RevokeResponse:
        g = state.get_grant(grant_id)
        if g is None:
            raise HTTPException(status_code=404, detail="grant not found")
        state.set_status(grant_id, GrantStatus.REVOKED)
        # ── Phase 7: revocation cascade ──────────────────────────────
        # Revoke every grant attenuated from this one, transitively (a
        # grandchild must not outlive its revoked root). (Audit finding
        # P-05.) The state store also refuses to reserve against any grant
        # with a revoked ancestor, so this pass is for status visibility.
        all_grants = state.list_grants()
        revoked_ids = {grant_id}
        frontier = [grant_id]
        while frontier:
            parent_id = frontier.pop()
            for grant in all_grants:
                if grant.parent_grant_id == parent_id and grant.id not in revoked_ids:
                    revoked_ids.add(grant.id)
                    frontier.append(grant.id)
                    if grant.status == GrantStatus.ACTIVE:
                        state.set_status(grant.id, GrantStatus.REVOKED)
        # Deny any in-flight approval waiters for the revoked grants.
        for p in approvals.list_pending():
            if p["grant_id"] in revoked_ids:
                approvals.resolve(p["action_id"], "denied")
        return RevokeResponse(grant_id=grant_id, status="revoked")

    @app.post("/grants/{grant_id}/attenuate", response_model=dict, dependencies=admin)
    def attenuate_grant(grant_id: str, req: AttenuateRequest) -> dict[str, Any]:
        """Derive a strictly-weaker sub-grant from an existing grant.

        This is the v1 wire endpoint for UCAN-style multi-agent delegation.
        The parent grant MUST be active. The child grant is freshly signed
        and stored, then returned. The parent is unaffected.
        """
        from datetime import datetime

        parent = state.get_grant(grant_id)
        if parent is None:
            raise HTTPException(status_code=404, detail="parent grant not found")
        if parent.status != GrantStatus.ACTIVE:
            raise HTTPException(
                status_code=409,
                detail=f"parent grant status is {parent.status.value}, must be active",
            )

        kwargs: dict[str, Any] = {}
        if req.agent_id is not None:
            kwargs["agent_id"] = req.agent_id
        if req.expires_at is not None:
            try:
                kwargs["expires_at"] = datetime.fromisoformat(req.expires_at)
                if kwargs["expires_at"].tzinfo is None:
                    kwargs["expires_at"] = kwargs["expires_at"].replace(tzinfo=UTC)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"invalid expires_at: {e}") from e
        if req.scopes_allow is not None:
            kwargs["scopes_allow"] = req.scopes_allow
        if req.scopes_deny is not None:
            kwargs["scopes_deny"] = req.scopes_deny
        if req.budget_limit is not None:
            kwargs["budget_limit"] = req.budget_limit
        if req.rate_max is not None:
            kwargs["rate_max"] = req.rate_max
        if req.rate_per_seconds is not None:
            kwargs["rate_per_seconds"] = req.rate_per_seconds
        if req.extra_approval_rules is not None:
            kwargs["extra_approval_rules"] = req.extra_approval_rules

        try:
            child = parent.attenuate(**kwargs)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"attenuation rejected: {e}") from e

        state.put_grant(child)
        return json.loads(child.model_dump_json())

    @app.post("/grants/{grant_id}/token", response_model=dict, dependencies=admin)
    def grant_to_token_endpoint(grant_id: str) -> dict[str, str]:
        """Mint a bearer token for an existing grant.

        The token is signed with the local signing key and can be presented
        to the v1 gateway as the ``X-Actenon-Grant`` header.
        """
        from .token import grant_to_token

        g = state.get_grant(grant_id)
        if g is None:
            raise HTTPException(status_code=404, detail="grant not found")
        if not g.signature:
            g.sign()
            state.put_grant(g)
        token = grant_to_token(g)
        return {"grant_id": grant_id, "token": token}

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------
    @app.get("/approvals", response_model=list, dependencies=admin)
    def list_approvals() -> list[dict[str, Any]]:
        return approvals.list_pending()

    @app.post("/approvals/{action_id}/approve", response_model=ApprovalResponse, dependencies=admin)
    def approve(action_id: str) -> ApprovalResponse:
        if approvals.get_status(action_id) != "pending":
            raise HTTPException(status_code=404, detail="no pending approval with that id")
        approvals.resolve(action_id, "approved")
        return ApprovalResponse(action_id=action_id, decision="approved")

    @app.post("/approvals/{action_id}/deny", response_model=ApprovalResponse, dependencies=admin)
    def deny(action_id: str) -> ApprovalResponse:
        if approvals.get_status(action_id) not in ("pending", None):
            raise HTTPException(status_code=409, detail="already resolved")
        approvals.resolve(action_id, "denied")
        return ApprovalResponse(action_id=action_id, decision="denied")

    @app.get("/approvals/stream", dependencies=admin)
    async def stream_approvals() -> StreamingResponse:
        q = approvals.subscribe()

        async def gen():
            try:
                # Initial heartbeat with current pending list.
                yield f"data: {json.dumps({'event': 'hello', 'pending': approvals.list_pending()})}\n\n"
                while True:
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=15.0)
                        yield f"data: {json.dumps(msg)}\n\n"
                    except TimeoutError:
                        yield f"data: {json.dumps({'event': 'heartbeat', 'ts': time.time()})}\n\n"
            finally:
                approvals.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream")

    # ------------------------------------------------------------------
    # Ledger
    # ------------------------------------------------------------------
    @app.get("/ledger", response_model=list, dependencies=admin)
    def get_ledger(grant_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        return ledger.list_entries(grant_id=grant_id, limit=limit)

    @app.get("/ledger/verify", response_model=dict, dependencies=admin)
    def verify_ledger() -> dict[str, bool]:
        return {"ok": ledger.verify()}

    # ------------------------------------------------------------------
    # v1: out-of-process gateway proxy (mounted only if a Gateway is provided)
    # ------------------------------------------------------------------
    if gateway is not None:
        from .gateway import mount_intent_routes, mount_proxy

        mount_proxy(app, gateway)
        # v1.3 (Prompt 10): AEI developer surface.
        mount_intent_routes(app, gateway)

    return app
