"""Tests for the v1 control-plane-to-gateway approval wiring.

When ``create_app(gateway=gw)`` is called with the default
``wire_gateway_approvals=True``, the gateway's ``approval_gate`` is replaced
with a ``BlockingApprovalGate`` backed by the app's ``ApprovalStore``. This
means REQUIRE_APPROVAL decisions made inside the gateway create pending
entries visible at ``/approvals``, and resolvable via
``/approvals/{id}/approve`` and ``/approvals/{id}/deny``.

This is the production path: ``permit serve --with-gateway`` runs ONE server
that hosts both the control plane and the gateway, with approvals flowing
through the same ApprovalStore. ``permit watch --url <url>`` can then approve
pending requests from a separate terminal.
"""

from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient

from actenon_permit import (
    PDP,
    Broker,
    Gateway,
    Ledger,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._mock_providers import mock_send_email
from actenon_permit.control import create_app
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


def _make_wired_app(tmp_db, monkeypatch):
    """Build a create_app'd FastAPI app with the gateway wired to the
    control plane's ApprovalStore (wire_gateway_approvals=True, the default)."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    tools.register(
        "send_email",
        action_type="email.send",
        target="smtp",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
    )
    # No AutoApproveGate — the gateway starts with no gate, and create_app
    # should wire it to the ApprovalStore via BlockingApprovalGate.
    gw = Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools)
    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw)
    return app, store, gw


def _issue_grant(store):
    policy = {
        "agent": "wired-approval-agent",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 50},
        "scopes": {"allow": ["email.send"], "deny": []},
        "approval": {"require_human": ["email.send"]},
    }
    g = compile_policy(policy)
    store.put_grant(g)
    return grant_to_token(g), g.id


def test_wired_gateway_creates_pending_approval(tmp_db, monkeypatch):
    """A REQUIRE_APPROVAL decision in the gateway must create a pending entry
    visible at GET /approvals on the same app.
    """
    app, store, _ = _make_wired_app(tmp_db, monkeypatch)
    token, _ = _issue_grant(store)
    client = TestClient(app)

    # Start a call that will REQUIRE_APPROVAL in a background thread (it
    # blocks until we approve or the timeout hits).
    result_holder: dict = {}

    def call():
        try:
            r = client.post(
                "/proxy/send_email",
                json={"to": "x@y.com", "subject": "hi"},
                headers={"X-Actenon-Grant": token},
            )
            result_holder["status"] = r.status_code
            result_holder["body"] = r.json()
        except Exception as e:  # noqa: BLE001
            result_holder["error"] = str(e)

    t = threading.Thread(target=call, daemon=True)
    t.start()

    # Wait for the pending approval to appear.
    pending = []
    for _ in range(50):
        pending = client.get("/approvals").json()
        if pending:
            break
        time.sleep(0.05)

    assert len(pending) == 1, f"expected 1 pending approval, got {pending}"
    action_id = pending[0]["action_id"]
    assert pending[0]["action_type"] == "email.send"

    # Approve it.
    r = client.post(f"/approvals/{action_id}/approve")
    assert r.status_code == 200
    t.join(timeout=5.0)

    # The original call should now have completed with ALLOW.
    assert result_holder.get("status") == 200, f"unexpected: {result_holder}"
    assert result_holder["body"]["outcome"] == "ALLOW"


def test_wired_gateway_deny_via_approvals_endpoint(tmp_db, monkeypatch):
    """If /approvals/{id}/deny is called, the blocked gateway call must
    return DENY."""
    app, store, _ = _make_wired_app(tmp_db, monkeypatch)
    token, _ = _issue_grant(store)
    client = TestClient(app)

    result_holder: dict = {}

    def call():
        r = client.post(
            "/proxy/send_email",
            json={"to": "x@y.com", "subject": "hi"},
            headers={"X-Actenon-Grant": token},
        )
        result_holder["status"] = r.status_code
        result_holder["body"] = r.json()

    t = threading.Thread(target=call, daemon=True)
    t.start()

    # Wait for pending.
    pending = []
    for _ in range(50):
        pending = client.get("/approvals").json()
        if pending:
            break
        time.sleep(0.05)

    assert len(pending) == 1
    action_id = pending[0]["action_id"]

    # Deny it.
    r = client.post(f"/approvals/{action_id}/deny")
    assert r.status_code == 200
    t.join(timeout=5.0)

    # The original call should now have completed with DENY (403).
    assert result_holder.get("status") == 403, f"unexpected: {result_holder}"
    assert result_holder["body"]["outcome"] == "DENY"
    assert "approval denied" in result_holder["body"]["reason"] or "denied" in result_holder["body"]["reason"]


def test_revoke_denies_inflight_approvals(tmp_db, monkeypatch):
    """When a grant is revoked, any in-flight approval waiters for that grant
    must be denied so the calling thread doesn't hang."""
    app, store, _ = _make_wired_app(tmp_db, monkeypatch)
    token, grant_id = _issue_grant(store)
    client = TestClient(app)

    result_holder: dict = {}

    def call():
        r = client.post(
            "/proxy/send_email",
            json={"to": "x@y.com", "subject": "hi"},
            headers={"X-Actenon-Grant": token},
        )
        result_holder["status"] = r.status_code
        result_holder["body"] = r.json()

    t = threading.Thread(target=call, daemon=True)
    t.start()

    # Wait for pending.
    pending = []
    for _ in range(50):
        pending = client.get("/approvals").json()
        if pending:
            break
        time.sleep(0.05)

    assert len(pending) == 1
    assert pending[0]["grant_id"] == grant_id

    # Revoke the grant — this should deny the in-flight approval.
    r = client.post(f"/grants/{grant_id}/revoke")
    assert r.status_code == 200
    t.join(timeout=5.0)

    # The original call should now have completed with DENY.
    assert result_holder.get("status") == 403, f"unexpected: {result_holder}"
    assert result_holder["body"]["outcome"] == "DENY"
    # The reason is one of "approval denied or timed out" (because revoke
    # resolves the pending approval as "denied") or "grant status is revoked"
    # (because the re-run decision after approval sees REVOKED). Either is
    # acceptable — what matters is that the call didn't hang and returned DENY.
    assert "denied" in result_holder["body"]["reason"].lower() or "revoked" in result_holder["body"]["reason"].lower()
