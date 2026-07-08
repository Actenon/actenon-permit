"""End-to-end tests for the v1 remote PEP client.

The agent-side code (``RemoteGuardRegistry`` + ``remote_guard``) talks to a
real HTTP gateway server (started in a background thread on a random port).
These tests prove the agent never imports the mock providers — it only makes
HTTP calls.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    Gateway,
    Ledger,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._mock_providers import mock_send_email, mock_stripe_charge, mock_stripe_refund
from actenon_permit.control import create_app
from actenon_permit.model import GrantStatus
from actenon_permit.pep_client import RemoteGuardDenied, RemoteGuardRegistry, remote_guard
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


def _pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 10.0) -> None:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=0.5) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"server at {url} did not become ready")


@pytest.fixture
def gateway_server(tmp_db, monkeypatch):
    """Start a real uvicorn server with the gateway mounted, yield its URL."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")

    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    tools.register(
        "refund",
        action_type="payment.refund",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="customer_request": mock_stripe_refund(secret, amount, reason),
    )
    tools.register(
        "charge",
        action_type="payment.charge",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description),
    )
    tools.register(
        "send_email",
        action_type="email.send",
        target="smtp",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
    )
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )
    app = create_app(state=store, ledger=ledger, pdp=pdp, gateway=gw)

    import uvicorn

    port = _pick_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(url)
        # Yield the store + url so tests can issue grants and tokens.
        yield {"url": url, "store": store, "gateway": gw}
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def _issue_grant(store: SQLiteStore) -> str:
    """Issue the demo grant and return its bearer token."""
    policy = {
        "agent": "remote-pep-agent",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 50},
        "scopes": {
            "allow": ["payment.refund", "email.send"],
            "deny": ["payment.charge", "shell.*"],
        },
        "rate": {"max": 20, "per": "1m"},
        "approval": {"require_human": ["email.send"]},
    }
    grant = compile_policy(policy)
    store.put_grant(grant)
    return grant_to_token(grant), grant.id


def test_remote_pep_seven_step_sequence(gateway_server):
    """The v1 remote PEP produces the same 7-step arc as the v0 demo."""
    token, grant_id = _issue_grant(gateway_server["store"])
    store = gateway_server["store"]

    reg = RemoteGuardRegistry(gateway_url=gateway_server["url"])
    reg.set_grant_token(token)

    @remote_guard("payment.refund", cost_from="amount", registry=reg)
    def refund(amount: float, reason: str = "customer_request") -> dict:
        ...

    @remote_guard("email.send", registry=reg)
    def send_email(to: str, subject: str, body: str = "") -> dict:
        ...

    @remote_guard("payment.charge", cost_from="amount", registry=reg)
    def charge(amount: float, description: str = "") -> dict:
        ...

    outcomes: list[str] = []

    # 1. refund $20 -> ALLOW
    r1 = refund(amount=20.0, reason="customer")
    outcomes.append("ALLOW")
    assert r1["amount"] == 20

    # 2. refund $25 -> ALLOW
    r2 = refund(amount=25.0, reason="fraud")
    outcomes.append("ALLOW")
    assert r2["amount"] == 25

    # 3. refund $20 -> DENY (budget)
    with pytest.raises(RemoteGuardDenied) as exc:
        refund(amount=20.0)
    outcomes.append("DENY")
    assert "budget" in str(exc.value)

    # 4. send_email -> REQUIRE_APPROVAL -> (auto) -> ALLOW
    r4 = send_email(to="ops@example.com", subject="refund", body="hi")
    outcomes.append("ALLOW")
    assert r4["status"] == "sent"

    # 5. charge $100 -> DENY (scope)
    with pytest.raises(RemoteGuardDenied) as exc:
        charge(amount=100.0)
    outcomes.append("DENY")
    assert "scope" in str(exc.value)

    # 6. kill switch
    store.set_status(grant_id, GrantStatus.REVOKED)

    # 7. refund $1 -> DENY (revoked)
    with pytest.raises(RemoteGuardDenied) as exc:
        refund(amount=1.0)
    outcomes.append("DENY")
    assert "revoked" in str(exc.value)

    assert outcomes == ["ALLOW", "ALLOW", "DENY", "ALLOW", "DENY", "DENY"]


def test_remote_pep_no_grant_token_raises(gateway_server):
    reg = RemoteGuardRegistry(gateway_url=gateway_server["url"])
    # No token set -> should raise immediately.

    @remote_guard("payment.refund", cost_from="amount", registry=reg)
    def refund(amount: float) -> dict:
        ...

    with pytest.raises(RemoteGuardDenied, match="no grant token"):
        refund(amount=10.0)


def test_remote_pep_unknown_tool_denied(gateway_server):
    token, _ = _issue_grant(gateway_server["store"])
    reg = RemoteGuardRegistry(gateway_url=gateway_server["url"])
    reg.set_grant_token(token)

    @remote_guard("payment.refund", registry=reg)  # type: ignore[arg-type]
    def nope(amount: float) -> dict:
        # The decorator names the tool after the function — so this maps to
        # /proxy/nope, which the gateway doesn't know.
        ...

    with pytest.raises(RemoteGuardDenied, match="unknown tool"):
        nope(amount=10.0)
