"""Real-agent integration test: starts a real gateway server, issues a grant,
and runs the ScriptedAgent + LLMAgent against it over HTTP.

This test proves the v1 gateway works seamlessly with real agents:
  - The ScriptedAgent runs the 7-step arc and every decision is correct.
  - The LLMAgent uses the z-ai SDK to plan tool calls based on a natural-language
    request, executes them through the gateway, and respects the grant's limits.

The test is marked as a real integration test (not a unit test) because it
spawns a real uvicorn server and (for the LLM agent) makes real LLM API calls.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the project root importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from actenon_permit import (  # noqa: E402
    PDP,
    AutoApproveGate,
    Broker,
    Gateway,
    Ledger,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit._mock_providers import (  # noqa: E402
    mock_send_email,
    mock_stripe_charge,
    mock_stripe_refund,
)
from actenon_permit._net import start_uvicorn_in_thread, wait_for_server  # noqa: E402
from actenon_permit.control import create_app  # noqa: E402
from actenon_permit.policy import compile_policy  # noqa: E402
from actenon_permit.token import grant_to_token  # noqa: E402


@pytest.fixture
def gateway_url(tmp_db, monkeypatch):
    """Start a real gateway server on an OS-assigned port; yield its URL."""
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
        description="Issue a refund via the (mock) Stripe provider.",
        input_schema={
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Amount to refund, in major currency units."},
                "reason": {"type": "string", "default": "customer_request"},
            },
            "required": ["amount"],
        },
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="customer_request": mock_stripe_refund(secret, amount, reason),
    )
    tools.register(
        "charge",
        action_type="payment.charge",
        target="stripe",
        description="Charge a card via the (mock) Stripe provider.",
        input_schema={
            "type": "object",
            "properties": {"amount": {"type": "number"}, "description": {"type": "string", "default": ""}},
            "required": ["amount"],
        },
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description),
    )
    tools.register(
        "send_email",
        action_type="email.send",
        target="smtp",
        description="Send an email via the (mock) SMTP provider.",
        input_schema={
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string", "default": ""},
            },
            "required": ["to", "subject"],
        },
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
    )
    gw = Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )
    app = create_app(
        state=store, ledger=ledger, pdp=pdp, gateway=gw,
        wire_gateway_approvals=False,
    )
    server, thread, url = start_uvicorn_in_thread(app, port=0)
    try:
        wait_for_server(url)
        yield {"url": url, "store": store}
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def _issue_grant(store):
    policy = {
        "agent": "real-agent-test",
        "ttl": "1h",
        "budget": {"currency": "USD", "limit": 50},
        "scopes": {
            "allow": ["payment.refund", "email.send"],
            "deny": ["payment.charge", "shell.*"],
        },
        "rate": {"max": 20, "per": "1m"},
        "approval": {"require_human": ["email.send"]},
    }
    g = compile_policy(policy)
    store.put_grant(g)
    return grant_to_token(g), g.id


def test_real_scripted_agent_through_gateway(gateway_url):
    """The ScriptedAgent runs the 7-step arc against a real HTTP gateway."""
    from agents.runner import GatewayClient, ScriptedAgent

    token, grant_id = _issue_grant(gateway_url["store"])
    client = GatewayClient(gateway_url["url"], token)

    # Verify the agent can see the tools.
    tools = client.list_tools()
    assert "refund" in tools
    assert "charge" in tools
    assert "send_email" in tools

    agent = ScriptedAgent(client)
    results = agent.run()

    # Verify the 7-step arc.
    # Steps 1-2: ALLOW (budget 50 -> 30 -> 5)
    assert results[0]["result"]["outcome"] == "ALLOW", f"step 1: {results[0]}"
    assert results[0]["result"]["remaining_budget"] == 30.0
    assert results[1]["result"]["outcome"] == "ALLOW", f"step 2: {results[1]}"
    assert results[1]["result"]["remaining_budget"] == 5.0
    # Step 3: DENY (budget)
    assert results[2]["result"]["outcome"] == "DENY"
    assert "budget" in results[2]["result"]["reason"]
    # Step 4: ALLOW (approval auto-approved)
    assert results[3]["result"]["outcome"] == "ALLOW"
    # Step 5: DENY (scope)
    assert results[4]["result"]["outcome"] == "DENY"
    assert "scope" in results[4]["result"]["reason"]
    # Step 7: DENY (revoked) — step 6 is the revoke
    assert results[5]["result"]["outcome"] == "DENY"
    assert "revoked" in results[5]["result"]["reason"]


def test_real_agent_cannot_call_unknown_tool(gateway_url):
    """An agent that tries to call a tool not in the registry gets DENY."""
    from agents.runner import GatewayClient

    token, _ = _issue_grant(gateway_url["store"])
    client = GatewayClient(gateway_url["url"], token)
    result = client.call_tool("delete_database", {})
    assert result["outcome"] == "DENY"
    assert "unknown tool" in result["reason"]


def test_real_agent_with_invalid_token_denied(gateway_url):
    """An agent presenting a garbage token gets DENY on every call."""
    from agents.runner import GatewayClient

    client = GatewayClient(gateway_url["url"], "v1.garbage-not-a-real-token")
    result = client.call_tool("refund", {"amount": 10})
    assert result["outcome"] == "DENY"
    assert "invalid grant token" in result["reason"]


def test_real_agent_budget_actually_decreases(gateway_url):
    """Multiple ALLOWed refunds must actually decrease the budget — proving
    the gateway isn't just returning ALLOW without enforcing."""
    from agents.runner import GatewayClient

    token, _ = _issue_grant(gateway_url["store"])
    client = GatewayClient(gateway_url["url"], token)

    r1 = client.call_tool("refund", {"amount": 15})
    assert r1["outcome"] == "ALLOW"
    assert r1["remaining_budget"] == 35.0

    r2 = client.call_tool("refund", {"amount": 10})
    assert r2["outcome"] == "ALLOW"
    assert r2["remaining_budget"] == 25.0

    # Now try to refund $30 — only $25 left, should DENY.
    r3 = client.call_tool("refund", {"amount": 30})
    assert r3["outcome"] == "DENY"
    assert "budget" in r3["reason"]


@pytest.mark.skipif(
    os.environ.get("SKIP_LLM_TESTS") == "1",
    reason="SKIP_LLM_TESTS=1 set",
)
def test_real_llm_agent_through_gateway(gateway_url):
    """The LLMAgent uses the z-ai CLI to plan and execute tool calls.

    Skipped if the z-ai CLI is not on PATH or SKIP_LLM_TESTS=1.
    """
    import shutil

    if not shutil.which("z-ai"):
        pytest.skip("z-ai CLI not on PATH")
    from agents.runner import GatewayClient, LLMAgent

    token, _ = _issue_grant(gateway_url["store"])
    client = GatewayClient(gateway_url["url"], token)

    # Verify the agent can fetch grant state.
    grant = client.get_grant()
    assert grant["status"] == "active"
    assert grant["budget"]["remaining"] == 50.0

    agent = LLMAgent(client, verbose=False)
    # A simple request the LLM should be able to plan: refund $10.
    results = agent.run("Refund $10 to a customer.", max_rounds=1)

    # The LLM should have produced at least one action, and the refund
    # should have been ALLOWed.
    assert len(results) > 0, "LLM produced no actions"
    refund_results = [r for r in results if r["tool"] == "refund"]
    assert len(refund_results) > 0, f"no refund call in results: {results}"
    assert refund_results[0]["result"]["outcome"] == "ALLOW", f"refund was denied: {refund_results[0]}"
    assert refund_results[0]["result"]["remaining_budget"] == 40.0  # 50 - 10
