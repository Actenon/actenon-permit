"""Regression tests for R6a-f, F02, F03, R2/F06, and R9/F12 in actenon-permit."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from actenon_permit import (
    PDP,
    AutoApproveGate,
    Broker,
    Credential,
    CredentialProviderRegistry,
    DenyUnconfiguredApprovalGate,
    EnvironmentSecretProvider,
    Gateway,
    GuardRegistry,
    Ledger,
    ReconciliationConflictError,
    SQLiteStore,
    ToolRegistry,
)
from actenon_permit.adapters.openapi import (
    MCPDynamicAdapter,
    OpenAPIDynamicAdapter,
    OpenAPIOperationSpec,
    SSRFBlockedError,
    WitnessSpec,
)
from actenon_permit.policy import compile_policy
from actenon_permit.token import grant_to_token


class _RecordingWitnessHandler(BaseHTTPRequestHandler):
    """Loopback server that records POSTs, GET query strings, and witness payloads."""

    _lock = threading.Lock()
    post_count = 0
    last_get_path = ""
    witness_override: dict[str, Any] | None = None
    response_id_override: str | None = None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802
        with type(self)._lock:
            type(self).post_count += 1
            count = type(self).post_count
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        rid = type(self).response_id_override or f"re_{count}"
        payload = {
            "id": rid,
            "status": "succeeded",
            "amount": body.get("amount", 0),
            "charge": body.get("charge", ""),
            "echo_secret": f"used:{token}",
        }
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        type(self).last_get_path = self.path
        if self.path.startswith("/v1/search"):
            payload = {"id": "search_1", "query_path": self.path}
        elif type(self).witness_override is not None:
            payload = dict(type(self).witness_override)
        else:
            rid = self.path.rsplit("/", 1)[-1]
            payload = {
                "id": rid,
                "status": "succeeded",
                "amount": 1500,
                "charge": "ch_101",
            }
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _HighBacklogHTTPServer(ThreadingHTTPServer):
    request_queue_size = 64


@pytest.fixture
def witness_server():
    _RecordingWitnessHandler.post_count = 0
    _RecordingWitnessHandler.last_get_path = ""
    _RecordingWitnessHandler.witness_override = None
    _RecordingWitnessHandler.response_id_override = None
    server = _HighBacklogHTTPServer(("127.0.0.1", 0), _RecordingWitnessHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _RecordingWitnessHandler
    finally:
        server.shutdown()
        server.server_close()


def test_r6a_no_shared_credential_attribute_and_concurrent_redaction(witness_server) -> None:
    """R6a: OpenAPIDynamicAdapter has no _last_credential_value state and redacts per-call credentials."""
    base_url, _ = witness_server
    adapter = OpenAPIDynamicAdapter(
        provider_id="stripe",
        base_url=base_url,
        allow_loopback_for_tests=True,
        block_uncertain_retries=False,
        operations=[
            OpenAPIOperationSpec(
                action="stripe.refund.create",
                method="POST",
                path_template="/v1/refunds",
                required_params=("charge", "amount"),
                param_types={"charge": str, "amount": int},
                witness=WitnessSpec(
                    path_template="/v1/refunds/{id}",
                    expected_status=(200,),
                    expected_fields={"status": "succeeded"},
                ),
            )
        ],
    )
    assert not hasattr(adapter, "_last_credential_value")

    def _call(idx: int) -> dict[str, Any]:
        secret = f"custom_secret_token_{idx}"
        cred = Credential(ref=f"ref_{idx}", value=secret, source="env")
        resp = adapter.execute(
            "stripe.refund.create",
            {"charge": "ch_101", "amount": 1500},
            cred,
        )
        assert secret not in json.dumps(resp.provider_evidence)
        assert resp.provider_evidence["echo_secret"] == "used:<redacted>"
        return resp.provider_evidence

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(16)))
    assert len(results) == 16


def test_r6b_witness_validates_action_id_path_and_binds_request_params(witness_server) -> None:
    """R6b: Unsafe provider_action_id or mismatched witness charge/amount raises ReconciliationConflictError."""
    base_url, handler = witness_server
    adapter = OpenAPIDynamicAdapter(
        provider_id="stripe",
        base_url=base_url,
        allow_loopback_for_tests=True,
        block_uncertain_retries=False,
        operations=[
            OpenAPIOperationSpec(
                action="stripe.refund.create",
                method="POST",
                path_template="/v1/refunds",
                required_params=("charge", "amount"),
                param_types={"charge": str, "amount": int},
                witness=WitnessSpec(
                    path_template="/v1/refunds/{id}",
                    expected_status=(200,),
                    expected_fields={"status": "succeeded"},
                    bind_request_params=("charge", "amount"),
                ),
            )
        ],
    )
    cred = Credential(ref="stripe", value="sk_test_123", source="env")

    # 1. Unsafe provider_action_id in response is rejected before path interpolation
    handler.response_id_override = "../admin"
    with pytest.raises(ReconciliationConflictError, match="unsafe path characters"):
        adapter.execute("stripe.refund.create", {"charge": "ch_101", "amount": 1500}, cred)

    # 2. Witness returning a different charge or amount than requested is rejected
    handler.response_id_override = "re_valid_1"
    handler.witness_override = {
        "id": "re_valid_1",
        "status": "succeeded",
        "charge": "ch_DIFFERENT",
        "amount": 1500,
    }
    with pytest.raises(ReconciliationConflictError, match="request-binding mismatch on 'charge'"):
        adapter.execute("stripe.refund.create", {"charge": "ch_101", "amount": 1500}, cred)


def test_r6c_cleartext_http_refused_for_non_loopback_authenticated_calls() -> None:
    """R6c: Authenticated calls over cleartext http:// to non-loopback hosts are refused."""
    adapter = OpenAPIDynamicAdapter(
        provider_id="ext",
        base_url="http://93.184.216.34",
        operations=[
            OpenAPIOperationSpec(
                action="ext.ping",
                method="POST",
                path_template="/v1/ping",
                required_params=("msg",),
                param_types={"msg": str},
            )
        ],
    )
    cred = Credential(ref="ext", value="secret_bearer_123", source="env")
    with pytest.raises(SSRFBlockedError, match="cleartext HTTP is forbidden"):
        adapter.execute("ext.ping", {"msg": "hello"}, cred)


def test_r6d_schema_validation_nullability_bounds_keywords_and_get_query(witness_server) -> None:
    """R6d: Rejects None for non-nullable, enforces bounds/enums, rejects $ref/oneOf, and encodes GET query params."""
    with pytest.raises(ValueError, match="unsupported keyword '\\$ref'"):
        OpenAPIDynamicAdapter.from_openapi(
            {
                "openapi": "3.0.0",
                "servers": [{"url": "https://api.example.com"}],
                "paths": {
                    "/v1/items": {
                        "post": {
                            "operationId": "items.create",
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "payload": {"$ref": "#/components/schemas/Item"}
                                            },
                                        }
                                    }
                                }
                            },
                        }
                    }
                },
            },
            provider_id="items",
        )

    base_url, handler = witness_server
    adapter = OpenAPIDynamicAdapter.from_openapi(
        {
            "openapi": "3.0.0",
            "servers": [{"url": base_url}],
            "paths": {
                "/v1/search": {
                    "get": {
                        "operationId": "items.search",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "integer", "minimum": 1, "maximum": 50},
                            },
                            {
                                "name": "sort",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "string", "enum": ["asc", "desc"]},
                            },
                        ],
                    }
                }
            },
        },
        provider_id="items",
        allow_loopback_for_tests=True,
    )

    # Non-nullable None rejected
    assert not adapter.validate_params("items.search", {"q": None}).ok
    # Out-of-bounds integer rejected
    assert not adapter.validate_params("items.search", {"q": "ok", "limit": 0}).ok
    assert not adapter.validate_params("items.search", {"q": "ok", "limit": 99}).ok
    # Invalid enum rejected
    assert not adapter.validate_params("items.search", {"q": "ok", "sort": "random"}).ok

    # Valid GET encodes query parameters
    cred = Credential(ref="items", value="sk_test_123", source="env")
    adapter.execute("items.search", {"q": "actenon", "limit": 10, "sort": "asc"}, cred)
    assert "q=actenon" in handler.last_get_path
    assert "limit=10" in handler.last_get_path
    assert "sort=asc" in handler.last_get_path


def test_r6e_reconciliation_conflict_preserves_outcome_unknown_and_blocks_duplicate_retry(
    witness_server, monkeypatch
) -> None:
    """R6e: Witness conflict maps to OUTCOME_UNKNOWN, holds budget reservation, and blocks duplicate retry."""
    base_url, handler = witness_server
    handler.witness_override = {"id": "re_1", "status": "pending", "charge": "ch_101", "amount": 25}

    monkeypatch.setenv("STRIPE_LIVE_KEY", "sk_test_reconcile_hold")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    reg = CredentialProviderRegistry()
    reg.register("stripe_live", EnvironmentSecretProvider({"stripe_live": "STRIPE_LIVE_KEY"}))
    broker = Broker(pdp, credential_providers=reg)
    tools = ToolRegistry()

    adapter = OpenAPIDynamicAdapter(
        provider_id="stripe",
        base_url=base_url,
        allow_loopback_for_tests=True,
        operations=[
            OpenAPIOperationSpec(
                action="payment.refund",
                method="POST",
                path_template="/v1/refunds",
                required_params=("charge", "amount"),
                param_types={"charge": str, "amount": int},
                cost_field="amount",
                witness=WitnessSpec(
                    path_template="/v1/refunds/{id}",
                    expected_status=(200,),
                    expected_fields={"status": "succeeded"},
                ),
            )
        ],
    )
    tools.register_adapter_tool(
        "refund_tool",
        action_type="payment.refund",
        target="ch_101",
        adapter=adapter,
        credential_ref="stripe_live",
        cost_from="amount",
    )
    gw = Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools)
    grant = compile_policy(
        {
            "agent": "reconcile-agent",
            "ttl": "1h",
            "budget": {"currency": "USD", "limit": 100},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        }
    )
    store.put_grant(grant)
    token = grant_to_token(grant)

    res1 = gw.call_tool("refund_tool", {"charge": "ch_101", "amount": 25}, grant_token=token)
    assert res1["outcome"] == "DENY"
    assert res1["execution_state"] == "outcome_unknown"
    assert res1["finality"] == "non_final"
    # Budget reservation of 25 is held (NOT refunded) because the POST already ran!
    assert res1["remaining_budget"] == 75.0
    assert handler.post_count == 1

    # A duplicate retry of the same uncertain action is blocked before making a second POST
    with pytest.raises(ReconciliationConflictError, match="locked in OUTCOME_UNKNOWN"):
        adapter.execute(
            "payment.refund",
            {"charge": "ch_101", "amount": 25},
            Credential(ref="stripe_live", value="sk_test_reconcile_hold", source="env"),
        )
    assert handler.post_count == 1


def test_r6f_experimental_opt_in_and_mcp_deprecation(monkeypatch) -> None:
    """R6f: OpenAPIDynamicAdapter is experimental and MCPDynamicAdapter emits DeprecationWarning."""
    assert OpenAPIDynamicAdapter.EXPERIMENTAL is True
    monkeypatch.setenv("ACTENON_ENV", "production")
    with pytest.raises(ValueError, match="experimental and excluded from the supported production profile"):
        OpenAPIDynamicAdapter(
            provider_id="stripe",
            base_url="https://api.stripe.com",
            operations=[],
            experimental_opt_in=False,
        )
    monkeypatch.delenv("ACTENON_ENV", raising=False)
    with pytest.warns(DeprecationWarning, match="MCPDynamicAdapter is deprecated"):
        MCPDynamicAdapter(
            provider_id="stripe",
            base_url="https://api.stripe.com",
            operations=[],
            test_mode=True,
        )


def test_f02_default_approval_gate_fails_closed_and_production_refuses_auto_approve() -> None:
    """F02: Gateway and GuardRegistry default to DenyUnconfiguredApprovalGate and refuse AutoApproveGate in production."""
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    gw = Gateway(state=store, ledger=ledger, pdp=pdp)
    assert isinstance(gw.approval_gate, DenyUnconfiguredApprovalGate)

    reg = GuardRegistry(store, pdp, Broker(pdp, production_mode=True))
    assert isinstance(reg.gate, DenyUnconfiguredApprovalGate)
    with pytest.raises(ValueError, match="AutoApproveGate is forbidden"):
        reg.set_approval_gate(AutoApproveGate())

    with pytest.raises(ValueError, match="AutoApproveGate is forbidden in production mode"):
        Gateway(
            state=store,
            ledger=ledger,
            pdp=pdp,
            broker=Broker(pdp, production_mode=True),
            approval_gate=AutoApproveGate(),
        )


def test_f03_post_dispatch_exception_holds_budget_reservation(monkeypatch) -> None:
    """F03: When a tool raises after dispatch starts, Gateway holds the budget reservation and reports outcome_unknown."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    store = SQLiteStore()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()

    def _crashing_tool(secret: str, amount: int) -> dict[str, Any]:
        raise RuntimeError("socket dropped after HTTP request sent")

    tools.register(
        "crash_refund",
        action_type="payment.refund",
        target="stripe",
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=_crashing_tool,
    )
    gw = Gateway(state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools)
    grant = compile_policy(
        {
            "agent": "f03-agent",
            "ttl": "1h",
            "budget": {"currency": "USD", "limit": 100},
            "scopes": {"allow": ["payment.refund"], "deny": []},
        }
    )
    store.put_grant(grant)
    token = grant_to_token(grant)

    res = gw.call_tool("crash_refund", {"amount": 40}, grant_token=token)
    assert res["outcome"] == "DENY"
    assert res["execution_state"] == "outcome_unknown"
    assert res["finality"] == "non_final"
    # Budget reservation of 40 must remain held, NOT released back to 100!
    assert res["remaining_budget"] == 60.0
