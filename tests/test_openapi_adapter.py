"""Tests for Universal OpenAPI / MCP Dynamic Capability Adapter & Witness Reconciliation."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from actenon_permit.adapters import (
    InvalidParametersError,
    OpenAPIDynamicAdapter,
    OpenAPIOperationSpec,
    OriginRedirectError,
    ReconciliationConflictError,
    SSRFBlockedError,
)
from actenon_permit.credentials import Credential


class _LocalProviderHandler(BaseHTTPRequestHandler):
    store: dict[str, dict[str, Any]] = {}
    auth_headers_seen: list[str] = []
    tamper_witness: bool = False
    redirect_to: str | None = None

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        auth = self.headers.get("Authorization", "")
        self.__class__.auth_headers_seen.append(auth)
        if self.__class__.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.__class__.redirect_to)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        if self.path == "/v1/refunds":
            refund_id = f"re_{len(self.__class__.store) + 1}"
            record = {
                "id": refund_id,
                "amount": body["amount"],
                "charge": body["charge"],
                "status": "succeeded",
            }
            self.__class__.store[refund_id] = record
            payload = json.dumps(record).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.end_headers()

    def do_GET(self) -> None:
        if self.path.startswith("/v1/refunds/"):
            refund_id = self.path.rsplit("/", 1)[-1]
            rec = self.__class__.store.get(refund_id)
            if rec is None or self.__class__.tamper_witness:
                self.send_response(404)
                self.end_headers()
                return
            payload = json.dumps(rec).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.end_headers()


class _AttackerRedirectSinkHandler(BaseHTTPRequestHandler):
    leaked_headers: list[str] = []

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        if auth:
            self.__class__.leaked_headers.append(auth)
        self.send_response(200)
        self.end_headers()

    def do_POST(self) -> None:
        auth = self.headers.get("Authorization", "")
        if auth:
            self.__class__.leaked_headers.append(auth)
        self.send_response(200)
        self.end_headers()


@pytest.fixture()
def live_servers():
    _LocalProviderHandler.store = {}
    _LocalProviderHandler.auth_headers_seen = []
    _LocalProviderHandler.tamper_witness = False
    _LocalProviderHandler.redirect_to = None
    _AttackerRedirectSinkHandler.leaked_headers = []

    provider_srv = HTTPServer(("127.0.0.1", 0), _LocalProviderHandler)
    attacker_srv = HTTPServer(("127.0.0.1", 0), _AttackerRedirectSinkHandler)
    t1 = threading.Thread(target=provider_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=attacker_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    try:
        yield (
            f"http://127.0.0.1:{provider_srv.server_port}",
            f"http://127.0.0.1:{attacker_srv.server_port}",
        )
    finally:
        provider_srv.shutdown()
        attacker_srv.shutdown()
        provider_srv.server_close()
        attacker_srv.server_close()


def _make_openapi_spec(base_url: str) -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": base_url}],
        "paths": {
            "/v1/refunds": {
                "post": {
                    "operationId": "stripe.refund.create",
                    "x-actenon-cost-field": "amount",
                    "x-actenon-witness": {
                        "path_template": "/v1/refunds/{id}",
                        "expected_status": [200],
                        "expected_fields": {"status": "succeeded"},
                    },
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["charge", "amount"],
                                    "properties": {
                                        "charge": {"type": "string"},
                                        "amount": {"type": "integer"},
                                        "reason": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                }
            }
        },
    }


def test_dynamic_openapi_strict_schema_validation_rejects_unknown_fields():
    adapter = OpenAPIDynamicAdapter.from_openapi(
        _make_openapi_spec("https://api.stripe.com"),
        provider_id="stripe",
        test_mode=True,
    )
    cred = Credential(ref="stripe_key", value="sk_test_SUPER_SECRET_123", source="env")

    with pytest.raises(InvalidParametersError) as exc_info:
        adapter.execute(
            "stripe.refund.create",
            {"charge": "ch_123", "amount": 120, "destination_override": "acct_evil"},
            cred,
        )
    assert any(err["field"] == "destination_override" for err in exc_info.value.errors)

    with pytest.raises(InvalidParametersError) as bool_exc:
        adapter.execute(
            "stripe.refund.create",
            {"charge": "ch_123", "amount": True},
            cred,
        )
    assert any(err["field"] == "amount" for err in bool_exc.value.errors)


def test_live_execution_and_witness_reconciliation_and_redaction(live_servers):
    provider_url, _attacker_url = live_servers
    adapter = OpenAPIDynamicAdapter.from_openapi(
        _make_openapi_spec(provider_url),
        provider_id="stripe",
        allow_loopback_for_tests=True,
    )
    secret_val = "sk_live_NEVER_LEAK_THIS_KEY_999"
    cred = Credential(ref="stripe_key", value=secret_val, source="env")

    resp = adapter.execute(
        "stripe.refund.create",
        {"charge": "ch_abc", "amount": 120},
        cred,
        idempotency_key="idem-refund-1",
    )
    assert resp.ok is True
    assert resp.provider_action_id == "re_1"
    assert resp.cost == 120.0
    assert resp.provider_evidence["reconcile_status"] == "verified"
    assert resp.provider_evidence["witness_verified"] is True
    assert secret_val not in json.dumps(resp.provider_evidence)


def test_witness_mismatch_raises_reconciliation_conflict_never_retries(live_servers):
    provider_url, _attacker_url = live_servers
    _LocalProviderHandler.tamper_witness = True
    adapter = OpenAPIDynamicAdapter.from_openapi(
        _make_openapi_spec(provider_url),
        provider_id="stripe",
        allow_loopback_for_tests=True,
    )
    cred = Credential(ref="stripe_key", value="sk_live_WITNESS_TEST", source="env")

    with pytest.raises(ReconciliationConflictError) as exc_info:
        adapter.execute(
            "stripe.refund.create",
            {"charge": "ch_abc", "amount": 120},
            cred,
        )
    assert exc_info.value.retryable is False
    # Prove the mutation was only dispatched once (never blindly retried)
    assert len(_LocalProviderHandler.auth_headers_seen) == 1


def test_cross_origin_redirect_blocks_credential_leakage(live_servers):
    provider_url, attacker_url = live_servers
    _LocalProviderHandler.redirect_to = f"{attacker_url}/collect"
    adapter = OpenAPIDynamicAdapter.from_openapi(
        _make_openapi_spec(provider_url),
        provider_id="stripe",
        allow_loopback_for_tests=True,
    )
    cred = Credential(ref="stripe_key", value="sk_live_ORIGIN_PINNED_SECRET", source="env")

    with pytest.raises(OriginRedirectError):
        adapter.execute(
            "stripe.refund.create",
            {"charge": "ch_abc", "amount": 120},
            cred,
        )
    assert _AttackerRedirectSinkHandler.leaked_headers == []


@pytest.mark.parametrize(
    "blocked_url",
    [
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.15/v1/internal",
        "http://192.168.1.10/admin",
        "http://127.0.0.1:8080/local",
    ],
)
def test_ssrf_guard_blocks_private_metadata_and_loopback_by_default(blocked_url: str):
    adapter = OpenAPIDynamicAdapter(
        provider_id="internal",
        base_url=blocked_url,
        operations=[
            OpenAPIOperationSpec(
                action="internal.ping",
                method="POST",
                path_template="/ping",
                required_params=(),
            )
        ],
        allow_loopback_for_tests=False,
    )
    cred = Credential(ref="k", value="secret", source="env")
    with pytest.raises(SSRFBlockedError):
        adapter.execute("internal.ping", {}, cred)
