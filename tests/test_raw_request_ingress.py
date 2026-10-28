"""Raw transport rejects before authority evaluation, intent state or dispatch.

These are local FastAPI/MCP entrypoints and real Permit grants. No provider
network is contacted. Existing intent/submit tests retain valid full flows.
"""

import io
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from actenon_permit import PDP, Broker, Gateway, Ledger, SQLiteStore, ToolRegistry
from actenon_permit._intent_routes import mount as mount_intents
from actenon_permit._proxy_routes import mount as mount_proxy
from actenon_permit.gateway import mcp_serve
from actenon_permit.model import Budget, Grant, Scopes
from actenon_permit.token import grant_to_token


@pytest.fixture
def ingress(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "public-raw-ingress-regression-key")
    store = SQLiteStore(str(tmp_path / "ingress.db"))
    ledger, calls, dispatched = Ledger(store), [], []
    pdp = PDP(store, ledger)
    grant = Grant(
        agent_id="raw-ingress-test",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        scopes=Scopes(allow=["test.typed"]),
        budget=Budget(limit=10, remaining=10),
    ).sign()
    store.put_grant(grant)
    tools = ToolRegistry()
    tools.register("typed", action_type="test.typed", real_call=lambda **p: dispatched.append(p))
    gateway = Gateway(state=store, ledger=ledger, pdp=pdp, broker=Broker(pdp), tools=tools)
    for name in ("call_tool", "create_intent", "execute_intent", "submit_intent_to_resource"):
        original = getattr(gateway, name)

        def observed(*args, _name=name, _original=original, **kwargs):
            calls.append(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(gateway, name, observed)
    app = FastAPI()
    mount_proxy(app, gateway)
    mount_intents(app, gateway)
    yield gateway, TestClient(app), grant_to_token(grant), calls, dispatched
    store.close()


INVALID_RAW = [
    pytest.param(b'{"x":\xff}', id="malformed-utf8"),
    pytest.param(b'{"x":1,"x":2}', id="duplicate"),
    pytest.param(b'{"x":1,"\\u0078":2}', id="escaped-duplicate"),
    pytest.param(b'{"x":1.0}', id="float"),
    pytest.param(b'{"x":-0.0}', id="negative-float-zero"),
    pytest.param(b'{"x":NaN}', id="nan"),
    pytest.param(b'{"x":"\\ud800"}', id="surrogate"),
    pytest.param(b'{"x":' + b"[" * 33 + b"0" + b"]" * 33 + b"}", id="deep"),
    pytest.param(b'{"x":"' + b"a" * 1_048_576 + b'"}', id="oversized"),
    pytest.param(b'{"x":', id="malformed-json"),
    pytest.param(b"[]", id="array"),
    pytest.param(b"null", id="null"),
]


@pytest.mark.parametrize("raw", INVALID_RAW)
@pytest.mark.parametrize(
    "path", ["/proxy/typed", "/intents", "/intents/absent/execute", "/intents/absent/submit"]
)
def test_raw_http_refused_before_gateway(ingress, raw, path):
    _, client, token, calls, dispatched = ingress
    response = client.post(
        path,
        content=raw,
        headers={
            "x-actenon-grant": token,
            "content-type": "application/json",
        },
    )
    assert response.status_code in (400, 403, 422), response.text
    assert calls == [], f"invalid raw representation reached gateway: {calls}"
    assert dispatched == []


def test_proxy_valid_typed_unicode_request_dispatches(ingress):
    _, client, token, calls, dispatched = ingress
    params = {"x": 2**100, "label": "雪ée\u0301", "enabled": True}
    response = client.post("/proxy/typed", json=params, headers={"x-actenon-grant": token})
    assert response.status_code == 200, response.text
    assert calls == ["call_tool"]
    assert dispatched == [params]


def test_execute_empty_body_remains_supported(ingress):
    _, client, token, calls, _ = ingress
    response = client.post("/intents/absent/execute", headers={"x-actenon-grant": token})
    assert response.status_code == 403
    assert calls == ["execute_intent"]


def test_execute_body_cannot_smuggle_unused_overrides(ingress):
    _, client, token, calls, _ = ingress
    response = client.post(
        "/intents/absent/execute", json={"target_id": "new"}, headers={"x-actenon-grant": token}
    )
    assert response.status_code == 400
    assert calls == []


@pytest.mark.parametrize("raw", INVALID_RAW)
def test_raw_mcp_refused_without_dispatch(ingress, raw):
    gateway, _, token, calls, dispatched = ingress
    # Place the invalid value inside the arguments of an otherwise genuine call.
    line = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"typed","arguments":'
        + raw
        + b"}}\n"
    )
    output = io.StringIO()
    mcp_serve(gateway, infile=io.BytesIO(line), outfile=output, grant_token=token)
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(responses) == 1
    assert "error" in responses[0], responses
    assert calls == []
    assert dispatched == []


def test_mcp_oversized_frame_drains_without_executing_suffix(ingress):
    gateway, _, token, calls, _ = ingress
    oversized = b'{"padding":"' + b"x" * 1_048_577 + b'"}\n'
    ping = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    output = io.StringIO()
    mcp_serve(gateway, infile=io.BytesIO(oversized + ping), outfile=output, grant_token=token)
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(responses) == 2
    assert "error" in responses[0]
    assert responses[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert calls == []


def test_mcp_valid_unicode_typed_call_preserved(ingress):
    gateway, _, token, calls, dispatched = ingress
    arguments = {"x": 2**100, "label": "雪", "enabled": True}
    raw = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "typed",
                "method": "tools/call",
                "params": {"name": "typed", "arguments": arguments},
            },
            ensure_ascii=False,
        ).encode()
        + b"\n"
    )
    output = io.StringIO()
    mcp_serve(gateway, infile=io.BytesIO(raw), outfile=output, grant_token=token)
    assert json.loads(output.getvalue())["result"]["isError"] is False
    assert calls == ["call_tool"]
    assert dispatched == [arguments]


@pytest.mark.parametrize(
    "extra",
    [
        {"Action_Type": "test.other"},
        {"unused": True},
        {"action_params": []},
        {"target_id": 1},
        {"expiry_seconds": True},
        {"metadata": []},
    ],
)
def test_create_wrapper_rejects_unknown_or_wrongly_typed_fields(ingress, extra):
    _, client, _, calls, _ = ingress
    body = {
        "action_type": "test.typed",
        "action_params": {"x": 1},
        "target_type": "test",
        "target_id": "fixture",
        "requested_execution_mode": "brokered",
        "requester_subject": "operator",
        "requester_agent_id": "agent",
        **extra,
    }
    response = client.post("/intents", json=body)
    assert response.status_code in (400, 422)
    assert calls == []


@pytest.mark.parametrize("extra", [{"Proof": {}}, {"target_id": "other"}])
def test_submission_rejects_unknown_wrapper_fields(ingress, extra):
    _, client, _, calls, _ = ingress
    response = client.post("/intents/absent/submit", json={"proof": {}, **extra})
    assert response.status_code == 400
    assert calls == []


@pytest.mark.parametrize(
    "params",
    [
        [],
        None,
        {"name": "typed", "Name": "other"},
        {"name": "typed", "arguments": []},
        {"name": "typed", "arguments": None},
        {"name": "typed", "_meta": []},
        {"name": "typed", "_meta": {"actenon_grant": 1}},
    ],
)
def test_mcp_wrong_wrapper_does_not_dispatch(ingress, params):
    gateway, _, token, calls, dispatched = ingress
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
    output = io.StringIO()
    mcp_serve(gateway, infile=io.StringIO(raw + "\n"), outfile=output, grant_token=token)
    assert json.loads(output.getvalue())["error"]["code"] == -32602
    assert calls == dispatched == []


@pytest.mark.parametrize("extra", [{"Method": "tools/call"}, {"id": True}, {"jsonrpc": 2}])
def test_mcp_unknown_or_wrongly_typed_envelope_refused(ingress, extra):
    gateway, _, token, calls, _ = ingress
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", **extra})
    output = io.StringIO()
    mcp_serve(gateway, infile=io.StringIO(raw + "\n"), outfile=output, grant_token=token)
    assert json.loads(output.getvalue())["error"]["code"] == -32600
    assert calls == []
