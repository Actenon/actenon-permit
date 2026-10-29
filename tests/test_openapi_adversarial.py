"""Independent adversarial checks of the experimental OpenAPIDynamicAdapter.

These complement test_openapi_concurrency.py (threads inside one process) with
boundaries that only real separate processes, real process death, real state
loss and real environment configuration can exercise. Every assertion counts
what a loopback provider actually received, not what the adapter reported.

Some tests pin down limitations rather than guarantees; their names say so.
"""

from __future__ import annotations

import json
import os
import posixpath
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from actenon_permit import Credential, ReconciliationConflictError
from actenon_permit.adapters.openapi import (
    OpenAPIDynamicAdapter,
    OpenAPIOperationSpec,
    WitnessSpec,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

CRED = Credential(ref="k", value="sk_test_adversarial", source="env")
PARAMS = {"charge": "ch_1", "amount": 10}


class _Provider(BaseHTTPRequestHandler):
    """Loopback provider recording every request it receives."""

    lock = threading.Lock()
    posts: list[dict[str, Any]] = []
    gets: list[str] = []
    hold = threading.Event()
    mode = "ok"  # ok | hold | drop
    witness: dict[str, dict[str, Any]] = {}

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send(self, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        cls = type(self)
        with cls.lock:
            cls.posts.append({"path": self.path, "auth": self.headers.get("Authorization")})
            n = len(cls.posts)
        if cls.mode == "hold":
            cls.hold.wait(30)
        if cls.mode == "drop":
            self.close_connection = True
            self.connection.close()
            return
        self._send({"id": f"re_{n}", "status": "succeeded", **body})

    def do_GET(self) -> None:  # noqa: N802
        cls = type(self)
        path = posixpath.normpath(self.path)  # what a typical provider router does
        with cls.lock:
            cls.gets.append(self.path)
        if path in cls.witness:
            self._send(cls.witness[path])
        elif path.startswith("/v1/refunds/"):  # genuine refund witness for OPS
            self._send({"id": path.rsplit("/", 1)[-1], "status": "succeeded"})
        else:
            self._send({"id": path.rsplit("/", 1)[-1], "status": "failed"})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[_Server, str]:
    srv = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def provider():
    _Provider.posts = []
    _Provider.gets = []
    _Provider.hold = threading.Event()
    _Provider.mode = "ok"
    _Provider.witness = {}
    srv, base = _serve(_Provider)
    try:
        yield base, _Provider
    finally:
        _Provider.hold.set()
        srv.shutdown()
        srv.server_close()


OPS = [
    OpenAPIOperationSpec(
        action="payment.refund",
        method="POST",
        path_template="/v1/refunds",
        required_params=("charge", "amount"),
        param_types={"charge": str, "amount": int},
        witness=WitnessSpec(
            path_template="/v1/refunds/{id}",
            expected_fields={"status": "succeeded"},
            verify_shared_request_fields=False,
        ),
    )
]


def _adapter(base: str, **kw: Any) -> OpenAPIDynamicAdapter:
    return OpenAPIDynamicAdapter(
        provider_id="stripe", base_url=base, operations=OPS, allow_loopback_for_tests=True, **kw
    )


CHILD = r"""
import json, sys, time
from pathlib import Path
from actenon_permit import Credential
from actenon_permit.adapters.openapi import OpenAPIDynamicAdapter, OpenAPIOperationSpec, WitnessSpec
base, db, key, start = sys.argv[1:5]
ops = [OpenAPIOperationSpec(action="payment.refund", method="POST", path_template="/v1/refunds",
    required_params=("charge", "amount"), param_types={"charge": str, "amount": int},
    witness=WitnessSpec(path_template="/v1/refunds/{id}", expected_fields={"status": "succeeded"},
    verify_shared_request_fields=False))]
adapter = OpenAPIDynamicAdapter(provider_id="stripe", base_url=base, operations=ops,
    allow_loopback_for_tests=True, durable_state_path=db if db != "-" else None)
while not Path(start).exists():
    time.sleep(0.001)
try:
    adapter.execute("payment.refund", {"charge": "ch_1", "amount": 10},
        Credential(ref="k", value="sk_test_adversarial", source="env"), idempotency_key=key)
    print(json.dumps({"outcome": "dispatched"}))
except Exception as exc:
    print(json.dumps({"outcome": type(exc).__name__, "retryable": getattr(exc, "retryable", None)}))
"""


def _spawn(base: str, db: str, key: str, start: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", CHILD, base, db, key, str(start)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONHASHSEED": str(os.getpid())},
    )


def _wait_for(predicate, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.01)


# --- separate processes ------------------------------------------------------


def test_separate_processes_sharing_durable_state_dispatch_once(provider, tmp_path) -> None:
    base, server = provider
    server.mode = "hold"
    db, start = str(tmp_path / "effects.db"), tmp_path / "go"
    procs = [_spawn(base, db, "refund-ch_1", start) for _ in range(6)]
    time.sleep(1.0)  # all six interpreters import and park on the start file
    start.touch()
    _wait_for(lambda: len(server.posts) >= 1)
    time.sleep(1.0)  # give any duplicate the chance to arrive while the first is held
    server.hold.set()
    outcomes = [json.loads(p.communicate(timeout=60)[0].strip().splitlines()[-1]) for p in procs]
    assert len(server.posts) == 1, outcomes
    assert sorted(o["outcome"] for o in outcomes).count("dispatched") == 1
    refused = [o for o in outcomes if o["outcome"] != "dispatched"]
    assert all(o == {"outcome": "ReconciliationConflictError", "retryable": False} for o in refused)


def test_sigkill_mid_flight_leaves_effect_owned_after_restart(provider, tmp_path) -> None:
    base, server = provider
    server.mode = "hold"
    db, start = str(tmp_path / "effects.db"), tmp_path / "go"
    start.touch()
    child = _spawn(base, db, "refund-ch_1", start)
    _wait_for(lambda: len(server.posts) == 1)
    child.send_signal(signal.SIGKILL)  # no Python cleanup, no finally blocks
    child.wait(timeout=10)
    server.hold.set()
    server.mode = "ok"
    restarted = _adapter(base, durable_state_path=db)
    with pytest.raises(ReconciliationConflictError) as exc:
        restarted.execute("payment.refund", PARAMS, CRED, idempotency_key="refund-ch_1")
    assert exc.value.retryable is False
    with pytest.raises(ReconciliationConflictError):  # same effect under a fresh key
        restarted.execute("payment.refund", PARAMS, CRED, idempotency_key="refund-ch_1-retry")
    assert len(server.posts) == 1


def test_limitation_in_memory_state_is_per_process(provider, tmp_path) -> None:
    """Without durable state a second process re-dispatches after response loss."""
    base, server = provider
    server.mode = "drop"
    start = tmp_path / "go"
    start.touch()
    first = json.loads(_spawn(base, "-", "k1", start).communicate(timeout=60)[0].splitlines()[-1])
    assert first["outcome"] != "dispatched"
    second = json.loads(_spawn(base, "-", "k1", start).communicate(timeout=60)[0].splitlines()[-1])
    assert second["outcome"] != "dispatched"
    assert len(server.posts) == 2  # the provider received the mutation twice


# --- durable state integrity ---------------------------------------------------


def test_limitation_deleting_durable_state_forfeits_ownership(provider, tmp_path) -> None:
    base, server = provider
    db = tmp_path / "effects.db"
    server.mode = "drop"
    with pytest.raises(Exception):  # noqa: B017 - any post-send failure
        _adapter(base, durable_state_path=db).execute(
            "payment.refund", PARAMS, CRED, idempotency_key="k1"
        )
    db.unlink()
    server.mode = "ok"
    _adapter(base, durable_state_path=db).execute(
        "payment.refund", PARAMS, CRED, idempotency_key="k1"
    )
    assert len(server.posts) == 2


def test_corrupted_durable_state_fails_closed_before_dispatch(provider, tmp_path) -> None:
    base, server = provider
    db = tmp_path / "effects.db"
    adapter = _adapter(base, durable_state_path=db)
    db.write_bytes(b"not a sqlite database" * 100)
    with pytest.raises(Exception) as exc:  # noqa: B017
        adapter.execute("payment.refund", PARAMS, CRED, idempotency_key="k1")
    assert "database" in str(exc.value).lower()
    assert server.posts == []


# --- environment and witness steering ----------------------------------------


class _Recorder(BaseHTTPRequestHandler):
    seen: list[dict[str, Any]] = []

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _record(self) -> None:
        type(self).seen.append({"line": self.requestline, "auth": self.headers.get("Authorization")})
        self.send_response(502)
        self.end_headers()

    do_GET = do_POST = do_CONNECT = _record  # noqa: N815


def test_ambient_proxy_environment_is_not_used(provider, monkeypatch) -> None:
    base, server = provider
    _Recorder.seen = []
    proxy, proxy_url = _serve(_Recorder)
    try:
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
            monkeypatch.setenv(name, proxy_url)
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        response = _adapter(base).execute("payment.refund", PARAMS, CRED, idempotency_key="k1")
    finally:
        proxy.shutdown()
        proxy.server_close()
    assert _Recorder.seen == [], "credential-bearing request reached the environment proxy"
    assert len(server.posts) == 1 and response.ok


STEERED = [
    OpenAPIOperationSpec(
        action="payment.refund",
        method="POST",
        path_template="/v1/refunds",
        required_params=("charge", "amount"),
        param_types={"charge": str, "amount": int},
        witness=WitnessSpec(
            path_template="/v1/charges/{charge}/refunds/{id}",
            expected_fields={"status": "succeeded"},
            verify_shared_request_fields=False,
        ),
    )
]


@pytest.mark.parametrize("charge", ["../../decoy", "ch_1/../../../decoy", "x?status=succeeded"])
def test_request_params_cannot_steer_witness_to_a_decoy(provider, charge: str) -> None:
    base, server = provider
    # The genuine refund witness reports failure; a decoy elsewhere reports success.
    server.witness = {
        "/decoy/refunds/re_1": {"id": "re_1", "status": "succeeded"},
        "/v1/charges/x": {"id": "re_1", "status": "succeeded"},
    }
    adapter = OpenAPIDynamicAdapter(
        provider_id="stripe", base_url=base, operations=STEERED, allow_loopback_for_tests=True
    )
    with pytest.raises(ReconciliationConflictError):
        adapter.execute("payment.refund", {"charge": charge, "amount": 10}, CRED)
    assert all("decoy" not in g and "?" not in g for g in server.gets), server.gets
    with pytest.raises(ReconciliationConflictError):  # held, not retried
        adapter.execute("payment.refund", {"charge": charge, "amount": 10}, CRED)
    assert len(server.posts) == 1


def test_safe_request_param_in_witness_path_still_verifies(provider) -> None:
    base, server = provider
    server.witness = {"/v1/charges/ch_1/refunds/re_1": {"id": "re_1", "status": "succeeded"}}
    adapter = OpenAPIDynamicAdapter(
        provider_id="stripe", base_url=base, operations=STEERED, allow_loopback_for_tests=True
    )
    response = adapter.execute("payment.refund", PARAMS, CRED)
    assert response.provider_evidence["witness_verified"] is True
    assert server.gets == ["/v1/charges/ch_1/refunds/re_1"]
