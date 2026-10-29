"""Adversarial single-dispatch tests for the experimental OpenAPIDynamicAdapter.

These tests run against a real loopback HTTP server (no mocked transport) and
count the POSTs the provider actually received. They establish exactly what the
adapter guarantees and, equally important, what it does NOT guarantee:

* Within ONE adapter instance, concurrent callers sharing an idempotency key
  (or identical mutating params) dispatch at most one POST.
* A crash, response loss, or witness mismatch after dispatch leaves the
  operation OUTCOME_UNKNOWN and blocks retries on that instance.
* In-memory state does NOT survive a restart and is NOT shared across
  instances: without ``durable_state_path`` a fresh instance re-dispatches.
* With ``durable_state_path`` (SQLite), the guarantees hold across instances,
  threads racing on separate instances, and simulated process restarts.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from actenon_permit import (
    PDP,
    Broker,
    BrokerExecutionError,
    Credential,
    CredentialProviderRegistry,
    EnvironmentSecretProvider,
    Ledger,
    ReconciliationConflictError,
    SQLiteStore,
)
from actenon_permit.adapters.openapi import (
    OpenAPIDynamicAdapter,
    OpenAPIOperationSpec,
    WitnessSpec,
)
from actenon_permit.model import Action, Decision, DecisionOutcome
from actenon_permit.policy import compile_policy


class _SlowProvider(BaseHTTPRequestHandler):
    lock = threading.Lock()
    post_count = 0
    post_delay = 0.0
    drop_response = False
    witness_status = "succeeded"

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
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        with type(self).lock:
            type(self).post_count += 1
            n = type(self).post_count
        time.sleep(type(self).post_delay)
        if type(self).drop_response:
            # Effect happened server-side; the response is lost on the wire.
            self.close_connection = True
            self.connection.close()
            return
        self._send({"id": f"re_{n}", "status": "succeeded", **body})

    def do_GET(self) -> None:  # noqa: N802
        rid = self.path.rsplit("/", 1)[-1]
        self._send({"id": rid, "status": type(self).witness_status})


class _Server(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = True


@pytest.fixture
def provider():
    _SlowProvider.post_count = 0
    _SlowProvider.post_delay = 0.0
    _SlowProvider.drop_response = False
    _SlowProvider.witness_status = "succeeded"
    srv = _Server(("127.0.0.1", 0), _SlowProvider)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", _SlowProvider
    finally:
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
PARAMS = {"charge": "ch_1", "amount": 10}
CRED = Credential(ref="k", value="sk_test_concurrency", source="env")


def _adapter(base: str, **kw: Any) -> OpenAPIDynamicAdapter:
    return OpenAPIDynamicAdapter(
        provider_id="stripe", base_url=base, operations=OPS, allow_loopback_for_tests=True, **kw
    )


def _race(fns: list[Any]) -> list[Any]:
    barrier = threading.Barrier(len(fns))

    def run(fn: Any) -> Any:
        barrier.wait()
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - outcomes are asserted
            return exc

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        return list(pool.map(run, fns))


# --- opt-in defaults -------------------------------------------------------


def test_experimental_opt_in_defaults_false_and_production_refuses(monkeypatch, tmp_path) -> None:
    import inspect

    sig = inspect.signature(OpenAPIDynamicAdapter.__init__)
    assert sig.parameters["experimental_opt_in"].default is False
    assert inspect.signature(OpenAPIDynamicAdapter.from_openapi).parameters[
        "experimental_opt_in"
    ].default is False

    with pytest.raises(ValueError, match="experimental"):
        _adapter("https://api.example.com", production_mode=True)
    monkeypatch.setenv("ACTENON_ENV", "production")
    with pytest.raises(ValueError, match="experimental"):
        _adapter("https://api.example.com")
    # Opt-in alone is not enough in production: durable state is mandatory.
    with pytest.raises(ValueError, match="durable_state_path"):
        _adapter("https://api.example.com", experimental_opt_in=True)
    ok = _adapter(
        "https://api.example.com",
        experimental_opt_in=True,
        durable_state_path=tmp_path / "fx.db",
    )
    assert ok.health()["durable_state"] is True


def test_broker_production_refuses_experimental_adapter_without_opt_in(monkeypatch) -> None:
    monkeypatch.setenv("K", "sk_test_x")
    store = SQLiteStore()
    pdp = PDP(store, Ledger(store))
    reg = CredentialProviderRegistry()
    reg.register("k", EnvironmentSecretProvider({"k": "K"}))
    broker = Broker(pdp, credential_providers=reg, production_mode=True)
    adapter = _adapter("https://api.example.com", test_mode=True)  # constructed outside prod
    grant = compile_policy(
        {"agent": "a", "ttl": "1h", "budget": {"currency": "USD", "limit": 100},
         "scopes": {"allow": ["payment.refund"], "deny": []}}
    )
    action = Action(grant_id=grant.id, type="payment.refund", target="ch_1", params=PARAMS)
    decision = Decision(outcome=DecisionOutcome.ALLOW, reason="test")
    with pytest.raises(BrokerExecutionError) as ei:
        broker.execute_via_adapter(grant, action, decision, adapter, credential_ref="k")
    assert ei.value.rule == "broker:experimental_adapter_disabled"


# --- in-process single instance -------------------------------------------


def test_concurrent_same_idempotency_key_dispatches_once(provider) -> None:
    base, h = provider
    h.post_delay = 0.3
    a = _adapter(base)
    results = _race([lambda: a.execute("payment.refund", PARAMS, CRED, idempotency_key="k1")] * 8)
    successes = [r for r in results if not isinstance(r, Exception)]
    refusals = [r for r in results if isinstance(r, ReconciliationConflictError)]
    assert h.post_count == 1
    assert len(successes) == 1 and len(refusals) == 7
    assert all(r.retryable is False for r in refusals)
    # After completion, the key replays the stored result with no new POST.
    replay = a.execute("payment.refund", PARAMS, CRED, idempotency_key="k1")
    assert replay.provider_action_id == successes[0].provider_action_id
    assert h.post_count == 1


def test_concurrent_identical_params_without_key_dispatch_once(provider) -> None:
    base, h = provider
    h.post_delay = 0.3
    a = _adapter(base)
    results = _race([lambda: a.execute("payment.refund", PARAMS, CRED)] * 6)
    assert h.post_count == 1
    assert sum(isinstance(r, ReconciliationConflictError) for r in results) == 5


def test_crash_after_dispatch_locks_outcome_unknown(provider) -> None:
    base, h = provider

    def boom() -> None:
        raise RuntimeError("worker crashed after provider accepted request")

    a = _adapter(base, post_dispatch_hook=boom)
    with pytest.raises(RuntimeError):
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="k2")
    a.post_dispatch_hook = None
    with pytest.raises(ReconciliationConflictError, match="OUTCOME_UNKNOWN"):
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="k2")
    with pytest.raises(ReconciliationConflictError, match="OUTCOME_UNKNOWN"):
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="different-key")
    assert h.post_count == 1


def test_response_loss_locks_outcome_unknown(provider) -> None:
    base, h = provider
    h.drop_response = True
    a = _adapter(base)
    with pytest.raises(Exception):  # noqa: B017,PT011 - transport-specific error type
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="k3")
    h.drop_response = False
    with pytest.raises(ReconciliationConflictError, match="OUTCOME_UNKNOWN"):
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="k3")
    assert h.post_count == 1


def test_witness_mismatch_locks_outcome_unknown(provider) -> None:
    base, h = provider
    h.witness_status = "pending"
    a = _adapter(base)
    with pytest.raises(ReconciliationConflictError, match="witness state mismatch"):
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="k4")
    h.witness_status = "succeeded"
    with pytest.raises(ReconciliationConflictError, match="OUTCOME_UNKNOWN"):
        a.execute("payment.refund", PARAMS, CRED, idempotency_key="k4")
    assert h.post_count == 1


def test_connection_refused_is_not_dispatched_and_releases_reservation() -> None:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listening -> ECONNREFUSED before any bytes are sent
    a = _adapter(f"http://127.0.0.1:{port}")
    for _ in range(2):
        with pytest.raises(Exception, match="unreachable"):
            a.execute("payment.refund", PARAMS, CRED, idempotency_key="k5")


# --- documented limitation: in-memory state is per instance/process ---------


def test_in_memory_state_does_not_survive_restart_or_span_instances(provider) -> None:
    """Honest negative result: ephemeral guards are NOT a cross-process guarantee."""
    base, h = provider
    h.witness_status = "pending"
    first = _adapter(base)
    with pytest.raises(ReconciliationConflictError):
        first.execute("payment.refund", PARAMS, CRED, idempotency_key="k6")
    h.witness_status = "succeeded"
    restarted = _adapter(base)  # equivalent to a new process / another worker
    restarted.execute("payment.refund", PARAMS, CRED, idempotency_key="k6")
    assert h.post_count == 2  # duplicate dispatch: why production requires durable state


# --- durable SQLite state ---------------------------------------------------


def test_durable_state_blocks_retry_after_restart(provider, tmp_path: Path) -> None:
    base, h = provider
    db = tmp_path / "effects.db"
    h.witness_status = "pending"
    with pytest.raises(ReconciliationConflictError):
        _adapter(base, durable_state_path=db).execute(
            "payment.refund", PARAMS, CRED, idempotency_key="k7"
        )
    h.witness_status = "succeeded"
    restarted = _adapter(base, durable_state_path=db)
    with pytest.raises(ReconciliationConflictError, match="OUTCOME_UNKNOWN"):
        restarted.execute("payment.refund", PARAMS, CRED, idempotency_key="k7")
    with pytest.raises(ReconciliationConflictError):
        restarted.execute("payment.refund", PARAMS, CRED, idempotency_key="other")
    assert h.post_count == 1


def test_durable_state_crash_mid_flight_stays_locked_after_restart(provider, tmp_path) -> None:
    """A process killed between dispatch and recording leaves IN_FLIGHT, which fails closed."""
    base, h = provider
    db = tmp_path / "effects.db"
    a = _adapter(base, durable_state_path=db)
    # Simulate SIGKILL: reserve, dispatch, then never record an outcome.
    a._reserve_or_check_execution(
        "payment.refund", __import__("actenon_permit.adapters.openapi", fromlist=["x"])
        ._hash_params("payment.refund", PARAMS), "k8", is_mutation=True,
    )
    restarted = _adapter(base, durable_state_path=db)
    with pytest.raises(ReconciliationConflictError, match="IN_FLIGHT"):
        restarted.execute("payment.refund", PARAMS, CRED, idempotency_key="k8")
    assert h.post_count == 0


def test_durable_state_concurrent_separate_instances_dispatch_once(provider, tmp_path) -> None:
    base, h = provider
    h.post_delay = 0.3
    db = tmp_path / "effects.db"
    instances = [_adapter(base, durable_state_path=db) for _ in range(6)]
    results = _race(
        [
            (lambda inst=inst: inst.execute("payment.refund", PARAMS, CRED, idempotency_key="k9"))
            for inst in instances
        ]
    )
    assert h.post_count == 1
    assert sum(isinstance(r, ReconciliationConflictError) for r in results) == 5
    # Completed result replays from SQLite on a brand-new instance.
    replay = _adapter(base, durable_state_path=db).execute(
        "payment.refund", PARAMS, CRED, idempotency_key="k9"
    )
    assert replay.ok and h.post_count == 1
