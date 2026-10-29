"""Experimental OpenAPI / HTTP Dynamic Capability Adapter with Witness Reconciliation.

NOTE: This adapter is **experimental** (``EXPERIMENTAL = True``) and is disabled
by default in production (``experimental_opt_in: bool = False``). It is excluded
from the first supported production profile (where ``GitHubAdapter`` is the
supported production adapter). It implements HTTP/OpenAPI capability execution
with post-action read-only ``GET`` witness reconciliation; it is **not** an MCP
JSON-RPC transport implementation.

Key properties:
1. **Dynamic Strict Schema Validation:** Validates action parameters against
   explicit ``OpenAPIOperationSpec`` definitions (rejecting unknown fields,
   missing required fields, non-nullable ``None`` values, ``bool`` masquerading
   as ``int``/``float``, out-of-range numbers, invalid enum values, and unsafe
   path segments with ``InvalidParametersError``). Unsupported OpenAPI schema
   composition keywords (``$ref``, ``oneOf``, ``anyOf``, ``allOf``) are rejected
   at spec-compilation time rather than silently widened to ``str``.
2. **Origin-Pinned Credentials, HTTPS Enforcement & DNS-Bound SSRF Defense:**
   Pins credentials to a single verified origin (``scheme://host[:port]``),
   requires ``https`` whenever a live credential is transmitted (unless
   ``allow_loopback_for_tests=True`` on a loopback target), binds DNS resolution
   directly to the outbound TCP connection to prevent DNS rebinding TOCTOU,
   bounds response reads to ``MAX_RESPONSE_BYTES``, and blocks cross-origin
   redirects.
3. **In-Flight Reservation, Crash/Restart Protection & Witness Reconciliation:**
   Reserves ``IN_FLIGHT`` state before network dispatch so concurrent callers
   using the same ``idempotency_key`` (or identical mutating parameters) cannot
   dispatch duplicate operations before the first completes. Supports durable
   SQLite persistence (``durable_state_path``) across adapter instances and
   process restarts (mandatory when ``production_mode=True`` or
   ``ACTENON_ENV=production``). Any mid-flight crash, response loss, or witness
   mismatch transitions the operation to ``OUTCOME_UNKNOWN`` and fails closed on
   retry with ``ReconciliationConflictError(retryable=False)``.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..credentials import Credential
from . import (
    AdapterError,
    InvalidParametersError,
    ProviderAdapter,
    ProviderPartialResponseError,
    ProviderResponse,
    ProviderTimeoutError,
    ReconciliationConflictError,
    UnsupportedActionError,
    ValidationResult,
)

_SAFE_PATH_PARAM_RE = re.compile(r"^[A-Za-z0-9._:@-]+$")
_TEMPLATE_PARAM_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB hard cap on provider HTTP responses
_UNSUPPORTED_SCHEMA_KEYWORDS = ("$ref", "oneOf", "anyOf", "allOf", "not")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class SSRFBlockedError(AdapterError):
    """Raised when a target URL, scheme, or resolved IP violates SSRF/origin policy."""

    def __init__(self, safe_message: str, *, provider: str = ""):
        super().__init__(safe_message, retryable=False, provider=provider)


class OriginRedirectError(AdapterError):
    """Raised when an HTTP redirect attempts to leave the pinned credential origin."""

    def __init__(self, safe_message: str, *, provider: str = ""):
        super().__init__(safe_message, retryable=False, provider=provider)


@dataclass(frozen=True)
class WitnessSpec:
    """Read-only witness probe configuration for post-action reconciliation."""

    path_template: str
    expected_status: tuple[int, ...] = (200,)
    expected_fields: dict[str, Any] = field(default_factory=dict)
    id_param_from_response: str = "id"
    bind_request_params: tuple[str, ...] = ()
    verify_shared_request_fields: bool = True


@dataclass(frozen=True)
class OpenAPIOperationSpec:
    """Strict schema and execution contract for one dynamic HTTP capability."""

    action: str
    method: str
    path_template: str
    required_params: tuple[str, ...] = ()
    optional_params: dict[str, Any] = field(default_factory=dict)
    param_types: dict[str, type | tuple[type, ...]] = field(default_factory=dict)
    nullable_params: tuple[str, ...] = ()
    param_enums: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    param_bounds: dict[str, tuple[int | float | None, int | float | None]] = field(
        default_factory=dict
    )
    path_params: tuple[str, ...] = ()
    response_id_field: str = "id"
    required_response_fields: tuple[str, ...] = ("id",)
    cost_field: str | None = None
    witness: WitnessSpec | None = None


def _extract_origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("URL is missing hostname")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _format_origin(scheme: str, host: str, port: int) -> str:
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(addr.is_loopback)


def _check_ip_allowed(
    ip_str: str, *, allow_loopback_for_tests: bool, provider: str
) -> None:
    addr = ipaddress.ip_address(ip_str)
    if addr.is_loopback:
        if not allow_loopback_for_tests:
            raise SSRFBlockedError(
                f"SSRF guard blocked loopback address {ip_str}", provider=provider
            )
        return
    if (
        addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        raise SSRFBlockedError(
            f"SSRF guard blocked non-public address {ip_str}", provider=provider
        )


def _validate_target_ssrf(
    url: str,
    *,
    pinned_origin: tuple[str, str, int],
    allow_loopback_for_tests: bool,
    provider: str,
) -> str:
    """Validate URL origin and SSRF policy and return the pinned target IP string."""
    try:
        scheme, host, port = _extract_origin(url)
    except ValueError as exc:
        raise SSRFBlockedError(str(exc), provider=provider) from exc

    if (scheme, host, port) != pinned_origin:
        raise OriginRedirectError(
            f"target origin {_format_origin(scheme, host, port)} does not match pinned origin {_format_origin(*pinned_origin)}",
            provider=provider,
        )

    # Literal IP check
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _check_ip_allowed(
            host, allow_loopback_for_tests=allow_loopback_for_tests, provider=provider
        )
        return host

    if host == "localhost" and not allow_loopback_for_tests:
        raise SSRFBlockedError(
            "SSRF guard blocked localhost target", provider=provider
        )

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AdapterError(
            f"DNS resolution failed for host {host}",
            retryable=True,
            provider=provider,
        ) from exc

    if not infos:
        raise AdapterError(
            f"DNS resolution returned no addresses for host {host}",
            retryable=True,
            provider=provider,
        )

    validated_ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip_str = str(sockaddr[0])
        _check_ip_allowed(
            ip_str, allow_loopback_for_tests=allow_loopback_for_tests, provider=provider
        )
        validated_ips.append(ip_str)

    return validated_ips[0]


class _PinnedIPHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects directly to the SSRF-validated IP address."""

    def __init__(self, host: str, port: int | None = None, *, resolved_ip: str, **kwargs: Any):
        super().__init__(host, port, **kwargs)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._resolved_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedIPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to the SSRF-validated IP while verifying TLS for host."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        resolved_ip: str,
        context: ssl.SSLContext | None = None,
        **kwargs: Any,
    ):
        super().__init__(host, port, context=context, **kwargs)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        raw_sock = socket.create_connection(
            (self._resolved_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self.sock = raw_sock
            self._tunnel()
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        ssl_ctx = self._context if hasattr(self, "_context") else ssl.create_default_context()
        self.sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=server_hostname)


class _PinnedIPHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, *, resolved_ip: str):
        super().__init__()
        self._resolved_ip = resolved_ip

    def http_open(self, req: urllib.request.Request):
        return self.do_open(
            lambda host, **kw: _PinnedIPHTTPConnection(
                host, resolved_ip=self._resolved_ip, **kw
            ),
            req,
        )


class _PinnedIPHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, *, resolved_ip: str):
        super().__init__()
        self._resolved_ip = resolved_ip

    def https_open(self, req: urllib.request.Request):
        return self.do_open(
            lambda host, **kw: _PinnedIPHTTPSConnection(
                host, resolved_ip=self._resolved_ip, **kw
            ),
            req,
        )


class _OriginPinnedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses any cross-origin or SSRF-unsafe redirect before headers are forwarded."""

    def __init__(
        self,
        *,
        pinned_origin: tuple[str, str, int],
        allow_same_origin_redirects: bool,
        allow_loopback_for_tests: bool,
        provider: str,
    ):
        super().__init__()
        self._pinned_origin = pinned_origin
        self._allow_same_origin_redirects = allow_same_origin_redirects
        self._allow_loopback_for_tests = allow_loopback_for_tests
        self._provider = provider

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        try:
            target_origin = _extract_origin(resolved_url)
        except ValueError as exc:
            raise OriginRedirectError(
                f"redirect target has invalid origin: {exc}", provider=self._provider
            ) from exc

        if target_origin != self._pinned_origin:
            raise OriginRedirectError(
                f"blocked cross-origin redirect from {_format_origin(*self._pinned_origin)} to {_format_origin(*target_origin)} (HTTP {code})",
                provider=self._provider,
            )
        if not self._allow_same_origin_redirects:
            raise OriginRedirectError(
                f"redirects are disabled for origin-pinned requests (HTTP {code})",
                provider=self._provider,
            )
        _validate_target_ssrf(
            resolved_url,
            pinned_origin=self._pinned_origin,
            allow_loopback_for_tests=self._allow_loopback_for_tests,
            provider=self._provider,
        )
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


_JSON_SCHEMA_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _parse_field_schema(
    field_name: str, schema: dict[str, Any]
) -> tuple[
    type | tuple[type, ...],
    bool,
    tuple[Any, ...] | None,
    tuple[int | float | None, int | float | None] | None,
]:
    """Validate and extract strict type, nullability, enum, and numeric bounds from an OpenAPI property schema."""
    for kw in _UNSUPPORTED_SCHEMA_KEYWORDS:
        if kw in schema:
            raise ValueError(
                f"OpenAPI schema for parameter {field_name!r} uses unsupported keyword {kw!r}; "
                "refusing to widen schema to str"
            )
    raw_type = schema.get("type")
    if not isinstance(raw_type, str) or raw_type not in _JSON_SCHEMA_TYPE_MAP:
        raise ValueError(
            f"OpenAPI schema for parameter {field_name!r} must declare a supported scalar/container type, got {raw_type!r}"
        )
    if raw_type == "object" and schema.get("additionalProperties") not in (None, False):
        raise ValueError(
            f"OpenAPI object schema for parameter {field_name!r} must not enable unconstrained additionalProperties"
        )
    py_type = _JSON_SCHEMA_TYPE_MAP[raw_type]
    nullable = bool(schema.get("nullable", False))
    enum_vals = tuple(schema["enum"]) if isinstance(schema.get("enum"), list) else None
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    bounds = (
        (minimum, maximum)
        if (isinstance(minimum, (int, float)) or isinstance(maximum, (int, float)))
        else None
    )
    return py_type, nullable, enum_vals, bounds


class OpenAPIDynamicAdapter(ProviderAdapter):
    """Experimental OpenAPI / HTTP Dynamic Capability Adapter with Witness Reconciliation.

    Disabled by default in production (``experimental_opt_in=False``). When opted
    into production (``production_mode=True`` or ``ACTENON_ENV=production``),
    requires ``durable_state_path`` so in-flight reservations, uncertain outcomes,
    and idempotency records survive process crashes and restarts.
    """

    EXPERIMENTAL = True

    def __init__(
        self,
        *,
        provider_id: str,
        base_url: str,
        operations: Sequence[OpenAPIOperationSpec],
        test_mode: bool = False,
        allow_loopback_for_tests: bool = False,
        allow_same_origin_redirects: bool = False,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        experimental_opt_in: bool = False,
        production_mode: bool = False,
        block_uncertain_retries: bool = True,
        durable_state_path: str | Path | None = None,
        require_durable_state: bool = False,
        post_dispatch_hook: Callable[[], None] | None = None,
    ):
        is_prod = (
            production_mode
            or os.environ.get("ACTENON_ENV", "").strip().lower() == "production"
        )
        if is_prod and not experimental_opt_in:
            raise ValueError(
                "OpenAPIDynamicAdapter is experimental and excluded from the supported "
                "production profile; pass experimental_opt_in=True to explicitly opt in."
            )
        if (is_prod or require_durable_state) and durable_state_path is None:
            raise ValueError(
                "OpenAPIDynamicAdapter requires durable_state_path when production_mode=True "
                "or require_durable_state=True; in-memory idempotency/uncertain caches do not "
                "survive process restarts or span worker processes."
            )
        self.provider_id = provider_id
        self.base_url = base_url.rstrip("/")
        self._pinned_origin = _extract_origin(self.base_url)
        self.pinned_origin = _format_origin(*self._pinned_origin)
        self.test_mode = test_mode
        self.allow_loopback_for_tests = allow_loopback_for_tests
        self.allow_same_origin_redirects = allow_same_origin_redirects
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self.experimental_opt_in = experimental_opt_in
        self.production_mode = production_mode
        self.block_uncertain_retries = block_uncertain_retries
        self.durable_state_path = Path(durable_state_path) if durable_state_path else None
        self.require_durable_state = require_durable_state or is_prod
        self.post_dispatch_hook = post_dispatch_hook
        self._operations: dict[str, OpenAPIOperationSpec] = {
            op.action: op for op in operations
        }
        # Process-local, per-instance guards. These do NOT survive a process
        # restart and are NOT shared between adapter instances or worker
        # processes. Cross-instance / cross-restart single-dispatch requires
        # ``durable_state_path`` (SQLite, BEGIN IMMEDIATE serialised).
        self._lock = threading.RLock()
        self._idem_cache: dict[str, tuple[int, ProviderResponse]] = {}
        self._uncertain_keys: dict[str, str] = {}
        self._uncertain_actions: dict[tuple[str, int], str] = {}
        self._inflight_keys: dict[str, int] = {}
        self._inflight_actions: set[tuple[str, int]] = set()
        if self.durable_state_path is not None:
            self._init_durable_db()

    def _init_durable_db(self) -> None:
        assert self.durable_state_path is not None
        self.durable_state_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.durable_state_path), timeout=30.0) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS openapi_adapter_effects (
                    scope_key TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    params_hash TEXT NOT NULL,
                    response_json TEXT,
                    error_reason TEXT
                )
                """
            )
            conn.commit()

    def _durable_scope_keys(
        self, action: str, params_hash: int, idempotency_key: str | None
    ) -> tuple[str | None, str]:
        idem_scope = (
            f"idem:{self.provider_id}:{self.pinned_origin}:{idempotency_key}"
            if idempotency_key is not None
            else None
        )
        act_scope = f"act:{self.provider_id}:{self.pinned_origin}:{action}:{params_hash}"
        return idem_scope, act_scope

    def _reserve_or_check_execution(
        self,
        action: str,
        params_hash: int,
        idempotency_key: str | None,
        *,
        is_mutation: bool,
    ) -> ProviderResponse | None:
        """Atomically check uncertain/in-flight/idempotent state and reserve IN_FLIGHT before dispatch."""
        track_action = self.block_uncertain_retries and is_mutation
        with self._lock:
            if self.durable_state_path is not None:
                idem_scope, act_scope = self._durable_scope_keys(
                    action, params_hash, idempotency_key
                )
                conn = sqlite3.connect(
                    str(self.durable_state_path), timeout=30.0, isolation_level=None
                )
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    if idem_scope is not None:
                        row = conn.execute(
                            "SELECT status, params_hash, response_json, error_reason "
                            "FROM openapi_adapter_effects WHERE scope_key = ?",
                            (idem_scope,),
                        ).fetchone()
                        if row is not None:
                            status, stored_hash, resp_json, err_reason = row
                            if status == "OUTCOME_UNKNOWN":
                                conn.execute("ROLLBACK")
                                raise ReconciliationConflictError(
                                    f"idempotency key '{idempotency_key}' is locked in OUTCOME_UNKNOWN after prior uncertain execution ({err_reason}); refusing duplicate retry until reconciled",
                                    retryable=False,
                                    provider=self.provider_id,
                                )
                            if status == "IN_FLIGHT":
                                conn.execute("ROLLBACK")
                                raise ReconciliationConflictError(
                                    f"idempotency key '{idempotency_key}' is locked in IN_FLIGHT/OUTCOME_UNKNOWN (concurrent execution or prior process crash before reconciliation); refusing duplicate dispatch",
                                    retryable=False,
                                    provider=self.provider_id,
                                )
                            if status == "COMPLETED":
                                conn.execute("ROLLBACK")
                                if int(stored_hash) != params_hash:
                                    raise InvalidParametersError(
                                        [
                                            {
                                                "field": "*",
                                                "reason": f"idempotency key '{idempotency_key}' was already used with different params",
                                            }
                                        ],
                                        provider=self.provider_id,
                                    )
                                data = json.loads(resp_json or "{}")
                                return ProviderResponse(
                                    ok=bool(data.get("ok", True)),
                                    action=str(data.get("action", action)),
                                    provider_action_id=data.get("provider_action_id"),
                                    provider_evidence=dict(data.get("provider_evidence", {})),
                                    cost=data.get("cost"),
                                    raw=None,
                                )
                    if track_action:
                        row = conn.execute(
                            "SELECT status, error_reason FROM openapi_adapter_effects WHERE scope_key = ?",
                            (act_scope,),
                        ).fetchone()
                        if row is not None:
                            status, err_reason = row
                            if status in ("OUTCOME_UNKNOWN", "IN_FLIGHT"):
                                conn.execute("ROLLBACK")
                                raise ReconciliationConflictError(
                                    f"action '{action}' with identical parameters is locked in {status} ({err_reason or 'concurrent or un-reconciled prior dispatch'}); refusing duplicate retry until reconciled",
                                    retryable=False,
                                    provider=self.provider_id,
                                )

                    if idem_scope is not None:
                        conn.execute(
                            "INSERT OR REPLACE INTO openapi_adapter_effects "
                            "(scope_key, status, params_hash, response_json, error_reason) "
                            "VALUES (?, 'IN_FLIGHT', ?, NULL, 'dispatch in flight')",
                            (idem_scope, str(params_hash)),
                        )
                    if track_action:
                        conn.execute(
                            "INSERT OR REPLACE INTO openapi_adapter_effects "
                            "(scope_key, status, params_hash, response_json, error_reason) "
                            "VALUES (?, 'IN_FLIGHT', ?, NULL, 'dispatch in flight')",
                            (act_scope, str(params_hash)),
                        )
                    conn.execute("COMMIT")
                finally:
                    conn.close()
                # Durable mode: SQLite is the single source of truth.
                return None

            if idempotency_key is not None and idempotency_key in self._uncertain_keys:
                prior_reason = self._uncertain_keys[idempotency_key]
                raise ReconciliationConflictError(
                    f"idempotency key '{idempotency_key}' is locked in OUTCOME_UNKNOWN after prior uncertain execution ({prior_reason}); refusing duplicate retry until reconciled",
                    retryable=False,
                    provider=self.provider_id,
                )
            if track_action and (action, params_hash) in self._uncertain_actions:
                prior_reason = self._uncertain_actions[(action, params_hash)]
                raise ReconciliationConflictError(
                    f"action '{action}' with identical parameters is locked in OUTCOME_UNKNOWN ({prior_reason}); refusing duplicate retry until reconciled",
                    retryable=False,
                    provider=self.provider_id,
                )
            if idempotency_key is not None and idempotency_key in self._inflight_keys:
                raise ReconciliationConflictError(
                    f"idempotency key '{idempotency_key}' is currently in-flight; refusing concurrent duplicate dispatch because single-execution cannot be guaranteed while prior dispatch is unresolved",
                    retryable=False,
                    provider=self.provider_id,
                )
            if track_action and (action, params_hash) in self._inflight_actions:
                raise ReconciliationConflictError(
                    f"action '{action}' with identical parameters is currently in-flight; refusing concurrent duplicate dispatch",
                    retryable=False,
                    provider=self.provider_id,
                )
            if idempotency_key is not None:
                cached = self._idem_cache.get(idempotency_key)
                if cached is not None:
                    cached_hash, cached_resp = cached
                    if cached_hash != params_hash:
                        raise InvalidParametersError(
                            [
                                {
                                    "field": "*",
                                    "reason": f"idempotency key '{idempotency_key}' was already used with different params",
                                }
                            ],
                            provider=self.provider_id,
                        )
                    return cached_resp

            if idempotency_key is not None:
                self._inflight_keys[idempotency_key] = params_hash
            if track_action:
                self._inflight_actions.add((action, params_hash))
            return None

    def _release_pre_dispatch_reservation(
        self,
        action: str,
        params_hash: int,
        idempotency_key: str | None,
        *,
        is_mutation: bool,
    ) -> None:
        track_action = self.block_uncertain_retries and is_mutation
        with self._lock:
            if idempotency_key is not None:
                self._inflight_keys.pop(idempotency_key, None)
            if track_action:
                self._inflight_actions.discard((action, params_hash))
            if self.durable_state_path is not None:
                idem_scope, act_scope = self._durable_scope_keys(
                    action, params_hash, idempotency_key
                )
                with sqlite3.connect(str(self.durable_state_path), timeout=30.0) as conn:
                    if idem_scope is not None:
                        conn.execute(
                            "DELETE FROM openapi_adapter_effects WHERE scope_key = ? AND status = 'IN_FLIGHT'",
                            (idem_scope,),
                        )
                    if track_action:
                        conn.execute(
                            "DELETE FROM openapi_adapter_effects WHERE scope_key = ? AND status = 'IN_FLIGHT'",
                            (act_scope,),
                        )
                    conn.commit()

    def _record_uncertain_outcome(
        self,
        action: str,
        params_hash: int,
        idempotency_key: str | None,
        reason: str,
        *,
        is_mutation: bool,
    ) -> None:
        track_action = self.block_uncertain_retries and is_mutation
        with self._lock:
            if idempotency_key is not None:
                self._inflight_keys.pop(idempotency_key, None)
                self._uncertain_keys[idempotency_key] = reason
            if track_action:
                self._inflight_actions.discard((action, params_hash))
                self._uncertain_actions[(action, params_hash)] = reason
            if self.durable_state_path is not None:
                idem_scope, act_scope = self._durable_scope_keys(
                    action, params_hash, idempotency_key
                )
                with sqlite3.connect(str(self.durable_state_path), timeout=30.0) as conn:
                    if idem_scope is not None:
                        conn.execute(
                            "INSERT OR REPLACE INTO openapi_adapter_effects "
                            "(scope_key, status, params_hash, response_json, error_reason) "
                            "VALUES (?, 'OUTCOME_UNKNOWN', ?, NULL, ?)",
                            (idem_scope, str(params_hash), reason),
                        )
                    if track_action:
                        conn.execute(
                            "INSERT OR REPLACE INTO openapi_adapter_effects "
                            "(scope_key, status, params_hash, response_json, error_reason) "
                            "VALUES (?, 'OUTCOME_UNKNOWN', ?, NULL, ?)",
                            (act_scope, str(params_hash), reason),
                        )
                    conn.commit()

    def _record_completed_outcome(
        self,
        action: str,
        params_hash: int,
        idempotency_key: str | None,
        response: ProviderResponse,
        *,
        is_mutation: bool,
    ) -> None:
        track_action = self.block_uncertain_retries and is_mutation
        with self._lock:
            if idempotency_key is not None:
                self._inflight_keys.pop(idempotency_key, None)
                self._idem_cache[idempotency_key] = (params_hash, response)
            if track_action:
                self._inflight_actions.discard((action, params_hash))
            if self.durable_state_path is not None:
                idem_scope, act_scope = self._durable_scope_keys(
                    action, params_hash, idempotency_key
                )
                with sqlite3.connect(str(self.durable_state_path), timeout=30.0) as conn:
                    if idem_scope is not None:
                        serialized = json.dumps(
                            {
                                "ok": response.ok,
                                "action": response.action,
                                "provider_action_id": response.provider_action_id,
                                "provider_evidence": response.provider_evidence,
                                "cost": response.cost,
                            },
                            sort_keys=True,
                        )
                        conn.execute(
                            "INSERT OR REPLACE INTO openapi_adapter_effects "
                            "(scope_key, status, params_hash, response_json, error_reason) "
                            "VALUES (?, 'COMPLETED', ?, ?, NULL)",
                            (idem_scope, str(params_hash), serialized),
                        )
                    if track_action:
                        conn.execute(
                            "DELETE FROM openapi_adapter_effects WHERE scope_key = ? AND status = 'IN_FLIGHT'",
                            (act_scope,),
                        )
                    conn.commit()

    @classmethod
    def from_openapi(
        cls,
        spec: dict[str, Any],
        *,
        provider_id: str,
        base_url: str | None = None,
        witness_map: dict[str, WitnessSpec] | None = None,
        test_mode: bool = False,
        allow_loopback_for_tests: bool = False,
        experimental_opt_in: bool = False,
        production_mode: bool = False,
        durable_state_path: str | Path | None = None,
        require_durable_state: bool = False,
    ) -> OpenAPIDynamicAdapter:
        """Compile an OpenAPI 3.x specification dictionary into an ``OpenAPIDynamicAdapter``."""
        resolved_base = base_url
        if not resolved_base:
            servers = spec.get("servers") or []
            if servers and isinstance(servers[0], dict) and servers[0].get("url"):
                resolved_base = str(servers[0]["url"])
            else:
                raise ValueError("base_url is required when OpenAPI spec has no servers[0].url")

        operations: list[OpenAPIOperationSpec] = []
        paths = spec.get("paths") or {}
        for path_tmpl, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            path_vars = tuple(_TEMPLATE_PARAM_RE.findall(path_tmpl))
            for method_lower, op_obj in path_item.items():
                if method_lower.lower() not in ("post", "put", "patch", "delete", "get", "head"):
                    continue
                if not isinstance(op_obj, dict):
                    continue
                action = str(
                    op_obj.get("operationId")
                    or f"{provider_id}.{method_lower.lower()}.{path_tmpl.strip('/')}"
                )
                required: list[str] = list(path_vars)
                optional: dict[str, Any] = {}
                param_types: dict[str, type | tuple[type, ...]] = {
                    p: str for p in path_vars
                }
                nullable_params: list[str] = []
                param_enums: dict[str, tuple[Any, ...]] = {}
                param_bounds: dict[str, tuple[int | float | None, int | float | None]] = {}

                for param in op_obj.get("parameters") or []:
                    if not isinstance(param, dict) or "name" not in param:
                        continue
                    pname = str(param["name"])
                    pschema = param.get("schema")
                    if not isinstance(pschema, dict):
                        raise ValueError(
                            f"OpenAPI parameter {pname!r} in {action!r} is missing a schema object"
                        )
                    ptype, is_nullable, enum_vals, bounds = _parse_field_schema(
                        pname, pschema
                    )
                    param_types[pname] = ptype
                    if is_nullable:
                        nullable_params.append(pname)
                    if enum_vals is not None:
                        param_enums[pname] = enum_vals
                    if bounds is not None:
                        param_bounds[pname] = bounds
                    if param.get("required") or param.get("in") == "path":
                        if pname not in required:
                            required.append(pname)
                    else:
                        optional[pname] = pschema.get("default")

                req_body = (
                    (op_obj.get("requestBody") or {})
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )
                if isinstance(req_body, dict) and req_body:
                    for kw in _UNSUPPORTED_SCHEMA_KEYWORDS:
                        if kw in req_body:
                            raise ValueError(
                                f"OpenAPI requestBody in {action!r} uses unsupported keyword {kw!r}"
                            )
                    body_req = set(req_body.get("required") or [])
                    props = req_body.get("properties") or {}
                    for prop_name, prop_schema in props.items():
                        if not isinstance(prop_schema, dict):
                            raise ValueError(
                                f"OpenAPI property {prop_name!r} in {action!r} must be a schema object"
                            )
                        ptype, is_nullable, enum_vals, bounds = _parse_field_schema(
                            prop_name, prop_schema
                        )
                        param_types[prop_name] = ptype
                        if is_nullable:
                            nullable_params.append(prop_name)
                        if enum_vals is not None:
                            param_enums[prop_name] = enum_vals
                        if bounds is not None:
                            param_bounds[prop_name] = bounds
                        if prop_name in body_req:
                            if prop_name not in required:
                                required.append(prop_name)
                        else:
                            optional[prop_name] = prop_schema.get("default")

                witness = (witness_map or {}).get(action)
                if witness is None and isinstance(op_obj.get("x-actenon-witness"), dict):
                    w_raw = op_obj["x-actenon-witness"]
                    witness = WitnessSpec(
                        path_template=str(w_raw["path_template"]),
                        expected_status=tuple(w_raw.get("expected_status", [200])),
                        expected_fields=dict(w_raw.get("expected_fields", {})),
                        id_param_from_response=str(
                            w_raw.get("id_param_from_response", "id")
                        ),
                        bind_request_params=tuple(
                            w_raw.get("bind_request_params", ())
                        ),
                        verify_shared_request_fields=bool(
                            w_raw.get("verify_shared_request_fields", True)
                        ),
                    )

                operations.append(
                    OpenAPIOperationSpec(
                        action=action,
                        method=method_lower.upper(),
                        path_template=path_tmpl,
                        required_params=tuple(required),
                        optional_params=optional,
                        param_types=param_types,
                        nullable_params=tuple(nullable_params),
                        param_enums=param_enums,
                        param_bounds=param_bounds,
                        path_params=path_vars,
                        cost_field=op_obj.get("x-actenon-cost-field"),
                        witness=witness,
                    )
                )

        return cls(
            provider_id=provider_id,
            base_url=resolved_base,
            operations=operations,
            test_mode=test_mode,
            allow_loopback_for_tests=allow_loopback_for_tests,
            experimental_opt_in=experimental_opt_in,
            production_mode=production_mode,
            durable_state_path=durable_state_path,
            require_durable_state=require_durable_state,
        )

    # ------------------------------------------------------------------
    # Discovery + strict parameter validation
    # ------------------------------------------------------------------

    def supported_actions(self) -> list[str]:
        return list(self._operations.keys())

    def validate_params(self, action: str, params: dict[str, Any]) -> ValidationResult:
        op = self._operations.get(action)
        if op is None:
            return ValidationResult(
                ok=False,
                errors=[{"field": "action", "reason": f"unknown action: {action}"}],
            )
        if not isinstance(params, dict):
            return ValidationResult(
                ok=False,
                errors=[{"field": "*", "reason": "params must be a dict"}],
            )

        known = set(op.required_params) | set(op.optional_params.keys())
        unknown = [k for k in params if k not in known]
        missing = [k for k in op.required_params if k not in params]
        errors: list[dict[str, str]] = []

        for k in unknown:
            errors.append({"field": k, "reason": "unsupported parameter"})
        for k in missing:
            errors.append({"field": k, "reason": "required parameter missing"})

        for k, v in params.items():
            if k not in known:
                continue
            if v is None:
                if k not in op.nullable_params:
                    errors.append(
                        {"field": k, "reason": "parameter is not nullable"}
                    )
                continue

            expected_type = op.param_types.get(k)
            if expected_type is not None:
                # In Python bool is a subclass of int; reject bool when int/float is expected.
                if isinstance(v, bool) and expected_type is not bool and (
                    expected_type is int
                    or expected_type is float
                    or (isinstance(expected_type, tuple) and bool not in expected_type)
                ):
                    errors.append(
                        {"field": k, "reason": "expected numeric value, got bool"}
                    )
                    continue
                if not isinstance(v, expected_type):
                    type_name = (
                        expected_type.__name__
                        if isinstance(expected_type, type)
                        else "/".join(t.__name__ for t in expected_type)
                    )
                    errors.append(
                        {"field": k, "reason": f"expected {type_name}, got {type(v).__name__}"}
                    )
                    continue

            if k in op.param_enums and v not in op.param_enums[k]:
                errors.append(
                    {"field": k, "reason": f"value {v!r} not in allowed enum {op.param_enums[k]!r}"}
                )
                continue

            if k in op.param_bounds and isinstance(v, (int, float)) and not isinstance(v, bool):
                min_v, max_v = op.param_bounds[k]
                if min_v is not None and v < min_v:
                    errors.append(
                        {"field": k, "reason": f"value {v} is below minimum {min_v}"}
                    )
                    continue
                if max_v is not None and v > max_v:
                    errors.append(
                        {"field": k, "reason": f"value {v} exceeds maximum {max_v}"}
                    )
                    continue

            if k in op.path_params and (
                not isinstance(v, str)
                or not _SAFE_PATH_PARAM_RE.fullmatch(v)
                or v in (".", "..")
            ):
                errors.append(
                    {"field": k, "reason": "unsafe or invalid path segment parameter"}
                )

        return ValidationResult(
            ok=not errors and not unknown,
            unknown_fields=unknown,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        *,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse:
        is_prod = (
            self.production_mode
            or os.environ.get("ACTENON_ENV", "").strip().lower() == "production"
        )
        if is_prod and not self.experimental_opt_in:
            raise UnsupportedActionError(
                "OpenAPIDynamicAdapter is experimental and disabled by default in production; "
                "pass experimental_opt_in=True to explicitly opt in.",
                provider=self.provider_id,
            )
        if (is_prod or self.require_durable_state) and self.durable_state_path is None:
            raise ReconciliationConflictError(
                "OpenAPIDynamicAdapter requires durable_state_path in production/durable mode "
                "because single-execution cannot be guaranteed across restarts with ephemeral state.",
                retryable=False,
                provider=self.provider_id,
            )

        op = self._operations.get(action)
        if op is None:
            raise UnsupportedActionError(
                f"{self.provider_id} adapter does not support action '{action}'",
                provider=self.provider_id,
            )

        vr = self.validate_params(action, params)
        if not vr.ok:
            raise InvalidParametersError(vr.errors, provider=self.provider_id)

        is_mutation = op.method.upper() in _MUTATING_METHODS
        params_hash = _hash_params(action, params)
        cached_resp = self._reserve_or_check_execution(
            action, params_hash, idempotency_key, is_mutation=is_mutation
        )
        if cached_resp is not None:
            return cached_resp

        secret_value = credential.value
        # Phase 1: primary dispatch. Only failures proven to occur before any
        # request bytes left this process release the reservation. Everything
        # else (including a redirect refusal, which happens AFTER the provider
        # received the request) is OUTCOME_UNKNOWN and blocks retries.
        try:
            if self.test_mode:
                raw = self._test_call(op, params)
            else:
                raw, _ = self._live_call_tracked(
                    op, params, credential, idempotency_key, timeout_seconds
                )
        except BaseException as exc:
            if getattr(exc, "_actenon_not_dispatched", False):
                self._release_pre_dispatch_reservation(
                    action, params_hash, idempotency_key, is_mutation=is_mutation
                )
            else:
                self._record_uncertain_outcome(
                    action,
                    params_hash,
                    idempotency_key,
                    f"{type(exc).__name__}: {exc}",
                    is_mutation=is_mutation,
                )
            raise

        # Phase 2: post-dispatch handling. The request was sent, so ANY failure
        # here (crash, partial response, witness refusal/mismatch) is uncertain.
        try:
            if self.post_dispatch_hook is not None:
                self.post_dispatch_hook()

            response = self.map_response(action, raw)
            response = self.reconcile(
                action, params, response, credential_value=secret_value
            )
            response = self.redact(
                action, params, response, credential_value=secret_value
            )
        except BaseException as exc:
            self._record_uncertain_outcome(
                action,
                params_hash,
                idempotency_key,
                f"{type(exc).__name__}: {exc}",
                is_mutation=is_mutation,
            )
            raise

        self._record_completed_outcome(
            action, params_hash, idempotency_key, response, is_mutation=is_mutation
        )
        return response

    def map_response(self, action: str, raw: Any) -> ProviderResponse:
        op = self._operations.get(action)
        if op is None:
            raise UnsupportedActionError(
                f"{self.provider_id} adapter cannot map response for '{action}'",
                provider=self.provider_id,
            )
        if not isinstance(raw, dict):
            raise ProviderPartialResponseError(
                provider=self.provider_id,
                action=action,
                missing_fields=list(op.required_response_fields) or ["*"],
            )
        missing = [f for f in op.required_response_fields if f not in raw]
        if missing:
            raise ProviderPartialResponseError(
                provider=self.provider_id,
                action=action,
                missing_fields=missing,
            )
        action_id = str(raw[op.response_id_field]) if op.response_id_field in raw else None
        cost: float | None = None
        if op.cost_field and op.cost_field in raw and isinstance(raw[op.cost_field], (int, float)):
            cost = float(raw[op.cost_field])

        evidence = {
            k: v
            for k, v in raw.items()
            if isinstance(v, (str, int, float, bool))
        }
        return ProviderResponse(
            ok=True,
            action=action,
            provider_action_id=action_id,
            provider_evidence=evidence,
            cost=cost,
            raw=raw,
        )

    def reconcile(
        self,
        action: str,
        params: dict[str, Any],
        response: ProviderResponse,
        *,
        credential_value: str | None = None,
    ) -> ProviderResponse:
        op = self._operations.get(action)
        if op is None or op.witness is None:
            response.provider_evidence["reconcile_status"] = "not_configured"
            return response

        if self.test_mode:
            response.provider_evidence["reconcile_status"] = "verified"
            response.provider_evidence["witness_verified"] = True
            return response

        witness = op.witness
        interp_vars: dict[str, str] = {
            k: str(v) for k, v in params.items() if isinstance(v, (str, int)) and not isinstance(v, bool)
        }
        if response.provider_action_id is not None:
            if (
                not _SAFE_PATH_PARAM_RE.fullmatch(response.provider_action_id)
                or response.provider_action_id in (".", "..")
            ):
                raise ReconciliationConflictError(
                    f"provider_action_id {response.provider_action_id!r} contains unsafe path characters; refusing witness interpolation",
                    retryable=False,
                    provider=self.provider_id,
                )
            interp_vars[witness.id_param_from_response] = response.provider_action_id
            interp_vars.setdefault("id", response.provider_action_id)

        try:
            witness_path = witness.path_template.format(**interp_vars)
        except KeyError as exc:
            raise ReconciliationConflictError(
                f"witness path template for '{action}' is missing variable {exc}; outcome is uncertain — refusing automatic retry",
                retryable=False,
                provider=self.provider_id,
            ) from exc

        try:
            status_code, witness_payload = self._http_request(
                method="GET",
                path=witness_path,
                body=None,
                credential_value=credential_value,
                idempotency_key=None,
                timeout_seconds=15.0,
            )
        except (OriginRedirectError, SSRFBlockedError):
            raise
        except AdapterError as exc:
            raise ReconciliationConflictError(
                f"witness GET {witness_path} failed ({exc}); "
                "real-world effect is unconfirmed — holding action for reconciliation without retry",
                retryable=False,
                provider=self.provider_id,
            ) from exc
        if status_code not in witness.expected_status:
            raise ReconciliationConflictError(
                f"witness GET {witness_path} returned HTTP {status_code} (expected {witness.expected_status}); "
                "real-world effect is unconfirmed — holding action for reconciliation without retry",
                retryable=False,
                provider=self.provider_id,
            )

        # Verify response identifier matches witness payload identifier when present.
        if (
            response.provider_action_id is not None
            and op.response_id_field in witness_payload
            and str(witness_payload[op.response_id_field]) != response.provider_action_id
        ):
            raise ReconciliationConflictError(
                f"witness identity mismatch on '{op.response_id_field}': expected {response.provider_action_id!r}, got {witness_payload[op.response_id_field]!r}; "
                "holding action for reconciliation without retry",
                retryable=False,
                provider=self.provider_id,
            )

        for expected_key, expected_val in witness.expected_fields.items():
            actual_val = witness_payload.get(expected_key)
            if actual_val != expected_val:
                raise ReconciliationConflictError(
                    f"witness state mismatch on field '{expected_key}': expected {expected_val!r}, got {actual_val!r}; "
                    "holding action for reconciliation without retry",
                    retryable=False,
                    provider=self.provider_id,
                )

        # Verify request parameters bound to the witness resource (explicitly bound
        # or shared between request params and witness payload).
        bound_keys = set(witness.bind_request_params)
        if witness.verify_shared_request_fields:
            bound_keys |= (set(params.keys()) & set(witness_payload.keys())) - set(op.path_params)
        for req_key in sorted(bound_keys):
            if req_key not in params:
                continue
            if req_key not in witness_payload:
                raise ReconciliationConflictError(
                    f"witness payload is missing bound request parameter '{req_key}'; holding action for reconciliation without retry",
                    retryable=False,
                    provider=self.provider_id,
                )
            if witness_payload[req_key] != params[req_key]:
                raise ReconciliationConflictError(
                    f"witness request-binding mismatch on '{req_key}': requested {params[req_key]!r}, witness reported {witness_payload[req_key]!r}; "
                    "holding action for reconciliation without retry",
                    retryable=False,
                    provider=self.provider_id,
                )

        response.provider_evidence["reconcile_status"] = "verified"
        response.provider_evidence["witness_verified"] = True
        response.provider_evidence["witness_path"] = witness_path
        return response

    def redact(
        self,
        action: str,
        params: dict[str, Any],
        response: ProviderResponse,
        *,
        credential_value: str | None = None,
    ) -> ProviderResponse:
        sensitive_keys = {
            "token",
            "authorization",
            "password",
            "secret",
            "api_key",
            "apikey",
            "client_secret",
            "private_key",
        }
        cleaned: dict[str, Any] = {}
        for k, v in response.provider_evidence.items():
            if k.lower() in sensitive_keys:
                cleaned[k] = "<redacted>"
                continue
            if isinstance(v, str):
                if credential_value and credential_value in v:
                    cleaned[k] = v.replace(credential_value, "<redacted>")
                    continue
                if v.startswith(("sk_live_", "sk_test_", "rk_live_", "ghp_", "gho_", "xoxb-")):
                    cleaned[k] = "<redacted>"
                    continue
            cleaned[k] = v

        return ProviderResponse(
            ok=response.ok,
            action=response.action,
            provider_action_id=response.provider_action_id,
            provider_evidence=cleaned,
            cost=response.cost,
            raw=None,
        )

    def health(self) -> dict[str, Any]:
        if self.test_mode:
            return {
                "ok": True,
                "provider": self.provider_id,
                "experimental": True,
                "experimental_opt_in": self.experimental_opt_in,
                "durable_state": self.durable_state_path is not None,
                "detail": "test mode (no network)",
                "pinned_origin": self.pinned_origin,
            }
        try:
            _validate_target_ssrf(
                self.base_url + "/",
                pinned_origin=self._pinned_origin,
                allow_loopback_for_tests=self.allow_loopback_for_tests,
                provider=self.provider_id,
            )
            return {
                "ok": True,
                "provider": self.provider_id,
                "experimental": True,
                "experimental_opt_in": self.experimental_opt_in,
                "durable_state": self.durable_state_path is not None,
                "detail": "origin and SSRF policy verified",
                "pinned_origin": self.pinned_origin,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.provider_id,
                "experimental": True,
                "experimental_opt_in": self.experimental_opt_in,
                "durable_state": self.durable_state_path is not None,
                "detail": f"unhealthy: {type(exc).__name__}",
                "pinned_origin": self.pinned_origin,
            }

    # ------------------------------------------------------------------
    # Internal HTTP & test helpers
    # ------------------------------------------------------------------

    def _live_call_tracked(
        self,
        op: OpenAPIOperationSpec,
        params: dict[str, Any],
        credential: Credential,
        idempotency_key: str | None,
        timeout_seconds: float | None,
    ) -> tuple[dict[str, Any], bool]:
        path_vars = {k: str(params[k]) for k in op.path_params if k in params}
        path = op.path_template.format(**path_vars)
        non_path_params = {k: v for k, v in params.items() if k not in op.path_params}
        method_upper = op.method.upper()
        if method_upper in ("GET", "HEAD") and non_path_params:
            query_str = urllib.parse.urlencode(non_path_params, doseq=True)
            sep = "&" if "?" in path else "?"
            path = f"{path}{sep}{query_str}"
            body = None
        else:
            body = (
                non_path_params
                if method_upper in _MUTATING_METHODS and non_path_params
                else None
            )
        status, payload, dispatch_started = self._http_request_tracked(
            method=method_upper,
            path=path,
            body=body,
            credential_value=credential.value,
            idempotency_key=idempotency_key,
            timeout_seconds=timeout_seconds,
        )
        if status >= 400:
            raise AdapterError(
                f"{self.provider_id} api returned HTTP {status} for {method_upper} {path}",
                retryable=500 <= status < 600,
                provider=self.provider_id,
            )
        return payload, dispatch_started

    def _live_call(
        self,
        op: OpenAPIOperationSpec,
        params: dict[str, Any],
        credential: Credential,
        idempotency_key: str | None,
        timeout_seconds: float | None,
    ) -> dict[str, Any]:
        payload, _ = self._live_call_tracked(
            op, params, credential, idempotency_key, timeout_seconds
        )
        return payload

    def _http_request(
        self,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        credential_value: str | None,
        idempotency_key: str | None,
        timeout_seconds: float | None,
    ) -> tuple[int, dict[str, Any]]:
        status, payload, _ = self._http_request_tracked(
            method=method,
            path=path,
            body=body,
            credential_value=credential_value,
            idempotency_key=idempotency_key,
            timeout_seconds=timeout_seconds,
        )
        return status, payload

    def _http_request_tracked(
        self,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        credential_value: str | None,
        idempotency_key: str | None,
        timeout_seconds: float | None,
    ) -> tuple[int, dict[str, Any], bool]:
        rel_path = path if path.startswith("/") else "/" + path
        url = self.base_url + rel_path
        scheme, host, _port = self._pinned_origin
        try:
            if (
                credential_value
                and scheme != "https"
                and not (self.allow_loopback_for_tests and _is_loopback_host(host))
            ):
                raise SSRFBlockedError(
                    f"cleartext HTTP is forbidden for authenticated requests to {self.pinned_origin}; use https://",
                    provider=self.provider_id,
                )

            resolved_ip = _validate_target_ssrf(
                url,
                pinned_origin=self._pinned_origin,
                allow_loopback_for_tests=self.allow_loopback_for_tests,
                provider=self.provider_id,
            )
        except AdapterError as exc:
            # Refused before any connection was opened: provably not dispatched.
            exc._actenon_not_dispatched = True  # type: ignore[attr-defined]
            raise

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "actenon-permit-openapi-adapter",
        }
        if credential_value:
            headers[self.auth_header] = (
                f"{self.auth_scheme} {credential_value}".strip()
                if self.auth_scheme
                else credential_value
            )
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        data: bytes | None = None
        if body is not None:
            data = json.dumps(body, sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        opener = urllib.request.build_opener(
            _PinnedIPHTTPHandler(resolved_ip=resolved_ip),
            _PinnedIPHTTPSHandler(resolved_ip=resolved_ip),
            _OriginPinnedRedirectHandler(
                pinned_origin=self._pinned_origin,
                allow_same_origin_redirects=self.allow_same_origin_redirects,
                allow_loopback_for_tests=self.allow_loopback_for_tests,
                provider=self.provider_id,
            ),
        )
        try:
            with opener.open(req, timeout=timeout_seconds or 30.0) as resp:
                raw_bytes = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw_bytes) > MAX_RESPONSE_BYTES:
                    raise AdapterError(
                        f"{self.provider_id} response exceeded {MAX_RESPONSE_BYTES} byte limit",
                        retryable=False,
                        provider=self.provider_id,
                    )
                decoded = raw_bytes.decode("utf-8")
                parsed = json.loads(decoded) if decoded else {}
                return (
                    resp.status,
                    parsed if isinstance(parsed, dict) else {"result": parsed},
                    True,
                )
        except OriginRedirectError:
            raise
        except SSRFBlockedError:
            raise
        except AdapterError:
            raise
        except urllib.error.HTTPError as exc:
            raise AdapterError(
                f"{self.provider_id} api returned HTTP {exc.code} for {method.upper()} {rel_path}",
                retryable=500 <= exc.code < 600,
                provider=self.provider_id,
            ) from exc
        except TimeoutError as exc:
            raise ProviderTimeoutError(
                provider=self.provider_id,
                action=method.upper(),
                timeout_seconds=timeout_seconds or 30.0,
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ProviderTimeoutError(
                    provider=self.provider_id,
                    action=method.upper(),
                    timeout_seconds=timeout_seconds or 30.0,
                ) from exc
            err = AdapterError(
                f"{self.provider_id} api unreachable: {type(exc.reason).__name__}",
                retryable=True,
                provider=self.provider_id,
            )
            if isinstance(exc.reason, ConnectionRefusedError):
                # TCP connect refused: no request bytes were sent.
                err._actenon_not_dispatched = True  # type: ignore[attr-defined]
            raise err from exc

    def _test_call(self, op: OpenAPIOperationSpec, params: dict[str, Any]) -> dict[str, Any]:
        seed = _hash_params(op.action, params)
        out: dict[str, Any] = {
            op.response_id_field: f"{self.provider_id}_{seed:012x}",
            "status": "succeeded",
        }
        for k, v in params.items():
            if isinstance(v, (str, int, float, bool)):
                out.setdefault(k, v)
        if op.witness:
            out.update(op.witness.expected_fields)
        return out


def _hash_params(action: str, params: dict[str, Any]) -> int:
    canonical = json.dumps({"action": action, "params": params}, sort_keys=True, default=str)
    return int.from_bytes(hashlib.sha256(canonical.encode("utf-8")).digest()[:8], "big")


UniversalOpenAPIAdapter = OpenAPIDynamicAdapter


class MCPDynamicAdapter(OpenAPIDynamicAdapter):
    """Deprecated alias retained only for backwards import compatibility.

    ``OpenAPIDynamicAdapter`` is an experimental OpenAPI/HTTP adapter, not an
    MCP JSON-RPC transport client.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        warnings.warn(
            "MCPDynamicAdapter is deprecated and does not implement MCP JSON-RPC transport; "
            "use OpenAPIDynamicAdapter (experimental HTTP/OpenAPI adapter) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


__all__ = [
    "MAX_RESPONSE_BYTES",
    "MCPDynamicAdapter",
    "OpenAPIDynamicAdapter",
    "OpenAPIOperationSpec",
    "OriginRedirectError",
    "SSRFBlockedError",
    "UniversalOpenAPIAdapter",
    "WitnessSpec",
]
