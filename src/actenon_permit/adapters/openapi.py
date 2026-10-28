"""Universal OpenAPI / MCP Dynamic Capability Adapter with Witness Reconciliation.

Bridges the dynamic capability execution and witness-verification model from
``rightclick-x`` into ``actenon-permit``'s ``ProviderAdapter`` contract:

1. **Dynamic Strict Schema Validation:** Validates action parameters against
   OpenAPI / JSON Schema operation definitions. Any unknown parameter, missing
   required field, type mismatch (including ``bool`` masquerading as ``int``),
   or path-traversal segment is rejected with ``InvalidParametersError``.
2. **Origin-Pinned Credentials & SSRF Defense:** Pins credentials to a single
   verified origin (``scheme://host[:port]``). Blocks private-network,
   link-local/cloud-metadata (``169.254.169.254``), loopback (unless explicitly
   enabled for local loopback integration servers), and cross-origin HTTP
   redirects so credentials never leak across redirects.
3. **Post-Action Read-Only Witness Reconciliation:** Executes an independent
   read-only ``GET`` witness probe after consequential mutations to prove the
   real-world side effect occurred. If the witness check disagrees or cannot
   confirm the state, raises ``ReconciliationConflictError(retryable=False)``
   (*"Unknown is not failed — never blindly retry an uncertain consequential
   action"*).
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
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


class SSRFBlockedError(AdapterError):
    """Raised when a target URL or resolved IP violates SSRF policy."""

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


@dataclass(frozen=True)
class OpenAPIOperationSpec:
    """Strict schema and execution contract for one dynamic capability."""

    action: str
    method: str
    path_template: str
    required_params: tuple[str, ...] = ()
    optional_params: dict[str, Any] = field(default_factory=dict)
    param_types: dict[str, type | tuple[type, ...]] = field(default_factory=dict)
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


def _check_ip_allowed(
    ip_str: str, *, allow_loopback_for_tests: bool, provider: str
) -> None:
    addr = ipaddress.ip_address(ip_str)
    if addr.is_Loopback if hasattr(addr, "is_Loopback") else addr.is_loopback:
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
) -> None:
    try:
        scheme, host, port = _extract_origin(url)
    except ValueError as exc:
        raise SSRFBlockedError(str(exc), provider=provider) from exc

    if (scheme, host, port) != pinned_origin:
        raise OriginRedirectError(
            f"target origin {_format_origin(scheme, host, port)} does not match pinned origin {_format_origin(*pinned_origin)}",
            provider=provider,
        )

    # Check literal IP first
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _check_ip_allowed(
            host, allow_loopback_for_tests=allow_loopback_for_tests, provider=provider
        )
        return

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

    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        _check_ip_allowed(
            ip_str, allow_loopback_for_tests=allow_loopback_for_tests, provider=provider
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


class OpenAPIDynamicAdapter(ProviderAdapter):
    """Universal OpenAPI / MCP Dynamic Capability Adapter with Witness Reconciliation."""

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
    ):
        self.provider_id = provider_id
        self.base_url = base_url.rstrip("/")
        self._pinned_origin = _extract_origin(self.base_url)
        self.pinned_origin = _format_origin(*self._pinned_origin)
        self.test_mode = test_mode
        self.allow_loopback_for_tests = allow_loopback_for_tests
        self.allow_same_origin_redirects = allow_same_origin_redirects
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self._operations: dict[str, OpenAPIOperationSpec] = {
            op.action: op for op in operations
        }
        self._idem_cache: dict[str, tuple[str, ProviderResponse]] = {}
        self._last_credential_value: str | None = None

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
                if method_lower.lower() not in ("post", "put", "patch", "delete", "get"):
                    continue
                if not isinstance(op_obj, dict):
                    continue
                action = str(op_obj.get("operationId") or f"{provider_id}.{method_lower.lower()}.{path_tmpl.strip('/')}")
                required: list[str] = list(path_vars)
                optional: dict[str, Any] = {}
                param_types: dict[str, type | tuple[type, ...]] = {p: str for p in path_vars}

                for param in op_obj.get("parameters") or []:
                    if not isinstance(param, dict) or "name" not in param:
                        continue
                    pname = str(param["name"])
                    pschema = param.get("schema") or {}
                    ptype = _JSON_SCHEMA_TYPE_MAP.get(str(pschema.get("type", "string")), str)
                    param_types[pname] = ptype
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
                if isinstance(req_body, dict):
                    body_req = set(req_body.get("required") or [])
                    props = req_body.get("properties") or {}
                    for prop_name, prop_schema in props.items():
                        if not isinstance(prop_schema, dict):
                            continue
                        ptype = _JSON_SCHEMA_TYPE_MAP.get(str(prop_schema.get("type", "string")), str)
                        param_types[prop_name] = ptype
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
                        id_param_from_response=str(w_raw.get("id_param_from_response", "id")),
                    )

                operations.append(
                    OpenAPIOperationSpec(
                        action=action,
                        method=method_lower.upper(),
                        path_template=path_tmpl,
                        required_params=tuple(required),
                        optional_params=optional,
                        param_types=param_types,
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
            expected_type = op.param_types.get(k)
            if expected_type is not None and v is not None:
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
        op = self._operations.get(action)
        if op is None:
            raise UnsupportedActionError(
                f"{self.provider_id} adapter does not support action '{action}'",
                provider=self.provider_id,
            )

        if idempotency_key is not None:
            params_hash = _hash_params(action, params)
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

        vr = self.validate_params(action, params)
        if not vr.ok:
            raise InvalidParametersError(vr.errors, provider=self.provider_id)

        self._last_credential_value = credential.value
        try:
            if self.test_mode:
                raw = self._test_call(op, params)
            else:
                raw = self._live_call(op, params, credential, idempotency_key, timeout_seconds)

            response = self.map_response(action, raw)
            response = self.reconcile(action, params, response)
            response = self.redact(action, params, response)
        finally:
            self._last_credential_value = None

        if idempotency_key is not None:
            self._idem_cache[idempotency_key] = (_hash_params(action, params), response)

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
        self, action: str, params: dict[str, Any], response: ProviderResponse
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
            k: str(v) for k, v in params.items() if isinstance(v, (str, int))
        }
        if response.provider_action_id is not None:
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
                credential_value=self._last_credential_value,
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
        for expected_key, expected_val in witness.expected_fields.items():
            actual_val = witness_payload.get(expected_key)
            if actual_val != expected_val:
                raise ReconciliationConflictError(
                    f"witness state mismatch on field '{expected_key}': expected {expected_val!r}, got {actual_val!r}; "
                    "holding action for reconciliation without retry",
                    retryable=False,
                    provider=self.provider_id,
                )

        response.provider_evidence["reconcile_status"] = "verified"
        response.provider_evidence["witness_verified"] = True
        response.provider_evidence["witness_path"] = witness_path
        return response

    def redact(
        self, action: str, params: dict[str, Any], response: ProviderResponse
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
        secret_val = self._last_credential_value
        cleaned: dict[str, Any] = {}
        for k, v in response.provider_evidence.items():
            if k.lower() in sensitive_keys:
                cleaned[k] = "<redacted>"
                continue
            if isinstance(v, str):
                if secret_val and secret_val in v:
                    cleaned[k] = v.replace(secret_val, "<redacted>")
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
                "detail": "origin and SSRF policy verified",
                "pinned_origin": self.pinned_origin,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.provider_id,
                "detail": f"unhealthy: {type(exc).__name__}",
                "pinned_origin": self.pinned_origin,
            }

    # ------------------------------------------------------------------
    # Internal HTTP & test helpers
    # ------------------------------------------------------------------

    def _live_call(
        self,
        op: OpenAPIOperationSpec,
        params: dict[str, Any],
        credential: Credential,
        idempotency_key: str | None,
        timeout_seconds: float | None,
    ) -> dict[str, Any]:
        path_vars = {k: str(params[k]) for k in op.path_params if k in params}
        path = op.path_template.format(**path_vars)
        body_params = {k: v for k, v in params.items() if k not in op.path_params}
        status, payload = self._http_request(
            method=op.method,
            path=path,
            body=body_params if op.method in ("POST", "PUT", "PATCH", "DELETE") and body_params else None,
            credential_value=credential.value,
            idempotency_key=idempotency_key,
            timeout_seconds=timeout_seconds,
        )
        if status >= 400:
            raise AdapterError(
                f"{self.provider_id} api returned HTTP {status} for {op.method} {path}",
                retryable=500 <= status < 600,
                provider=self.provider_id,
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
        rel_path = path if path.startswith("/") else "/" + path
        url = self.base_url + rel_path
        _validate_target_ssrf(
            url,
            pinned_origin=self._pinned_origin,
            allow_loopback_for_tests=self.allow_loopback_for_tests,
            provider=self.provider_id,
        )

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
            _OriginPinnedRedirectHandler(
                pinned_origin=self._pinned_origin,
                allow_same_origin_redirects=self.allow_same_origin_redirects,
                allow_loopback_for_tests=self.allow_loopback_for_tests,
                provider=self.provider_id,
            )
        )
        try:
            with opener.open(req, timeout=timeout_seconds or 30.0) as resp:
                raw_bytes = resp.read().decode("utf-8")
                parsed = json.loads(raw_bytes) if raw_bytes else {}
                return resp.status, parsed if isinstance(parsed, dict) else {"result": parsed}
        except OriginRedirectError:
            raise
        except SSRFBlockedError:
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
            raise AdapterError(
                f"{self.provider_id} api unreachable: {type(exc.reason).__name__}",
                retryable=True,
                provider=self.provider_id,
            ) from exc

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
    import hashlib

    canonical = json.dumps({"action": action, "params": params}, sort_keys=True, default=str)
    return int.from_bytes(hashlib.sha256(canonical.encode("utf-8")).digest()[:8], "big")


UniversalOpenAPIAdapter = OpenAPIDynamicAdapter
MCPDynamicAdapter = OpenAPIDynamicAdapter

__all__ = [
    "MCPDynamicAdapter",
    "OpenAPIDynamicAdapter",
    "OpenAPIOperationSpec",
    "OriginRedirectError",
    "SSRFBlockedError",
    "UniversalOpenAPIAdapter",
    "WitnessSpec",
]
