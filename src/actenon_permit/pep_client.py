"""Actenon-Permit v1 remote PEP client.

Drop-in replacement for the v0 in-process ``@guard`` decorator that talks to
an out-of-process gateway over HTTP. The agent-side call signature is
identical — only the import changes::

    # v0 (in-process)
    from actenon_permit import guard, GuardRegistry
    @guard("payment.refund", cost_from="amount", credential_name="STRIPE_KEY", registry=reg)
    def refund(secret, amount, reason=""): ...

    # v1 (out-of-process)
    from actenon_permit.pep_client import remote_guard, RemoteGuardRegistry
    @remote_guard("payment.refund", cost_from="amount", registry=reg)
    def refund(amount, reason=""): ...   # no `secret` — it lives in the gateway

The v1 wrapped function takes NO ``secret`` parameter (the gateway holds the
secret). The agent only ever sees the tool signature and the outcome.
"""

from __future__ import annotations

import functools
import inspect
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from .enforce import ApprovalGate
from .token import TokenError, grant_to_token


class RemoteGuardError(Exception):
    """Raised when the remote gateway returns an unexpected response."""


class RemoteGuardDenied(Exception):
    """Raised when the remote gateway DENIES a call. ``reason`` has the detail."""

    def __init__(self, reason: str, rule_matched: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.rule_matched = rule_matched


class RemoteGuardRegistry:
    """Agent-side handle that knows where the gateway is and which grant to use.

    Mirrors the surface of v0's ``GuardRegistry`` so agent code can switch by
    changing one import. The grant is set as a token string (issued by the
    control plane or attenuated from a parent grant).
    """

    def __init__(self, gateway_url: str = "http://127.0.0.1:7780"):
        self.gateway_url = gateway_url.rstrip("/")
        self._grant_token: str | None = None
        self._gate: ApprovalGate | None = None  # unused on client; approvals happen server-side

    def set_grant_token(self, token: str) -> None:
        """Set the grant token to present on every call."""
        self._grant_token = token

    def set_grant(self, grant) -> None:
        """Set the grant from a Grant object (will be tokenized)."""
        self._grant_token = grant_to_token(grant)

    @property
    def grant_token(self) -> str | None:
        return self._grant_token

    @property
    def grant_id(self) -> str | None:
        if not self._grant_token:
            return None
        try:
            from .token import token_to_grant

            g = token_to_grant(self._grant_token, verify=True)
            return g.id
        except TokenError:
            return None

    def set_approval_gate(self, gate: ApprovalGate) -> None:  # noqa: ARG002
        # Server-side approvals only in v1; this is a no-op for API parity.
        pass


def remote_guard(
    action_type: str,
    *,
    target: str = "",
    cost_from: str | None = None,
    registry: RemoteGuardRegistry,
    # NOTE: no credential_name — the gateway holds the credential. This is
    # the whole point of v1: the agent process never sees the secret.
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that wraps a tool function with remote PEP enforcement.

    The wrapped function is the agent-side STUB — its body is never called.
    It exists only to declare the signature. The real implementation lives
    in the gateway's ToolRegistry. This is the opposite of v0, where the
    decorator wrapped the real function and injected the secret.

    Usage::

        @remote_guard("payment.refund", cost_from="amount", registry=reg)
        def refund(amount: float, reason: str = "") -> dict:
            "Issue a refund"  # docstring only; body is ignored
            ...

        refund(amount=20)  # -> calls gateway -> broker -> real provider
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not registry.grant_token:
                raise RemoteGuardDenied("no grant token is set on the registry")
            sig = inspect.signature(fn)
            try:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
            except TypeError:
                raise RemoteGuardDenied("tool arguments do not match its signature") from None
            # Strip a leading `secret` param if present (back-compat with v0
            # tool signatures — the agent shouldn't pass it, but if someone
            # copied a v0 tool verbatim the stub will still work).
            secret_param = next(iter(sig.parameters), None)
            if secret_param == "secret":
                arguments.pop("secret", None)

            url = f"{registry.gateway_url}/proxy/{tool_name}"
            req = urllib.request.Request(
                url,
                data=json.dumps(arguments).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Actenon-Grant": registry.grant_token,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = resp.read().decode("utf-8")
                    status = resp.status
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")
                status = e.code
            except urllib.error.URLError as e:
                raise RemoteGuardError(f"cannot reach gateway at {url}: {e}") from e

            try:
                payload = json.loads(body)
            except json.JSONDecodeError as e:
                raise RemoteGuardError(f"gateway returned non-JSON response (status {status}): {body!r}") from e

            outcome = payload.get("outcome")
            if outcome == "ALLOW":
                return payload.get("result")
            raise RemoteGuardDenied(
                payload.get("reason", "denied"),
                rule_matched=payload.get("rule_matched"),
            )

        wrapper.__actenon_remote_guard__ = {  # type: ignore[attr-defined]
            "action_type": action_type,
            "target": target,
            "cost_from": cost_from,
            "tool_name": tool_name,
            "original": fn,
        }
        return wrapper

    return decorator


def remote_wrap(
    fn: Callable[..., Any],
    *,
    action_type: str,
    target: str = "",
    cost_from: str | None = None,
    registry: RemoteGuardRegistry,
) -> Callable[..., Any]:
    """Functional equivalent of ``@remote_guard(...)``."""
    return remote_guard(
        action_type,
        target=target,
        cost_from=cost_from,
        registry=registry,
    )(fn)


__all__ = [
    "RemoteGuardRegistry",
    "RemoteGuardError",
    "RemoteGuardDenied",
    "remote_guard",
    "remote_wrap",
]
