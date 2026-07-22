"""Provider adapter contract for Actenon-Permit.

A ``ProviderAdapter`` is the stable interface between the broker and a
specific external service (GitHub, Stripe, Slack, AWS, etc.). The broker
does NOT call provider SDKs directly — it calls the adapter. This is what
allows the broker to enforce the same security boundary (parameter
validation, exact-action execution, idempotency, redaction, reconciliation)
across every provider, instead of trusting each provider's SDK to do the
right thing.

Contract surface (per the Prompt 8 spec):

  * provider identifier        - ``provider_id``
  * supported actions          - ``supported_actions()``
  * parameter validation       - ``validate_params()``
  * exact-action execution     - ``execute()``
  * idempotency support        - ``idempotency_key()``
  * provider response mapping  - ``map_response()``
  * reconciliation             - ``reconcile()``
  * redaction                  - ``redact()``
  * test mode                  - ``test_mode`` flag + no-network behaviour
  * health checks              - ``health()``

Adapters MUST NOT silently ignore unsupported parameters. ``validate_params``
returns either ``ValidationResult(ok=True)`` or a result listing every
unknown/invalid field - never a silent drop.
"""

from __future__ import annotations

import abc
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..credentials import Credential

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AdapterError(RuntimeError):
    """Base class for adapter failures.

    The broker treats any subclass of ``AdapterError`` as a structured
    failure (mapped to a DENY with the class name as ``rule_matched``).
    Other exceptions are treated as unexpected adapter crashes.

    The error message MUST NOT contain a credential value. The base
    ``__str__`` only returns ``self.safe_message``; concrete subclasses
    MUST sanitise any provider exception text before constructing the
    AdapterError.
    """

    def __init__(self, safe_message: str, *, retryable: bool = False, provider: str = ""):
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.retryable = retryable
        self.provider = provider

    def __str__(self) -> str:
        return self.safe_message


class UnsupportedActionError(AdapterError):
    """Raised when the adapter does not implement the requested action."""


class InvalidParametersError(AdapterError):
    """Raised when ``validate_params`` rejects the request.

    The ``errors`` field carries a list of ``{field, reason}`` dicts so
    the caller can see exactly which fields were wrong. This is what
    enforces "adapters must not silently ignore unsupported parameters".
    """

    def __init__(self, errors: list[dict[str, str]], *, provider: str = ""):
        msg = "parameter validation failed: " + ", ".join(
            f"{e['field']} ({e['reason']})" for e in errors
        )
        super().__init__(msg, retryable=False, provider=provider)
        self.errors = errors


class ProviderTimeoutError(AdapterError):
    """Raised when the provider call exceeds the broker's timeout budget."""

    def __init__(self, *, provider: str, action: str, timeout_seconds: float):
        super().__init__(
            f"provider '{provider}' timed out on action '{action}' after {timeout_seconds:.1f}s",
            retryable=True,
            provider=provider,
        )
        self.action = action
        self.timeout_seconds = timeout_seconds


class ProviderPartialResponseError(AdapterError):
    """Raised when the provider returns a response that is missing required
    fields. The provider's response is captured (sanitised) for
    reconciliation, but the action is treated as failed.
    """

    def __init__(self, *, provider: str, action: str, missing_fields: list[str]):
        super().__init__(
            f"provider '{provider}' returned a partial response for '{action}': missing {missing_fields}",
            retryable=True,
            provider=provider,
        )
        self.action = action
        self.missing_fields = missing_fields


class ReconciliationConflictError(AdapterError):
    """Raised when post-call reconciliation cannot determine the final
    state of the action (e.g. the provider returned a 500 but the side
    effect actually happened). The broker MUST treat this as
    "unknown outcome" and refuse to retry until a human reconciles.
    """


# ---------------------------------------------------------------------------
# Validation + response types
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    """Result of ``ProviderAdapter.validate_params``.

    ``unknown_fields`` is the list of parameter keys the adapter does
    NOT recognise. Non-empty ``unknown_fields`` MUST be treated as a
    validation failure - adapters MUST NOT silently drop unknown fields.
    """

    ok: bool
    unknown_fields: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ProviderResponse:
    """Normalised provider response.

    Adapters MUST map the provider's raw response into this shape before
    returning from ``execute()``. The broker never inspects raw provider
    payloads - it only looks at these normalised fields.

    ``provider_evidence`` is whatever the provider returned that proves
    the action ran (an issue URL, a commit SHA, a charge ID). It MUST be
    safe to write to the receipt - ``redact()`` has already been applied
    before ``ProviderResponse`` is constructed.
    """

    ok: bool
    action: str
    provider_action_id: str | None  # e.g. GitHub node_id, Stripe charge id
    provider_evidence: dict[str, Any] = field(default_factory=dict)
    cost: float | None = None  # USD if applicable, else None
    raw: Any = None  # adapter-private; never logged or persisted


# ---------------------------------------------------------------------------
# Adapter contract
# ---------------------------------------------------------------------------


class ProviderAdapter(abc.ABC):
    """Stable provider adapter contract.

    Every concrete adapter (GitHub, Stripe, Slack, AWS, ...) implements
    this interface. The broker calls only these methods - never a
    provider SDK directly.
    """

    #: Stable provider identifier, e.g. ``"github"``, ``"stripe"``.
    provider_id: str = "abstract"

    #: When True, the adapter MUST NOT touch the network. It returns
    #: deterministic mock responses. Used for tests and the safe demo.
    test_mode: bool = False

    # ------------------------------------------------------------------
    # Discovery + validation
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def supported_actions(self) -> list[str]:
        """Return the action keys this adapter implements.

        Each key is a stable identifier (e.g. ``"issue.create"``,
        ``"issue.comment"``, ``"branch.create"``, ``"pr.open"``).
        """

    @abc.abstractmethod
    def validate_params(self, action: str, params: dict[str, Any]) -> ValidationResult:
        """Validate the parameters for ``action``.

        MUST return ``ok=False`` with a non-empty ``unknown_fields`` list
        if any parameter key is not part of the action's schema. MUST
        NOT silently drop unknown fields.
        """

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def execute(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        *,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse:
        """Execute the EXACT action with the EXACT params.

        The adapter MUST:
          * use ``credential.value`` only to authenticate the underlying
            call, never log it, never return it;
          * respect ``timeout_seconds`` if set (raise
            ``ProviderTimeoutError`` on overrun);
          * honour ``idempotency_key`` - a duplicate key with the same
            params returns the original response, a duplicate key with
            different params raises ``InvalidParametersError``;
          * map the provider's response into a ``ProviderResponse`` via
            ``map_response()`` before returning.
        """

    # ------------------------------------------------------------------
    # Post-call hooks
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def map_response(self, action: str, raw: Any) -> ProviderResponse:
        """Map a raw provider response into a normalised
        ``ProviderResponse``. Called by ``execute()`` before return.
        """

    @abc.abstractmethod
    def reconcile(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ProviderResponse:
        """Reconcile the response after the call.

        For idempotent actions, this MAY re-fetch the provider state to
        confirm the side effect landed (e.g. GET the issue to confirm
        it exists). For partial responses, this MAY retry the read. The
        broker calls this BEFORE returning the response to the caller.
        """

    @abc.abstractmethod
    def redact(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ProviderResponse:
        """Return a copy of ``response`` with any secrets removed.

        This is the final step before the response is written to the
        receipt. Adapters MUST strip:
          * any field whose value matches the credential value;
          * any field the provider marks as sensitive (e.g. ``token``,
            ``authorization``);
          * any URL query parameter that looks like a key.
        """

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def health(self) -> dict[str, Any]:
        """Lightweight health probe.

        Returns ``{"ok": bool, "provider": str, "detail": str}``. MUST
        NOT raise. The broker uses this for readiness checks.
        """

    # ------------------------------------------------------------------
    # Idempotency key helper (default impl)
    # ------------------------------------------------------------------

    @staticmethod
    def idempotency_key(action: str, params: dict[str, Any], nonce: str) -> str:
        """Build a deterministic idempotency key.

        The broker passes a per-action ``nonce`` (typically the action_id
        from the proof). The adapter combines it with the action and the
        canonical params to produce a key that is stable across retries
        of the same logical action but different for different params.
        """
        canonical = json.dumps(
            {"action": action, "params": params}, sort_keys=True, default=str
        )
        h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return f"{action.replace('.', '_')}_{nonce}_{h}"


__all__ = [
    "AdapterError",
    "InvalidParametersError",
    "ProviderAdapter",
    "ProviderPartialResponseError",
    "ProviderResponse",
    "ProviderTimeoutError",
    "ReconciliationConflictError",
    "UnsupportedActionError",
    "ValidationResult",
]
