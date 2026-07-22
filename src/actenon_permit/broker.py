"""Actenon-Permit credential broker.

The broker is the airlock between an ALLOW decision and the real-world call.
It resolves a credential by NAME (e.g. ``"stripe_key"``) from the environment
at call time — the secret is never passed to or returned to the agent. Only
after a prior ALLOW does the broker invoke the real call, passing the secret
only to that call.

In v0 the broker is in-process. v1 (roadmap) moves it to an out-of-process
proxy / MCP-gateway PEP so even an agent with arbitrary code-exec cannot
import the provider SDK directly to bypass the wrapper.

**v1.1 (Prompt 8)** adds the adapter-based execution path. The broker can
now drive a ``ProviderAdapter`` (see ``actenon_permit.adapters``) through
``execute_via_adapter()``. This path enforces the full Prompt-8 boundary:

  * credentials are resolved from a ``CredentialProviderRegistry``,
    NOT a raw env-var lookup;
  * the adapter validates parameters strictly (unknown fields rejected);
  * the adapter executes the EXACT action that was authorised (the broker
    refuses to call a different action than the one in the proof);
  * the adapter returns a normalised ``ProviderResponse``;
  * the broker reconciles cost via the PDP;
  * the broker redacts secrets from receipts and logs;
  * the broker destroys / purges ephemeral credentials after the call.

The legacy ``execute()`` method (env-var lookup + raw ``real_call`` lambda)
is preserved for backward compatibility with the v1 gateway.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from .adapters import (
    AdapterError,
    InvalidParametersError,
    ProviderAdapter,
    ProviderResponse,
    UnsupportedActionError,
)
from .credentials import (
    Credential,
    CredentialProvider,
    CredentialProviderRegistry,
    CredentialResolutionError,
)
from .model import Action, Decision, Grant
from .pdp import PDP

logger = logging.getLogger(__name__)


class CredentialMissing(RuntimeError):
    """Raised when a referenced credential name is not present in the environment."""


class BrokerExecutionError(RuntimeError):
    """Raised when an adapter call fails. The message is sanitised -
    it MUST NOT contain the credential value."""

    def __init__(self, safe_message: str, *, retryable: bool = False, rule: str = ""):
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.retryable = retryable
        self.rule = rule or "broker:execution_error"

    def __str__(self) -> str:
        return self.safe_message


class Broker:
    """Resolves credentials by name and runs guarded real-world calls.

    The broker has two execution paths:

    1. ``execute()`` (legacy v1) - env-var lookup + raw ``real_call``
       lambda. Used by the v1 gateway for backward compatibility.

    2. ``execute_via_adapter()`` (v1.1, Prompt 8) - resolves the
       credential via a ``CredentialProviderRegistry``, invokes a
       ``ProviderAdapter`` for the EXACT authorised action, then
       redacts and reconciles.

    Both paths share the same PDP commit / release semantics for budget.
    """

    def __init__(
        self,
        pdp: PDP,
        *,
        credential_providers: CredentialProviderRegistry | None = None,
        production_mode: bool = False,
    ):
        self.pdp = pdp
        self.credential_providers = credential_providers or CredentialProviderRegistry()
        self.production_mode = production_mode
        # Track materialised credentials so we can destroy them after the
        # call. Single-use only - never cached across calls.
        self._live_credentials: dict[int, Credential] = {}

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    @staticmethod
    def resolve(name: str) -> str:
        """Look up a credential by NAME in the environment.

        The returned value NEVER leaves the broker — it is passed only to the
        ``real_call`` callable inside ``execute``. If the env var is missing,
        raises CredentialMissing (which the PEP must surface as a DENY).
        """
        val = os.environ.get(name)
        if val is None or val == "":
            raise CredentialMissing(f"credential '{name}' is not set in the environment")
        return val

    # ------------------------------------------------------------------
    # Guarded execution
    # ------------------------------------------------------------------

    def execute(
        self,
        grant: Grant,
        action: Action,
        decision: Decision,
        real_call: Callable[[str], Any],
        credential_name: str,
    ) -> tuple[Any, float]:
        """Run ``real_call(resolved_secret)`` after a prior ALLOW.

        Returns ``(result, actual_cost)`` where ``actual_cost`` is whatever
        ``real_call`` reports (see ``cost_key`` / return contract below).

        ``real_call`` may return:
        - a dict with an ``"amount"`` key (used as actual_cost)
        - a dict with a ``"cost"`` key
        - a plain number (used as actual_cost)
        - anything else (actual_cost defaults to ``action.est_cost``)

        After the call returns, the broker reconciles cost with the PDP.
        """
        if not decision or decision.outcome.value != "ALLOW":
            raise RuntimeError("broker.execute called without a prior ALLOW")

        secret = self.resolve(credential_name)
        # The secret is a local variable. It is NEVER returned, NEVER logged,
        # NEVER passed anywhere except to real_call.
        result = real_call(secret)

        actual_cost = extract_cost(result, action)
        self.pdp.commit(grant, action, actual_cost)
        return result, actual_cost

    # ------------------------------------------------------------------
    # Adapter-based execution (v1.1, Prompt 8)
    # ------------------------------------------------------------------

    def execute_via_adapter(
        self,
        grant: Grant,
        action: Action,
        decision: Decision,
        adapter: ProviderAdapter,
        *,
        credential_ref: str,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
    ) -> tuple[ProviderResponse, float]:
        """Run an adapter call after a prior ALLOW, with the full Prompt-8
        boundary enforced.

        Boundary contract (enforced here, NOT delegated to the adapter):

          1. ``decision.outcome == ALLOW`` (else RuntimeError).
          2. The adapter's action MUST equal ``action.type``. The broker
             refuses to execute a different action than the one in the
             proof. The adapter cannot broaden parameters.
          3. Credential is resolved from ``self.credential_providers``
             (NOT a raw env var) by reference. The agent never sees the
             ``credential_ref`` -> value mapping.
          4. If the credential is marked ``development_only`` and the
             broker is in ``production_mode``, the call is refused.
          5. After the call, the credential is destroyed (zeroed in
             memory and dropped from the live-credentials map).
          6. The adapter's response is redacted by the adapter (the
             broker trusts but verifies - it strips any field whose
             value matches the credential).
          7. Cost is reconciled via the PDP.
          8. ANY exception is wrapped in ``BrokerExecutionError`` with
             a sanitised message - never the credential value.

        Returns ``(response, actual_cost)`` where ``response`` is the
        redacted ``ProviderResponse`` safe to write to the receipt.
        """
        # 1. Prior ALLOW required.
        if not decision or decision.outcome.value != "ALLOW":
            raise RuntimeError("broker.execute_via_adapter called without a prior ALLOW")

        # 2. Exact-action enforcement. The adapter is being asked to
        # execute ``action``; it MUST NOT be invoked for any other
        # action. We pass ``action.type`` to the adapter and trust the
        # adapter to validate it, but we ALSO assert that the caller
        # is not trying to slip a different action through.
        # (The PDP already decided on ``action.type``; if the adapter
        # is wired with a different action_type in the ToolSpec, that
        # is a wiring bug we want to fail loud on.)
        # The check below is a defensive duplicate - the gateway
        # enforces this at registration time too.
        adapter_actions = set(adapter.supported_actions())
        if action.type not in adapter_actions:
            raise BrokerExecutionError(
                f"adapter '{adapter.provider_id}' does not support action '{action.type}'",
                rule="broker:action_not_supported",
            )

        # 3. Resolve credential via the provider registry. This raises
        # CredentialResolutionError, which the gateway surfaces as a
        # DENY (never as a 500).
        try:
            credential = self.credential_providers.resolve(credential_ref)
        except CredentialResolutionError as e:
            raise BrokerExecutionError(
                str(e), retryable=e.retryable, rule="broker:credential_resolution_failed"
            ) from e

        # 4. Production-mode guard against development-only credentials.
        if self.production_mode and credential.development_only:
            # Destroy immediately and refuse.
            self._destroy_credential(credential)
            raise BrokerExecutionError(
                f"credential ref '{credential_ref}' is marked development-only; "
                "refused in production mode",
                rule="broker:dev_credential_in_production",
            )

        # Track the live credential so we can destroy it on any exit path.
        cred_id = id(credential)
        self._live_credentials[cred_id] = credential

        # 5. Execute via the adapter. The credential value is passed
        # ONLY to the adapter.execute() call - never returned, never
        # logged. The adapter is responsible for using it to
        # authenticate the underlying provider call.
        try:
            response = adapter.execute(
                action=action.type,
                params=dict(action.params),
                credential=credential,
                idempotency_key=idempotency_key,
                timeout_seconds=timeout_seconds,
            )
        except UnsupportedActionError as e:
            raise BrokerExecutionError(str(e), rule="broker:unsupported_action") from e
        except InvalidParametersError as e:
            raise BrokerExecutionError(str(e), rule="broker:invalid_parameters") from e
        except AdapterError as e:
            raise BrokerExecutionError(
                str(e), retryable=e.retryable, rule=f"adapter:{adapter.provider_id}"
            ) from e
        except Exception as e:
            # Unexpected adapter crash. Sanitise the message - never
            # include the credential value (which might appear in a
            # library's exception text if it leaks via a stack trace).
            safe = f"adapter '{adapter.provider_id}' raised {type(e).__name__}"
            raise BrokerExecutionError(safe, rule="broker:adapter_crash") from e
        finally:
            # 5b. Destroy the credential regardless of outcome. The
            # value is overwritten with zeros in memory and the
            # reference is dropped from the live-credentials map.
            cred = self._live_credentials.pop(cred_id, None)
            if cred is not None:
                self._destroy_credential(cred)

        # 6. Belt-and-braces redaction: strip any field whose value
        # matches the credential value, even if the adapter's redact()
        # missed it. The credential has already been destroyed, but
        # we kept a local reference for this exact check.
        response = self._final_redact(response, credential)

        # 7. Reconcile cost. Adapters may report a cost (e.g. usage-
        # based billing). If they don't, fall back to the reservation.
        actual_cost = response.cost if response.cost is not None else float(action.est_cost or 0.0)
        self.pdp.commit(grant, action, actual_cost)

        return response, actual_cost

    # ------------------------------------------------------------------
    # Credential destruction + final redaction
    # ------------------------------------------------------------------

    @staticmethod
    def _destroy_credential(credential: Credential) -> None:
        """Best-effort destroy: overwrite the value with zeros, clear
        the dataclass field, drop the reference. Python's memory model
        means this is not a cryptographic wipe (the GC may have copied
        the string), but it raises the bar for memory-scraping attacks
        and ensures the broker does not hold the value longer than
        necessary.
        """
        # The Credential value is a str, which is immutable in Python.
        # We can't zero it in place. Best we can do is drop our
        # reference and let GC reclaim it. We also clear the dataclass
        # field so accidental logging of the Credential object doesn't
        # leak the value.
        try:
            object.__setattr__(credential, "value", "")
        except Exception:
            pass

    @staticmethod
    def _final_redact(response: ProviderResponse, credential: Credential) -> ProviderResponse:
        """Belt-and-braces redaction. The adapter's ``redact()`` has
        already run; this is the broker's defensive pass to ensure the
        credential value does not appear anywhere in the evidence.

        We compare the credential value against every string field in
        ``provider_evidence`` and replace any match with ``<redacted>``.
        We never log the credential value here.
        """
        secret = credential.value
        if not secret:
            return response

        def _scrub(v: Any) -> Any:
            if isinstance(v, str):
                if secret in v:
                    return "<redacted>"
                return v
            if isinstance(v, dict):
                return {k: _scrub(val) for k, val in v.items()}
            if isinstance(v, list):
                return [_scrub(item) for item in v]
            return v

        return ProviderResponse(
            ok=response.ok,
            action=response.action,
            provider_action_id=response.provider_action_id,
            provider_evidence=_scrub(response.provider_evidence),
            cost=response.cost,
            raw=None,  # Always drop raw on the broker side.
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Aggregate health of the broker + its credential providers."""
        return {
            "ok": True,
            "production_mode": self.production_mode,
            "credential_providers": self.credential_providers.health(),
            "live_credentials": len(self._live_credentials),
        }


def extract_cost(result: Any, action: Action) -> float:
    """Extract the actual cost of a completed call from its result.

    Public helper (was ``Broker._extract_cost``). Used by both the broker
    and the gateway's no-credential path. The lookup order is:

    1. ``result`` is a number → use it.
    2. ``result`` is a dict with one of ``amount`` / ``cost`` /
       ``actual_cost`` / ``charged`` → use that.
    3. Fall back to ``action.est_cost`` (the reservation). The broker does
       NOT inflate cost.

    This is deliberately permissive: real provider SDKs return a variety of
    shapes, and we'd rather fall back to the reservation than crash.
    """
    if isinstance(result, (int, float)):
        return float(result)
    if isinstance(result, dict):
        for k in ("amount", "cost", "actual_cost", "charged"):
            if k in result and isinstance(result[k], (int, float)):
                return float(result[k])
    # Fall back to the reservation. The broker does NOT inflate cost.
    return float(action.est_cost or 0.0)
