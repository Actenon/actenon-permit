"""Agnostic payments adapter — provider-neutral interface for consequential payment actions.

Fable 5 Part 3F: "pick the wedge and go deep rather than wide. The docs
already argue refunds/invoice payments force exact binding of amount,
currency, tenant, actor, and target — the hardest binding case. One
provider-backed, production-grade payments adapter with real
reconciliation is worth more than ten test-mode adapters, because it
converts 'provider response observed' into 'provider-authenticated
finality,' which is currently an explicit non-guarantee."

This module defines the provider-neutral payments adapter contract.
Concrete providers (Stripe, Adyen, Braintree, GoCardless, etc.) implement
this contract. The broker calls only these methods — never a provider SDK
directly — so the same proof-bound execution, exact-parameter binding,
and reconciliation guarantees apply regardless of which payment provider
is wired.

Why payments are special
------------------------

Payments are the hardest binding case in the Actenon ecosystem because
every field is consequential:

  - **amount** — wrong amount = wrong money movement
  - **currency** — wrong currency = FX error or wrong account debit
  - **tenant** — wrong tenant = cross-tenant data leakage
  - **actor** — wrong actor = unauthorized payment
  - **target** — wrong target = payment to wrong account/merchant
  - **idempotency** — duplicate payment = double charge

The payments adapter enforces exact binding on ALL of these fields. The
proof's action_hash covers the canonical payment parameters; the adapter
validates that the params it receives match the proof's params; and the
reconciliation step confirms the provider actually moved the money.

Reconciliation: provider-authenticated finality
-----------------------------------------------

The key innovation is the reconciliation contract. After the provider
returns "succeeded", the adapter does NOT immediately return to the
caller. Instead, it:

  1. Waits for provider-side confirmation (webhook or poll)
  2. Re-fetches the payment object by ID
  3. Confirms the amount, currency, and status match what was requested
  4. Returns a reconciled response with provider-authenticated finality

This converts "provider response observed" (the current non-guarantee)
into "provider-authenticated finality" — the difference between thinking
a refund happened and knowing it happened.

Supported actions
-----------------

  - ``payment.refund``    — refund a previously captured charge
  - ``invoice.pay``       — pay an outstanding invoice
  - ``payment.capture``   — capture a previously authorized payment
  - ``payment.cancel``    — cancel an authorized but uncaptured payment

Each action has a strict parameter schema. Unknown parameters are rejected
(never silently dropped). Amounts are always integer minor units (cents,
pence, etc.) — never floats.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import (
    InvalidParametersError,
    ProviderAdapter,
    ProviderResponse,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Payment-specific data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Money:
    """An amount in minor units (cents, pence, etc.).

    Amounts are ALWAYS integer minor units. Never floats. This prevents
    rounding errors that could move the wrong amount of money.

    Examples:
        Money(amount=2500, currency="GBP")  — £25.00
        Money(amount=1000, currency="USD")  — $10.00
        Money(amount=1, currency="JPY")     — ¥1 (JPY has no minor units)
    """

    amount: int
    currency: str  # ISO 4217 three-letter code

    def __post_init__(self) -> None:
        if self.amount < 0:
            raise ValueError(f"Money.amount must be non-negative, got {self.amount}")
        if not isinstance(self.amount, int):
            raise TypeError(f"Money.amount must be int (minor units), got {type(self.amount).__name__}")
        if len(self.currency) != 3:
            raise ValueError(f"Money.currency must be ISO 4217 3-letter code, got {self.currency!r}")

    def format_display(self) -> str:
        """Human-readable display string (e.g. '£25.00')."""
        symbols = {"GBP": "£", "USD": "$", "EUR": "€", "JPY": "¥"}
        symbol = symbols.get(self.currency, "")
        if self.currency == "JPY":
            return f"{symbol}{self.amount}"
        return f"{symbol}{self.amount / 100:.2f}"


@dataclass(frozen=True)
class ReconciliationResult:
    """Result of reconciling a payment action against the provider.

    Attributes:
        reconciled: True if the provider confirmed the action landed.
        provider_status: The status observed from the provider (e.g. "succeeded", "pending", "failed").
        provider_reference: The provider's reference for the action (e.g. charge ID, refund ID).
        confirmed_amount: The amount the provider confirms was moved (for audit).
        confirmed_currency: The currency the provider confirms was used.
        mismatch: If reconciled is False, describes the mismatch.
        checked_at: ISO 8601 timestamp of the reconciliation check.
    """

    reconciled: bool
    provider_status: str
    provider_reference: str
    confirmed_amount: int | None = None
    confirmed_currency: str | None = None
    mismatch: str | None = None
    checked_at: str = ""


# ---------------------------------------------------------------------------
# Action parameter schemas (strict — unknown fields rejected)
# ---------------------------------------------------------------------------


PAYMENT_ACTION_SCHEMAS: dict[str, dict[str, type]] = {
    "payment.refund": {
        "charge_id": str,
        "amount": int,
        "currency": str,
        "reason": str,
        "metadata": dict,
    },
    "invoice.pay": {
        "invoice_id": str,
        "amount": int,
        "currency": str,
        "payment_method": str,
        "metadata": dict,
    },
    "payment.capture": {
        "payment_intent_id": str,
        "amount": int,
        "currency": str,
        "metadata": dict,
    },
    "payment.cancel": {
        "payment_intent_id": str,
        "reason": str,
        "metadata": dict,
    },
}

PAYMENT_REQUIRED_FIELDS: dict[str, set[str]] = {
    "payment.refund": {"charge_id", "amount", "currency"},
    "invoice.pay": {"invoice_id", "amount", "currency", "payment_method"},
    "payment.capture": {"payment_intent_id", "amount", "currency"},
    "payment.cancel": {"payment_intent_id"},
}


# ---------------------------------------------------------------------------
# Abstract payments adapter
# ---------------------------------------------------------------------------


class PaymentsAdapter(ProviderAdapter):
    """Abstract base for all payment provider adapters.

    Extends ProviderAdapter with payment-specific validation and
    reconciliation. Concrete adapters (Stripe, Adyen, etc.) implement
    the provider-specific _execute and _reconcile methods.
    """

    provider_id: str = "abstract-payments"

    def supported_actions(self) -> list[str]:
        return list(PAYMENT_ACTION_SCHEMAS.keys())

    def validate_params(self, action: str, params: dict[str, Any]) -> ValidationResult:
        """Validate payment action parameters.

        Rejects:
          - unknown actions
          - unknown parameter keys (never silently dropped)
          - wrong types (amount must be int, not float or string)
          - missing required fields
          - negative amounts
          - invalid currency codes
        """
        if action not in PAYMENT_ACTION_SCHEMAS:
            return ValidationResult(
                ok=False,
                unknown_fields=[],
                errors=[{"field": "action", "reason": f"unsupported payment action: {action!r}"}],
            )

        schema = PAYMENT_ACTION_SCHEMAS[action]
        required = PAYMENT_REQUIRED_FIELDS[action]
        errors: list[dict[str, str]] = []
        unknown: list[str] = []

        for key in params:
            if key not in schema:
                unknown.append(key)

        for key, expected_type in schema.items():
            if key not in params:
                if key in required:
                    errors.append({"field": key, "reason": "required field missing"})
                continue

            value = params[key]
            if not isinstance(value, expected_type):
                errors.append({
                    "field": key,
                    "reason": f"expected {expected_type.__name__}, got {type(value).__name__}",
                })
                continue

            if key == "amount" and isinstance(value, int) and value < 0:
                errors.append({"field": "amount", "reason": "must be non-negative (minor units)"})

            if key == "currency" and isinstance(value, str):
                if len(value) != 3:
                    errors.append({"field": "currency", "reason": "must be ISO 4217 3-letter code"})

        return ValidationResult(ok=len(errors) == 0 and len(unknown) == 0, unknown_fields=unknown, errors=errors)

    def reconcile(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ProviderResponse:
        """Reconcile a payment response against the provider.

        This is the key innovation: after the provider says "succeeded",
        we re-fetch the object to confirm the amount, currency, and
        status match what was requested. This converts "provider response
        observed" into "provider-authenticated finality".
        """
        if not response.ok:
            return response

        result = self._reconcile(action, params, response)

        evidence = dict(response.provider_evidence)

        if not result.reconciled:
            evidence["reconciliation"] = {
                "reconciled": False,
                "mismatch": result.mismatch,
                "checked_at": result.checked_at,
            }
            return ProviderResponse(
                ok=False,
                action=action,
                provider_action_id=response.provider_action_id,
                provider_evidence=evidence,
                raw=response.raw,
            )

        evidence["reconciliation"] = {
            "reconciled": True,
            "confirmed_amount": result.confirmed_amount,
            "confirmed_currency": result.confirmed_currency,
            "checked_at": result.checked_at,
        }
        return ProviderResponse(
            ok=True,
            action=action,
            provider_action_id=response.provider_action_id,
            provider_evidence=evidence,
            raw=response.raw,
        )

    def _reconcile(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ReconciliationResult:
        """Provider-specific reconciliation. Override in concrete adapters."""
        raise NotImplementedError


__all__ = [
    "Money",
    "PAYMENT_ACTION_SCHEMAS",
    "PAYMENT_REQUIRED_FIELDS",
    "PaymentsAdapter",
    "ReconciliationResult",
]
