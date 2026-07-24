"""Stripe payments adapter — concrete implementation of PaymentsAdapter.

Fable 5 Part 3F: "One provider-backed, production-grade payments adapter
with real reconciliation is worth more than ten test-mode adapters,
because it converts 'provider response observed' into 'provider-authenticated
finality,' which is currently an explicit non-guarantee."

Test mode: deterministic mock responses, no network.
Production mode: real Stripe API calls via the stripe Python package.

Reconciliation: after every successful call, re-fetches the object from
Stripe to confirm status, amount, and currency match what was requested.
This is what makes the response "provider-authenticated."
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..credentials import Credential
from . import (
    AdapterError,
    InvalidParametersError,
    ProviderResponse,
    ProviderTimeoutError,
)
from .payments import (
    Money,
    PaymentsAdapter,
    ReconciliationResult,
)


class StripeAdapter(PaymentsAdapter):
    """Concrete Stripe payments adapter."""

    provider_id: str = "stripe"

    def __init__(self, *, test_mode: bool = False, api_base: str = "https://api.stripe.com") -> None:
        self.test_mode = test_mode
        self.api_base = api_base

    def execute(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        *,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse:
        validation = self.validate_params(action, params)
        if not validation.ok:
            raise InvalidParametersError(validation.errors, provider="stripe")

        if self.test_mode:
            return self._execute_test_mode(action, params, credential, idempotency_key)

        return self._execute_live(action, params, credential, idempotency_key, timeout_seconds)

    def _execute_test_mode(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        idempotency_key: str | None,
    ) -> ProviderResponse:
        money = Money(amount=params["amount"], currency=params["currency"]) if "amount" in params else None

        if action == "payment.refund":
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=f"re_test_{idempotency_key or 'nokey'}",
                provider_evidence={
                    "id": f"re_test_{idempotency_key or 'nokey'}",
                    "object": "refund",
                    "amount": money.amount,
                    "currency": money.currency.lower(),
                    "charge": params["charge_id"],
                    "status": "succeeded",
                },
            )

        if action == "invoice.pay":
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=params["invoice_id"],
                provider_evidence={
                    "id": params["invoice_id"],
                    "object": "invoice",
                    "status": "paid",
                    "amount_paid": money.amount,
                    "currency": money.currency.lower(),
                    "payment_method": params["payment_method"],
                },
            )

        if action == "payment.capture":
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=params["payment_intent_id"],
                provider_evidence={
                    "id": params["payment_intent_id"],
                    "object": "payment_intent",
                    "status": "succeeded",
                    "amount": money.amount,
                    "currency": money.currency.lower(),
                },
            )

        if action == "payment.cancel":
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=params["payment_intent_id"],
                provider_evidence={
                    "id": params["payment_intent_id"],
                    "object": "payment_intent",
                    "status": "canceled",
                    "cancellation_reason": params.get("reason", "requested_by_customer"),
                },
            )

        raise AdapterError(f"unsupported action in test mode: {action}", provider="stripe")

    def _execute_live(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        idempotency_key: str | None,
        timeout_seconds: float | None,
    ) -> ProviderResponse:
        try:
            import stripe  # type: ignore[import-untyped]
        except ImportError as e:
            raise AdapterError(
                "stripe package not installed; install with: pip install stripe",
                provider="stripe",
            ) from e

        stripe.api_key = credential.value
        stripe.api_base = self.api_base
        if timeout_seconds is not None:
            stripe.timeout = int(timeout_seconds)

        try:
            if action == "payment.refund":
                raw = stripe.Refund.create(
                    charge=params["charge_id"],
                    amount=params["amount"],
                    currency=params["currency"].lower(),
                    reason=params.get("reason", "requested_by_customer"),
                    metadata=params.get("metadata", {}),
                    idempotency_key=idempotency_key,
                )
                return self.map_response(action, raw)

            if action == "invoice.pay":
                invoice = stripe.Invoice.retrieve(params["invoice_id"])
                if invoice.amount_due != params["amount"]:
                    raise InvalidParametersError(
                        [{"field": "amount", "reason": f"invoice amount_due={invoice.amount_due} but params.amount={params['amount']}"}],
                        provider="stripe",
                    )
                raw = invoice.pay(payment_method=params["payment_method"], idempotency_key=idempotency_key)
                return self.map_response(action, raw)

            if action == "payment.capture":
                raw = stripe.PaymentIntent.capture(
                    params["payment_intent_id"],
                    amount_to_capture=params["amount"],
                    idempotency_key=idempotency_key,
                )
                return self.map_response(action, raw)

            if action == "payment.cancel":
                raw = stripe.PaymentIntent.cancel(
                    params["payment_intent_id"],
                    cancellation_reason=params.get("reason", "requested_by_customer"),
                    idempotency_key=idempotency_key,
                )
                return self.map_response(action, raw)

        except stripe.error.Timeout as e:
            raise ProviderTimeoutError("Stripe API timed out", provider="stripe") from e
        except stripe.error.AuthenticationError as e:
            raise AdapterError("Stripe authentication failed (check API key)", provider="stripe") from e
        except stripe.error.CardError as e:
            raise AdapterError(f"Stripe card error: {e.user_message}", provider="stripe", retryable=False) from e
        except stripe.error.RateLimitError as e:
            raise AdapterError("Stripe rate limited; retry later", provider="stripe", retryable=True) from e
        except stripe.error.APIConnectionError as e:
            raise AdapterError("Stripe API connection error", provider="stripe", retryable=True) from e
        except stripe.error.StripeError as e:
            raise AdapterError(f"Stripe API error: {type(e).__name__}", provider="stripe") from e

        raise AdapterError(f"unsupported action: {action}", provider="stripe")

    def map_response(self, action: str, raw: Any) -> ProviderResponse:
        def _get(obj: Any, key: str, default: Any = None) -> Any:
            if hasattr(obj, key):
                return getattr(obj, key)
            if isinstance(obj, dict):
                return obj.get(key, default)
            return default

        if action == "payment.refund":
            status = str(_get(raw, "status", "unknown"))
            return ProviderResponse(
                ok=status == "succeeded",
                action=action,
                provider_action_id=str(_get(raw, "id", "")),
                provider_evidence={
                    "id": _get(raw, "id"),
                    "object": "refund",
                    "amount": _get(raw, "amount"),
                    "currency": _get(raw, "currency"),
                    "charge": _get(raw, "charge"),
                    "status": status,
                },
            )

        if action == "invoice.pay":
            status = str(_get(raw, "status", "unknown"))
            return ProviderResponse(
                ok=status == "paid",
                action=action,
                provider_action_id=str(_get(raw, "id", "")),
                provider_evidence={
                    "id": _get(raw, "id"),
                    "object": "invoice",
                    "status": status,
                    "amount_paid": _get(raw, "amount_paid"),
                    "currency": _get(raw, "currency"),
                },
            )

        if action in ("payment.capture", "payment.cancel"):
            status = str(_get(raw, "status", "unknown"))
            expected = "succeeded" if action == "payment.capture" else "canceled"
            return ProviderResponse(
                ok=status == expected,
                action=action,
                provider_action_id=str(_get(raw, "id", "")),
                provider_evidence={
                    "id": _get(raw, "id"),
                    "object": "payment_intent",
                    "status": status,
                    "amount": _get(raw, "amount"),
                    "currency": _get(raw, "currency"),
                },
            )

        raise AdapterError(f"cannot map response for action: {action}", provider="stripe")

    def _reconcile(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ReconciliationResult:
        now = datetime.now(UTC).isoformat()

        if self.test_mode:
            return ReconciliationResult(
                reconciled=True,
                provider_status=response.provider_evidence.get("status", ""),
                provider_reference=response.provider_action_id or "",
                confirmed_amount=params.get("amount"),
                confirmed_currency=params.get("currency"),
                checked_at=now,
            )

        try:
            import stripe  # type: ignore[import-untyped]
        except ImportError:
            return ReconciliationResult(
                reconciled=False,
                provider_status=response.provider_evidence.get("status", ""),
                provider_reference=response.provider_action_id or "",
                mismatch="stripe package not installed; cannot reconcile",
                checked_at=now,
            )

        try:
            if action == "payment.refund":
                obj = stripe.Refund.retrieve(response.provider_action_id)
                return self._check_reconciliation(obj, params, response, "amount", "currency", "succeeded", now)
            if action == "invoice.pay":
                obj = stripe.Invoice.retrieve(response.provider_action_id)
                return self._check_reconciliation(obj, params, response, "amount_paid", "currency", "paid", now)
            if action in ("payment.capture", "payment.cancel"):
                obj = stripe.PaymentIntent.retrieve(response.provider_action_id)
                expected_status = "succeeded" if action == "payment.capture" else "canceled"
                return self._check_reconciliation(obj, params, response, "amount", "currency", expected_status, now)
        except Exception as e:
            return ReconciliationResult(
                reconciled=False,
                provider_status=response.provider_evidence.get("status", ""),
                provider_reference=response.provider_action_id or "",
                mismatch=f"reconciliation fetch failed: {type(e).__name__}",
                checked_at=now,
            )

        return ReconciliationResult(
            reconciled=False,
            provider_status=response.provider_evidence.get("status", ""),
            provider_reference=response.provider_action_id or "",
            mismatch=f"cannot reconcile action: {action}",
            checked_at=now,
        )

    def _check_reconciliation(
        self,
        obj: Any,
        params: dict[str, Any],
        response: ProviderResponse,
        amount_field: str,
        currency_field: str,
        expected_status: str,
        checked_at: str,
    ) -> ReconciliationResult:
        def _get(obj: Any, key: str) -> Any:
            if hasattr(obj, key):
                return getattr(obj, key)
            if isinstance(obj, dict):
                return obj.get(key)
            return None

        status = str(_get(obj, "status") or "")
        amount = _get(obj, amount_field)
        currency = _get(obj, currency_field)
        ref = response.provider_action_id or ""

        if status != expected_status:
            return ReconciliationResult(
                reconciled=False,
                provider_status=status,
                provider_reference=ref,
                mismatch=f"status mismatch: expected {expected_status!r}, provider reports {status!r}",
                checked_at=checked_at,
            )

        if amount is not None and params.get("amount") is not None and int(amount) != int(params["amount"]):
            return ReconciliationResult(
                reconciled=False,
                provider_status=status,
                provider_reference=ref,
                mismatch=f"amount mismatch: requested {params['amount']}, provider reports {amount}",
                checked_at=checked_at,
            )

        if currency is not None and params.get("currency") is not None and str(currency).upper() != params["currency"].upper():
            return ReconciliationResult(
                reconciled=False,
                provider_status=status,
                provider_reference=ref,
                mismatch=f"currency mismatch: requested {params['currency']!r}, provider reports {currency!r}",
                checked_at=checked_at,
                )

        return ReconciliationResult(
            reconciled=True,
            provider_status=status,
            provider_reference=ref,
            confirmed_amount=int(amount) if amount is not None else None,
            confirmed_currency=str(currency).upper() if currency else None,
            checked_at=checked_at,
        )

    def redact(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ProviderResponse:
        sensitive_keys = {"api_key", "secret", "token", "authorization", "private_key"}
        redacted_evidence = {
            k: v for k, v in (response.provider_evidence or {}).items()
            if k.lower() not in sensitive_keys
        }
        return ProviderResponse(
            ok=response.ok,
            action=response.action,
            provider_action_id=response.provider_action_id,
            provider_evidence=redacted_evidence,
            cost=response.cost,
            raw=response.raw,
        )

    def health(self) -> dict[str, Any]:
        if self.test_mode:
            return {"ok": True, "provider": "stripe", "detail": "test mode (no network)"}
        return {"ok": True, "provider": "stripe", "detail": f"api_base={self.api_base}"}


__all__ = ["StripeAdapter"]
