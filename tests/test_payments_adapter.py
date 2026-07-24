"""Tests for the agnostic payments adapter and Stripe implementation.

Tests use test_mode=True — no real Stripe API calls are made.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from actenon_permit.adapters import (
    InvalidParametersError,
    ProviderResponse,
)
from actenon_permit.adapters.payments import (
    Money,
)
from actenon_permit.adapters.stripe import StripeAdapter
from actenon_permit.credentials import Credential


def _make_credential() -> Credential:
    return Credential(ref="STRIPE_SECRET_KEY", value="sk_test_fake_not_a_real_key_12345", source="env")


class TestMoney(unittest.TestCase):
    def test_valid_money(self):
        m = Money(amount=2500, currency="GBP")
        self.assertEqual(m.amount, 2500)
        self.assertEqual(m.currency, "GBP")

    def test_float_amount_rejected(self):
        with self.assertRaises(TypeError):
            Money(amount=25.00, currency="GBP")

    def test_negative_amount_rejected(self):
        with self.assertRaises(ValueError):
            Money(amount=-100, currency="GBP")

    def test_invalid_currency_rejected(self):
        with self.assertRaises(ValueError):
            Money(amount=100, currency="POUND")
        with self.assertRaises(ValueError):
            Money(amount=100, currency="GB")

    def test_display_format(self):
        self.assertEqual(Money(amount=2500, currency="GBP").format_display(), "£25.00")
        self.assertEqual(Money(amount=1000, currency="USD").format_display(), "$10.00")
        self.assertEqual(Money(amount=100, currency="JPY").format_display(), "¥100")
        self.assertEqual(Money(amount=500, currency="EUR").format_display(), "€5.00")


class TestPaymentsAdapterValidation(unittest.TestCase):
    def setUp(self):
        self.adapter = StripeAdapter(test_mode=True)

    def test_supported_actions(self):
        actions = self.adapter.supported_actions()
        self.assertIn("payment.refund", actions)
        self.assertIn("invoice.pay", actions)
        self.assertIn("payment.capture", actions)
        self.assertIn("payment.cancel", actions)

    def test_unknown_action_rejected(self):
        result = self.adapter.validate_params("payment.wire_transfer", {"amount": 100})
        self.assertFalse(result.ok)

    def test_unknown_field_rejected(self):
        result = self.adapter.validate_params("payment.refund", {
            "charge_id": "ch_123",
            "amount": 2500,
            "currency": "GBP",
            "evil_field": "should be rejected",
        })
        self.assertFalse(result.ok)
        self.assertIn("evil_field", result.unknown_fields)

    def test_missing_required_field_rejected(self):
        result = self.adapter.validate_params("payment.refund", {
            "charge_id": "ch_123",
            "currency": "GBP",
        })
        self.assertFalse(result.ok)
        error_fields = [e["field"] for e in result.errors]
        self.assertIn("amount", error_fields)

    def test_float_amount_rejected(self):
        result = self.adapter.validate_params("payment.refund", {
            "charge_id": "ch_123",
            "amount": 25.00,
            "currency": "GBP",
        })
        self.assertFalse(result.ok)
        error_fields = [e["field"] for e in result.errors]
        self.assertIn("amount", error_fields)

    def test_negative_amount_rejected(self):
        result = self.adapter.validate_params("payment.refund", {
            "charge_id": "ch_123",
            "amount": -100,
            "currency": "GBP",
        })
        self.assertFalse(result.ok)

    def test_invalid_currency_rejected(self):
        result = self.adapter.validate_params("payment.refund", {
            "charge_id": "ch_123",
            "amount": 100,
            "currency": "POUND",
        })
        self.assertFalse(result.ok)

    def test_valid_params_pass(self):
        result = self.adapter.validate_params("payment.refund", {
            "charge_id": "ch_123",
            "amount": 2500,
            "currency": "GBP",
            "reason": "requested_by_customer",
        })
        self.assertTrue(result.ok, f"Expected ok, got errors: {result.errors}")


class TestStripeAdapterTestMode(unittest.TestCase):
    def setUp(self):
        self.adapter = StripeAdapter(test_mode=True)
        self.credential = _make_credential()

    def test_refund_test_mode(self):
        response = self.adapter.execute(
            "payment.refund",
            {"charge_id": "ch_123", "amount": 2500, "currency": "GBP", "reason": "requested_by_customer"},
            self.credential,
            idempotency_key="test-key-1",
        )
        self.assertTrue(response.ok)
        self.assertEqual(response.provider_evidence["status"], "succeeded")
        self.assertTrue(response.provider_action_id.startswith("re_test_"))
        self.assertEqual(response.provider_evidence["amount"], 2500)
        self.assertEqual(response.provider_evidence["currency"], "gbp")
        self.assertEqual(response.provider_evidence["charge"], "ch_123")

    def test_invoice_pay_test_mode(self):
        response = self.adapter.execute(
            "invoice.pay",
            {"invoice_id": "in_123", "amount": 5000, "currency": "USD", "payment_method": "pm_123"},
            self.credential,
            idempotency_key="test-key-2",
        )
        self.assertTrue(response.ok)
        self.assertEqual(response.provider_evidence["status"], "paid")
        self.assertEqual(response.provider_action_id, "in_123")
        self.assertEqual(response.provider_evidence["amount_paid"], 5000)

    def test_payment_capture_test_mode(self):
        response = self.adapter.execute(
            "payment.capture",
            {"payment_intent_id": "pi_123", "amount": 3000, "currency": "EUR"},
            self.credential,
            idempotency_key="test-key-3",
        )
        self.assertTrue(response.ok)
        self.assertEqual(response.provider_evidence["status"], "succeeded")
        self.assertEqual(response.provider_action_id, "pi_123")
        self.assertEqual(response.provider_evidence["amount"], 3000)

    def test_payment_cancel_test_mode(self):
        response = self.adapter.execute(
            "payment.cancel",
            {"payment_intent_id": "pi_456", "reason": "requested_by_customer"},
            self.credential,
            idempotency_key="test-key-4",
        )
        self.assertTrue(response.ok)
        self.assertEqual(response.provider_evidence["status"], "canceled")
        self.assertEqual(response.provider_action_id, "pi_456")

    def test_invalid_params_raise_before_api_call(self):
        with self.assertRaises(InvalidParametersError):
            self.adapter.execute(
                "payment.refund",
                {"charge_id": "ch_123", "amount": -100, "currency": "GBP"},
                self.credential,
            )


class TestReconciliation(unittest.TestCase):
    """Tests for the reconciliation contract — provider-authenticated finality."""

    def setUp(self):
        self.adapter = StripeAdapter(test_mode=True)
        self.credential = _make_credential()

    def test_reconciliation_test_mode_succeeds(self):
        response = self.adapter.execute(
            "payment.refund",
            {"charge_id": "ch_123", "amount": 2500, "currency": "GBP", "reason": "requested_by_customer"},
            self.credential,
            idempotency_key="recon-test-1",
        )
        reconciled = self.adapter.reconcile("payment.refund", {"amount": 2500, "currency": "GBP"}, response)
        self.assertTrue(reconciled.ok)
        self.assertIn("reconciliation", reconciled.provider_evidence)
        self.assertTrue(reconciled.provider_evidence["reconciliation"]["reconciled"])
        self.assertEqual(reconciled.provider_evidence["reconciliation"]["confirmed_amount"], 2500)
        self.assertEqual(reconciled.provider_evidence["reconciliation"]["confirmed_currency"], "GBP")

    def test_reconciliation_failed_response_skipped(self):
        failed_response = ProviderResponse(
            ok=False,
            action="payment.refund",
            provider_action_id="re_123",
            provider_evidence={"error": "card declined"},
        )
        result = self.adapter.reconcile("payment.refund", {}, failed_response)
        self.assertFalse(result.ok)

    def test_reconciliation_detects_amount_mismatch_live_mode(self):
        adapter = StripeAdapter(test_mode=False)
        mock_stripe = MagicMock()
        mock_refund = MagicMock()
        mock_refund.status = "succeeded"
        mock_refund.amount = 25000
        mock_refund.currency = "gbp"
        mock_stripe.Refund.retrieve.return_value = mock_refund

        with patch.dict("sys.modules", {"stripe": mock_stripe}):
            response = ProviderResponse(
                ok=True,
                action="payment.refund",
                provider_action_id="re_123",
                provider_evidence={"amount": 2500, "currency": "GBP"},
            )
            params = {"charge_id": "ch_123", "amount": 2500, "currency": "GBP"}
            result = adapter.reconcile("payment.refund", params, response)

        self.assertFalse(result.ok)
        self.assertIn("amount mismatch", result.provider_evidence["reconciliation"]["mismatch"])
        self.assertIn("2500", result.provider_evidence["reconciliation"]["mismatch"])
        self.assertIn("25000", result.provider_evidence["reconciliation"]["mismatch"])

    def test_reconciliation_detects_status_mismatch_live_mode(self):
        adapter = StripeAdapter(test_mode=False)
        mock_stripe = MagicMock()
        mock_refund = MagicMock()
        mock_refund.status = "pending"
        mock_refund.amount = 2500
        mock_refund.currency = "gbp"
        mock_stripe.Refund.retrieve.return_value = mock_refund

        with patch.dict("sys.modules", {"stripe": mock_stripe}):
            response = ProviderResponse(
                ok=True,
                action="payment.refund",
                provider_action_id="re_123",
                provider_evidence={"amount": 2500, "currency": "GBP"},
            )
            params = {"charge_id": "ch_123", "amount": 2500, "currency": "GBP"}
            result = adapter.reconcile("payment.refund", params, response)

        self.assertFalse(result.ok)
        self.assertIn("status mismatch", result.provider_evidence["reconciliation"]["mismatch"])

    def test_reconciliation_detects_currency_mismatch_live_mode(self):
        adapter = StripeAdapter(test_mode=False)
        mock_stripe = MagicMock()
        mock_refund = MagicMock()
        mock_refund.status = "succeeded"
        mock_refund.amount = 2500
        mock_refund.currency = "usd"
        mock_stripe.Refund.retrieve.return_value = mock_refund

        with patch.dict("sys.modules", {"stripe": mock_stripe}):
            response = ProviderResponse(
                ok=True,
                action="payment.refund",
                provider_action_id="re_123",
                provider_evidence={"amount": 2500, "currency": "GBP"},
            )
            params = {"charge_id": "ch_123", "amount": 2500, "currency": "GBP"}
            result = adapter.reconcile("payment.refund", params, response)

        self.assertFalse(result.ok)
        self.assertIn("currency mismatch", result.provider_evidence["reconciliation"]["mismatch"])

    def test_reconciliation_succeeds_when_all_match_live_mode(self):
        adapter = StripeAdapter(test_mode=False)
        mock_stripe = MagicMock()
        mock_refund = MagicMock()
        mock_refund.status = "succeeded"
        mock_refund.amount = 2500
        mock_refund.currency = "gbp"
        mock_stripe.Refund.retrieve.return_value = mock_refund

        with patch.dict("sys.modules", {"stripe": mock_stripe}):
            response = ProviderResponse(
                ok=True,
                action="payment.refund",
                provider_action_id="re_123",
                provider_evidence={"amount": 2500, "currency": "GBP"},
            )
            params = {"charge_id": "ch_123", "amount": 2500, "currency": "GBP"}
            result = adapter.reconcile("payment.refund", params, response)

        self.assertTrue(result.ok)
        self.assertTrue(result.provider_evidence["reconciliation"]["reconciled"])
        self.assertEqual(result.provider_evidence["reconciliation"]["confirmed_amount"], 2500)
        self.assertEqual(result.provider_evidence["reconciliation"]["confirmed_currency"], "GBP")


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.adapter = StripeAdapter(test_mode=True)

    def test_sensitive_fields_stripped(self):
        response = ProviderResponse(
            ok=True,
            action="payment.refund",
            provider_action_id="re_123",
            provider_evidence={
                "id": "re_123",
                "amount": 2500,
                "api_key": "sk_live_should_be_stripped",
                "token": "tok_should_be_stripped",
            },
        )
        redacted = self.adapter.redact("payment.refund", {}, response)
        self.assertNotIn("api_key", redacted.provider_evidence)
        self.assertNotIn("token", redacted.provider_evidence)
        self.assertIn("id", redacted.provider_evidence)
        self.assertIn("amount", redacted.provider_evidence)


class TestHealth(unittest.TestCase):
    def test_health_test_mode(self):
        adapter = StripeAdapter(test_mode=True)
        result = adapter.health()
        self.assertTrue(result["ok"])
        self.assertEqual(result["provider"], "stripe")
        self.assertIn("test mode", result["detail"])

    def test_health_live_mode(self):
        adapter = StripeAdapter(test_mode=False)
        result = adapter.health()
        self.assertTrue(result["ok"])
        self.assertEqual(result["provider"], "stripe")
        self.assertIn("api_base", result["detail"])


if __name__ == "__main__":
    unittest.main()
