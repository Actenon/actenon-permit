"""Mock providers for the Actenon-Permit demo.

These are deliberately fake. They do NOT touch the network. They do NOT
process real money. They exist so the demo can run with zero external
accounts and zero API keys.

The "secret" they accept is a mock value (`sk_mock_123`) that lives only
inside the broker — the agent never sees it.
"""

from __future__ import annotations

from typing import Any


class MockProviderError(RuntimeError):
    """Raised when a mock provider is called incorrectly."""


def mock_stripe_refund(secret: str, amount: float, reason: str = "customer_request") -> dict[str, Any]:
    """Pretend to issue a refund via Stripe. Returns a fake charge id.

    The mock validates that the secret looks like our mock key — this is
    purely to prove the broker passed the right value. The agent never sees
    ``secret``.
    """
    if not secret or not secret.startswith("sk_mock_"):
        raise MockProviderError("mock stripe refused: bad secret")
    return {
        "id": f"re_mock_{abs(hash((amount, reason))) % 10_000_000:07d}",
        "amount": float(amount),
        "currency": "USD",
        "reason": reason,
        "status": "succeeded",
        "mock": True,
    }


def mock_stripe_charge(secret: str, amount: float, description: str = "") -> dict[str, Any]:
    """Pretend to charge a card. This is what an injected agent might try."""
    if not secret or not secret.startswith("sk_mock_"):
        raise MockProviderError("mock stripe refused: bad secret")
    return {
        "id": f"ch_mock_{abs(hash((amount, description))) % 10_000_000:07d}",
        "amount": float(amount),
        "currency": "USD",
        "description": description,
        "status": "succeeded",
        "mock": True,
    }


def mock_send_email(secret: str, to: str, subject: str, body: str = "") -> dict[str, Any]:
    """Pretend to send an email. No SMTP, no network."""
    if not secret or not secret.startswith("sk_mock_"):
        raise MockProviderError("mock email refused: bad secret")
    return {
        "id": f"msg_mock_{abs(hash((to, subject, body))) % 10_000_000:07d}",
        "to": to,
        "subject": subject,
        "status": "sent",
        "mock": True,
    }
