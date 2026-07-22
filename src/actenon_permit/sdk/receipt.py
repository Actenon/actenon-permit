"""Receipt verification helpers for the Actenon SDK.

These helpers let developers verify resource receipts independently,
without trusting the broker's assertion that the receipt is valid.

Usage::

    from actenon_permit.sdk.receipt import verify_resource_receipt

    verified = verify_resource_receipt(
        receipt={"charge_id": "ch_123", "signing_key_id": "rk_1", "signature": "..."},
        signing_keys={"rk_1": b"the-secret-bytes"},
    )
    if not verified:
        raise ValueError("forged receipt!")
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from actenon.execution.mode_aware import (
    ResourceReceiptVerificationError,
    ResourceReceiptVerifier,
    ResourceSigningKey,
)


def verify_resource_receipt(
    receipt: dict[str, Any],
    signing_keys: dict[str, bytes],
) -> bool:
    """Verify a resource receipt against a set of known signing keys.

    Args:
        receipt: The receipt dict (must contain ``signing_key_id`` and
            ``signature`` fields).
        signing_keys: A mapping of ``key_id`` -> ``secret_bytes``.

    Returns:
        True iff the receipt's signature matches the canonical body
        computed with the key identified by ``signing_key_id``.

    Raises:
        ResourceReceiptVerificationError: if the receipt is malformed
            (missing ``signature`` or ``signing_key_id``, or the
            ``signing_key_id`` is not in ``signing_keys``).
    """
    verifier = ResourceReceiptVerifier()
    for key_id, secret in signing_keys.items():
        verifier.register_key(ResourceSigningKey(
            resource_id="sdk-verify",
            key_id=key_id,
            secret=secret,
        ))
    try:
        verifier.verify_or_raise(receipt)
        return True
    except ResourceReceiptVerificationError:
        return False


def compute_receipt_signature(
    body: dict[str, Any],
    secret: bytes,
) -> str:
    """Compute the HMAC-SHA256 signature for a receipt body.

    This is the same canonicalisation + HMAC that the
    ``ResourceReceiptVerifier`` uses. Exposed for testing and for
    resource boundary implementors who need to sign receipts.
    """
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


__all__ = [
    "compute_receipt_signature",
    "verify_resource_receipt",
]
