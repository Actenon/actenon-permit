"""Mock providers for the Actenon-Permit demo.

These are deliberately fake. They do NOT touch the network. They do NOT
process real money. They exist so the demo can run with zero external
accounts and zero API keys.

The canonical implementation lives in ``actenon_permit._mock_providers``;
this file re-exports it so the SPEC's repo layout (``examples/mock_providers.py``)
is preserved.
"""

from actenon_permit._mock_providers import (
    MockProviderError,
    mock_send_email,
    mock_stripe_charge,
    mock_stripe_refund,
)

__all__ = [
    "MockProviderError",
    "mock_send_email",
    "mock_stripe_charge",
    "mock_stripe_refund",
]
