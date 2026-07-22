"""Actenon Python SDK — the official developer-facing surface.

The SDK provides a small default path for protected execution without
hiding security boundaries. The hero quickstart::

    from actenon_permit import Actenon

    client = Actenon.local(
        agent_id="my-agent",
        scopes=["github.issue.create"],
    )

    intent = client.authorised_execution_intents.create(
        action="github.issue.create",
        target="Actenon/example",
        parameters={"title": "Example", "body": "Created through authorised execution."},
    )

    result = intent.execute()

The SDK is synchronous by default. An async API is available via
``Actenon.async_local()`` for provider and approval workflows that
require it.

Security boundaries are NOT hidden:
  * The raw provider credential is never given to the agent.
  * Every execution returns a discriminated result (brokered vs
    resource-owned) with explicit finality, observation, and receipt
    fields.
  * Development-only defaults emit explicit warnings.
  * No implicit global mutable state — every client is explicit.
"""

from __future__ import annotations

from .client import Actenon
from .config import CloudTransportConfig, LocalRuntimeConfig
from .exceptions import (
    ActenonError,
    ExecutionFailedError,
    ExecutionRefusedError,
    IntentNotFoundError,
    OutcomeUnknownError,
    ProofMissingError,
    ProviderError,
    RetryableError,
)
from .models import (
    BrokeredResult,
    ExecutionResult,
    IntentCreateRequest,
    IntentHandle,
    ResourceOwnedResult,
)
from .receipt import compute_receipt_signature, verify_resource_receipt
from .retry import with_retry

__all__ = [
    "Actenon",
    "ActenonError",
    "BrokeredResult",
    "CloudTransportConfig",
    "ExecutionFailedError",
    "ExecutionRefusedError",
    "ExecutionResult",
    "IntentCreateRequest",
    "IntentHandle",
    "IntentNotFoundError",
    "LocalRuntimeConfig",
    "OutcomeUnknownError",
    "ProofMissingError",
    "ProviderError",
    "ResourceOwnedResult",
    "RetryableError",
    "compute_receipt_signature",
    "verify_resource_receipt",
    "with_retry",
]

__version__ = "1.4.0"
