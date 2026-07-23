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
        target="github",
        parameters={"title": "Example", "body": "Created through authorised execution."},
    )

    result = intent.execute()

An async API is available via ``Actenon.async_local()`` /
``Actenon.async_cloud()`` for provider and approval workflows that
require it.

Security boundaries are NOT hidden:
  * The raw provider credential is never given to the agent.
  * Every execution returns a discriminated result (brokered vs
    resource-owned) with explicit finality, observation, and receipt
    fields.
  * Development-only defaults emit explicit warnings.
  * No implicit global mutable state — every client is explicit.

Signing-key resolution (LocalRuntimeConfig):
  1. ``signing_key=`` argument (explicit)
  2. ``ACTENON_SIGNING_KEY`` env var
  3. ``~/.actenon-permit/dev-signing-key`` (auto-generated on first use)
  4. Ephemeral in-memory key (with a warning — last resort)
"""

from __future__ import annotations

from .async_client import AsyncActenonClient
from .client import Actenon, ActenonClient, CloudActenonClient, LocalActenonClient
from .config import (
    CapabilityInfo,
    CloudTransportConfig,
    LocalRuntimeConfig,
    ResourceClientConfig,
)
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
    "ActenonClient",
    "ActenonError",
    "AsyncActenonClient",
    "BrokeredResult",
    "CapabilityInfo",
    "CloudActenonClient",
    "CloudTransportConfig",
    "ExecutionFailedError",
    "ExecutionRefusedError",
    "ExecutionResult",
    "IntentCreateRequest",
    "IntentHandle",
    "IntentNotFoundError",
    "LocalActenonClient",
    "LocalRuntimeConfig",
    "OutcomeUnknownError",
    "ProofMissingError",
    "ProviderError",
    "ResourceClientConfig",
    "ResourceOwnedResult",
    "RetryableError",
    "compute_receipt_signature",
    "verify_resource_receipt",
    "with_retry",
]

__version__ = "1.4.0"
