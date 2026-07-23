"""Typed request and result models for the Actenon SDK.

The result models are discriminated: ``ExecutionResult`` is a union of
``BrokeredResult`` and ``ResourceOwnedResult``. The two are NOT
interchangeable — callers MUST branch on ``isinstance`` or on the
``mode`` field before reading mode-specific attributes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class IntentCreateRequest:
    """Typed request for creating an AuthorisedExecutionIntent.

    Attributes:
        action: The action type (e.g. ``"github.issue.create"``).
        target: The target resource (e.g. ``"Actenon/example"`` or
            ``"github"``).
        parameters: The action parameters (e.g. ``{"title": "..."}``).
        requested_execution_mode: ``"brokered"`` (default) or
            ``"resource_owned"``.
        idempotency_key: Optional operation identity for dedup. If
            not provided, a random key is generated.
        expiry_seconds: Intent expiry in seconds (default 3600).
        metadata: Optional metadata (strict limits apply — no secrets).
    """

    action: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    requested_execution_mode: Literal["brokered", "resource_owned"] = "brokered"
    idempotency_key: str | None = None
    expiry_seconds: int = 3600
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IntentHandle:
    """A handle to a created intent.

    The handle carries the intent_id and a reference to the client
    that created it, so ``.execute()`` can be called directly.

    Attributes:
        intent_id: The unique intent identifier.
        lifecycle_state: The current lifecycle state (e.g. ``"created"``).
        client: The Actenon client (for executing the intent).
    """

    intent_id: str
    lifecycle_state: str
    # client is not frozen — it's a reference to the ActenonClient.
    # We use a default field to avoid the frozen-dataclass constraint.
    _client: Any = field(default=None, repr=False, compare=False)

    def execute(self) -> ExecutionResult:
        """Execute this intent. Returns a discriminated ExecutionResult."""
        if self._client is None:
            raise RuntimeError("IntentHandle has no client reference")
        return self._client._execute_intent(self.intent_id)

    def submit_to_resource(self, proof: dict[str, Any]) -> ExecutionResult:
        """Submit this intent to a resource boundary (resource-owned mode).

        Requires a proof dict from the authority broker.
        """
        if self._client is None:
            raise RuntimeError("IntentHandle has no client reference")
        return self._client._submit_intent(self.intent_id, proof)


# ---------------------------------------------------------------------------
# Discriminated result models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BrokeredResult:
    """Result of a brokered execution.

    Hard invariants (enforced by the Protocol layer):
      * ``state == "succeeded"`` implies ``provider_execution_observed == True``.
      * ``finality`` is derived from ``state``.

    Attributes:
        intent_id: The intent that was executed.
        state: One of ``succeeded``, ``failed``, ``refused``, ``outcome_unknown``.
        finality: ``"final"`` or ``"non_final"``.
        provider_execution_observed: Whether the broker observed the
            provider's response.
        receipt_received: Whether a receipt was issued.
        receipt_verified: Whether the receipt was cryptographically verified.
        evidence: Redacted provider evidence (safe to log/persist).
        attempt_id: The execution attempt id.
    """

    intent_id: str
    state: Literal["succeeded", "failed", "refused", "outcome_unknown"]
    finality: Literal["final", "non_final"]
    provider_execution_observed: bool
    receipt_received: bool
    receipt_verified: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    attempt_id: str | None = None

    @property
    def mode(self) -> Literal["brokered"]:
        return "brokered"

    @property
    def succeeded(self) -> bool:
        """True iff state == 'succeeded'."""
        return self.state == "succeeded"

    @property
    def is_final(self) -> bool:
        """True iff finality == 'final'."""
        return self.finality == "final"


@dataclass(frozen=True)
class ResourceOwnedResult:
    """Result of a resource-owned execution.

    Hard invariants (enforced by the Protocol layer):
      * ``state == "succeeded"`` implies ``resource_receipt_verified == True``.
      * ``state == "submitted"`` implies ``provider_execution_observed == False``
        and ``resource_receipt_received == False``.

    Attributes:
        intent_id: The intent that was submitted.
        state: One of ``submitted``, ``accepted``, ``refused``,
            ``succeeded``, ``failed``, ``outcome_unknown``.
        finality: ``"final"`` or ``"non_final"``.
        provider_execution_observed: Whether the resource reported an
            execution outcome.
        resource_receipt_received: Whether the resource returned a receipt.
        resource_receipt_verified: Whether the receipt's signature verified.
        submission_reference: Correlation id for polling.
        evidence: Redacted resource receipt (signature stripped).
        attempt_id: The execution attempt id.
    """

    intent_id: str
    state: Literal["submitted", "accepted", "refused", "succeeded", "failed", "outcome_unknown"]
    finality: Literal["final", "non_final"]
    provider_execution_observed: bool
    resource_receipt_received: bool
    resource_receipt_verified: bool
    submission_reference: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    attempt_id: str | None = None

    @property
    def mode(self) -> Literal["resource_owned"]:
        return "resource_owned"

    @property
    def succeeded(self) -> bool:
        """True iff state == 'succeeded'."""
        return self.state == "succeeded"

    @property
    def is_final(self) -> bool:
        """True iff finality == 'final'."""
        return self.finality == "final"


# Discriminated union
ExecutionResult = BrokeredResult | ResourceOwnedResult


__all__ = [
    "BrokeredResult",
    "ExecutionResult",
    "IntentCreateRequest",
    "IntentHandle",
    "ResourceOwnedResult",
]
