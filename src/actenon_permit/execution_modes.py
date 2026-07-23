"""Permit-side execution-mode coordinators (Prompt 9).

Permit is the authority broker. It produces the proof, then either:

  * (brokered mode) drives the adapter via ``Broker.execute_via_adapter``
    and produces a ``BrokeredExecutionResult``; or
  * (resource_owned mode) submits the request + proof to an
    independently-operated resource boundary and produces a
    ``ResourceOwnedExecutionResult`` based on what the resource
    returns.

This module is the Permit layer of the Prompt-9 formalisation. It
depends on:

  * ``actenon_protocol.execution_results`` for the discriminated
    result model.
  * ``actenon.execution.mode_aware`` for the Kernel-side
    ``ModeAwareExecutionResult`` wrapper, ``ResourceReceiptVerifier``,
    and per-mode state machines.
  * ``actenon_permit.broker.Broker`` for the brokered execution path
    (Prompt 8).

The coordinators are intentionally small. They wire the existing
Broker + adapter contract into the new result model. They do NOT
re-implement broker semantics; they translate.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from actenon.execution.mode_aware import (
    ModeAwareExecutionResult,
    ResourceReceiptVerifier,
    build_brokered_result,
    build_resource_owned_result,
)
from actenon_protocol.execution_results import (
    BrokeredExecutionState,
    ResourceOwnedExecutionState,
)

from .broker import Broker, BrokerExecutionError
from .model import Action, Decision, DecisionOutcome, Grant

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ExecutionCoordinatorError(RuntimeError):
    """Raised when a coordinator cannot produce a result. The message is
    safe to surface to the caller; it MUST NOT contain a credential."""


# ---------------------------------------------------------------------------
# Brokered coordinator
# ---------------------------------------------------------------------------


@dataclass
class BrokeredExecutionCoordinator:
    """Coordinates a brokered execution and produces a ModeAwareExecutionResult.

    Wraps the existing ``Broker.execute_via_adapter`` (Prompt 8) and
    translates its outcome into the Prompt-9 ``BrokeredExecutionResult``
    shape. The coordinator is the single place that decides which
    brokered state applies:

      * ``succeeded`` — adapter returned a successful ProviderResponse
        AND ``provider_execution_observed=True``.
      * ``failed`` — adapter raised an AdapterError that maps to a
        provider failure (the call was attempted but failed).
      * ``refused`` — broker refused before any provider call (proof
        invalid, action not supported, parameter validation failed,
        credential resolution failed, dev-credential in production).
      * ``outcome_unknown`` — adapter raised a timeout, partial
        response, or returned an unreconciled response.

    The hard rule (``succeeded`` requires ``provider_execution_observed``)
    is enforced at the Protocol dataclass layer; this coordinator
    supplies the inputs.
    """

    broker: Broker
    verifier_identity: str = "actenon-permit-broker"

    def coordinate(
        self,
        grant: Grant,
        action: Action,
        decision: Decision,
        adapter: Any,
        *,
        credential_ref: str,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
        pccb_id: str | None = None,
        action_hash: str | None = None,
    ) -> ModeAwareExecutionResult:
        """Run a brokered execution and return a ModeAwareExecutionResult.

        ``decision.outcome`` MUST be ALLOW; the caller is expected to
        have run the PDP already.
        """
        if decision.outcome != DecisionOutcome.ALLOW:
            # The caller should not have reached the coordinator. Treat
            # as a broker-side refusal.
            return self._refused(
                action,
                reason=f"coordinator called without ALLOW (was {decision.outcome.value})",
                pccb_id=pccb_id,
                action_hash=action_hash,
            )

        attempt_id = f"exec_{uuid4().hex[:16]}"
        occurred_at = datetime.now(UTC).isoformat()

        try:
            response, actual_cost = self.broker.execute_via_adapter(
                grant,
                action,
                decision,
                adapter,
                credential_ref=credential_ref,
                idempotency_key=idempotency_key,
                timeout_seconds=timeout_seconds,
            )
        except BrokerExecutionError as e:
            # The broker refused or the adapter failed. Map to a state.
            state = self._map_broker_error_to_state(e)
            if state == BrokeredExecutionState.REFUSED:
                return self._refused(
                    action,
                    reason=str(e),
                    pccb_id=pccb_id,
                    action_hash=action_hash,
                    attempt_id=attempt_id,
                    occurred_at=occurred_at,
                )
            if state == BrokeredExecutionState.OUTCOME_UNKNOWN:
                return self._outcome_unknown(
                    action,
                    reason=str(e),
                    pccb_id=pccb_id,
                    action_hash=action_hash,
                    attempt_id=attempt_id,
                    occurred_at=occurred_at,
                )
            # state == FAILED
            return self._failed(
                action,
                reason=str(e),
                pccb_id=pccb_id,
                action_hash=action_hash,
                attempt_id=attempt_id,
                occurred_at=occurred_at,
            )

        # Success path. provider_execution_observed is True because the
        # adapter returned a ProviderResponse (which means it observed
        # the provider's response). The Protocol dataclass will reject
        # succeeded-without-observation if we lie here.
        # Reconciliation status from the adapter:
        reconcile = response.provider_evidence.get("reconcile_status")
        reconciliation_status: str | None = None
        if reconcile and not str(reconcile).startswith("ok"):
            # Adapter reported an unreconciled state — keep the call as
            # succeeded (the side effect may have landed) but record
            # the reconcile_status for the receipt.
            reconciliation_status = str(reconcile)
        return build_brokered_result(
            state=BrokeredExecutionState.SUCCEEDED,
            verified_by=self.verifier_identity,
            executed_by=self.verifier_identity,
            attempt_id=attempt_id,
            occurred_at=occurred_at,
            provider_execution_observed=True,
            receipt_received=True,
            receipt_verified=True,  # the broker signs its own receipts
            provider_evidence=dict(response.provider_evidence),
            reconciliation_status=reconciliation_status,
            pccb_id=pccb_id,
            action_hash=action_hash,
            kernel_verifier_identity=self.verifier_identity,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_broker_error_to_state(e: BrokerExecutionError) -> BrokeredExecutionState:
        """Map a BrokerExecutionError.rule to a brokered state.

        Refused (no provider call attempted):
          - broker:action_not_supported
          - broker:invalid_parameters
          - broker:unsupported_action
          - broker:credential_resolution_failed
          - broker:dev_credential_in_production

        Outcome unknown (provider call attempted, outcome unclear):
          - broker:adapter_crash (unexpected exception - we don't know
            whether the provider call landed)
          - adapter timeouts (rule starts with 'adapter:')
            that are retryable

        Failed (provider call attempted, observed failure):
          - adapter:github HTTP 4xx/5xx that are not retryable
            (the provider returned an explicit failure)
        """
        rule = e.rule
        refused_rules = {
            "broker:action_not_supported",
            "broker:invalid_parameters",
            "broker:unsupported_action",
            "broker:credential_resolution_failed",
            "broker:dev_credential_in_production",
        }
        if rule in refused_rules:
            return BrokeredExecutionState.REFUSED
        # Adapter errors that are retryable (timeout, partial, network)
        # are outcome_unknown. Non-retryable adapter errors (HTTP 4xx
        # that aren't 408/429) are failed.
        if e.retryable:
            return BrokeredExecutionState.OUTCOME_UNKNOWN
        if rule == "broker:adapter_crash":
            # Unexpected crash; we don't know if the provider call
            # landed. Safe default: outcome_unknown.
            return BrokeredExecutionState.OUTCOME_UNKNOWN
        return BrokeredExecutionState.FAILED

    def _refused(
        self,
        action: Action,
        *,
        reason: str,
        pccb_id: str | None,
        action_hash: str | None,
        attempt_id: str | None = None,
        occurred_at: str | None = None,
    ) -> ModeAwareExecutionResult:
        return build_brokered_result(
            state=BrokeredExecutionState.REFUSED,
            verified_by=self.verifier_identity,
            executed_by=self.verifier_identity,
            attempt_id=attempt_id or f"exec_{uuid4().hex[:16]}",
            occurred_at=occurred_at or datetime.now(UTC).isoformat(),
            provider_execution_observed=False,  # refused = no provider call
            receipt_received=True,
            receipt_verified=True,
            provider_evidence={"reason": reason, "action_type": action.type},
            pccb_id=pccb_id,
            action_hash=action_hash,
            kernel_verifier_identity=self.verifier_identity,
        )

    def _failed(
        self,
        action: Action,
        *,
        reason: str,
        pccb_id: str | None,
        action_hash: str | None,
        attempt_id: str,
        occurred_at: str,
    ) -> ModeAwareExecutionResult:
        return build_brokered_result(
            state=BrokeredExecutionState.FAILED,
            verified_by=self.verifier_identity,
            executed_by=self.verifier_identity,
            attempt_id=attempt_id,
            occurred_at=occurred_at,
            provider_execution_observed=True,  # failed = provider returned a failure
            receipt_received=True,
            receipt_verified=True,
            provider_evidence={"reason": reason, "action_type": action.type},
            pccb_id=pccb_id,
            action_hash=action_hash,
            kernel_verifier_identity=self.verifier_identity,
        )

    def _outcome_unknown(
        self,
        action: Action,
        *,
        reason: str,
        pccb_id: str | None,
        action_hash: str | None,
        attempt_id: str,
        occurred_at: str,
    ) -> ModeAwareExecutionResult:
        return build_brokered_result(
            state=BrokeredExecutionState.OUTCOME_UNKNOWN,
            verified_by=self.verifier_identity,
            executed_by=self.verifier_identity,
            attempt_id=attempt_id,
            occurred_at=occurred_at,
            provider_execution_observed=False,  # outcome unknown = not observed
            receipt_received=False,
            receipt_verified=False,
            provider_evidence={"reason": reason, "action_type": action.type},
            reconciliation_status="pending",
            pccb_id=pccb_id,
            action_hash=action_hash,
            kernel_verifier_identity=self.verifier_identity,
        )


# ---------------------------------------------------------------------------
# Resource-owned coordinator
# ---------------------------------------------------------------------------


@dataclass
class ResourceOwnedSubmissionClient:
    """Submits a request + proof to a resource boundary and produces a
    ResourceOwnedExecutionResult.

    The resource boundary is independently operated. It receives the
    request + proof, verifies the proof using its own Kernel
    deployment, and either:
      * accepts the request and returns a submission_reference (state
        ``accepted``);
      * completes synchronously and returns a signed resource receipt
        (state ``succeeded`` if the receipt verifies);
      * refuses (state ``refused``);
      * times out / returns no usable response (state ``submitted`` if
        the submission itself timed out, or ``outcome_unknown`` if
        the resource returned an unparseable response).

    Hard rules enforced (via the Protocol dataclass):
      * ``succeeded`` requires ``resource_receipt_received=True`` AND
        ``resource_receipt_verified=True``. A forged or missing
        receipt cannot elevate the state.
      * ``submitted`` requires ``provider_execution_observed=False``
        and ``resource_receipt_received=False``. Submission is not
        execution.
    """

    resource_endpoint: str
    resource_id: str
    receipt_verifier: ResourceReceiptVerifier
    verifier_identity: str = "actenon-permit-broker"
    timeout_seconds: float = 30.0

    def submit(
        self,
        action: Action,
        proof: dict[str, Any],
        *,
        pccb_id: str | None = None,
        action_hash: str | None = None,
    ) -> ModeAwareExecutionResult:
        """POST the request + proof to the resource boundary."""
        attempt_id = f"exec_{uuid4().hex[:16]}"
        occurred_at = datetime.now(UTC).isoformat()
        payload = {
            "attempt_id": attempt_id,
            "action": {"type": action.type, "target": action.target, "params": action.params},
            "proof": proof,
        }
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.resource_endpoint,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "actenon-permit-broker",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # Resource returned an HTTP error. 4xx = refused; 5xx =
            # outcome_unknown (resource may or may not have executed).
            state = (
                ResourceOwnedExecutionState.REFUSED
                if 400 <= e.code < 500
                else ResourceOwnedExecutionState.OUTCOME_UNKNOWN
            )
            return self._build_non_success(
                state=state,
                action=action,
                attempt_id=attempt_id,
                occurred_at=occurred_at,
                reason=f"resource returned HTTP {e.code}",
                pccb_id=pccb_id,
                action_hash=action_hash,
            )
        except TimeoutError:
            # Submission itself timed out — we don't know if the
            # resource received the request. State is outcome_unknown.
            return self._build_non_success(
                state=ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
                action=action,
                attempt_id=attempt_id,
                occurred_at=occurred_at,
                reason="submission timed out",
                pccb_id=pccb_id,
                action_hash=action_hash,
            )
        except Exception as e:
            # Network failure, DNS, etc. — outcome_unknown.
            return self._build_non_success(
                state=ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
                action=action,
                attempt_id=attempt_id,
                occurred_at=occurred_at,
                reason=f"submission error: {type(e).__name__}",
                pccb_id=pccb_id,
                action_hash=action_hash,
            )

        # Resource returned 2xx. Inspect the response.
        # Three shapes:
        #   1. {"status": "accepted", "submission_reference": "sub_..."}
        #      -> state=accepted, no receipt yet.
        #   2. {"status": "succeeded", "receipt": {...}}
        #      -> state=succeeded IF receipt verifies.
        #   3. {"status": "refused", "reason": "..."}
        #      -> state=refused.
        status_str = str(resp_body.get("status", "")).lower()
        if status_str == "accepted":
            return build_resource_owned_result(
                state=ResourceOwnedExecutionState.ACCEPTED,
                verified_by=self.verifier_identity,
                executed_by=self.resource_id,
                attempt_id=attempt_id,
                occurred_at=occurred_at,
                submission_reference=resp_body.get("submission_reference"),
                pccb_id=pccb_id,
                action_hash=action_hash,
                kernel_verifier_identity=self.verifier_identity,
            )
        if status_str == "succeeded":
            receipt = resp_body.get("receipt")
            if not isinstance(receipt, dict):
                # Resource claimed success but provided no receipt.
                # Cannot verify -> outcome_unknown.
                return self._build_non_success(
                    state=ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
                    action=action,
                    attempt_id=attempt_id,
                    occurred_at=occurred_at,
                    reason="resource claimed success but provided no receipt",
                    pccb_id=pccb_id,
                    action_hash=action_hash,
                )
            try:
                return build_resource_owned_result(
                    state=ResourceOwnedExecutionState.SUCCEEDED,
                    verified_by=self.verifier_identity,
                    executed_by=self.resource_id,
                    attempt_id=attempt_id,
                    occurred_at=occurred_at,
                    provider_execution_observed=True,
                    resource_receipt_received=True,
                    resource_receipt=receipt,
                    resource_receipt_verifier=self.receipt_verifier,
                    submission_reference=resp_body.get("submission_reference"),
                    pccb_id=pccb_id,
                    action_hash=action_hash,
                    kernel_verifier_identity=self.verifier_identity,
                )
            except Exception:
                # build_resource_owned_result raised because the receipt
                # did not verify and we requested SUCCEEDED. Fall back
                # to outcome_unknown — the forged receipt cannot
                # elevate the state.
                return self._build_non_success(
                    state=ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
                    action=action,
                    attempt_id=attempt_id,
                    occurred_at=occurred_at,
                    reason="resource receipt failed cryptographic verification",
                    pccb_id=pccb_id,
                    action_hash=action_hash,
                )
        if status_str == "refused":
            return self._build_non_success(
                state=ResourceOwnedExecutionState.REFUSED,
                action=action,
                attempt_id=attempt_id,
                occurred_at=occurred_at,
                reason=str(resp_body.get("reason", "resource refused")),
                pccb_id=pccb_id,
                action_hash=action_hash,
            )
        # Unknown status string — outcome_unknown.
        return self._build_non_success(
            state=ResourceOwnedExecutionState.OUTCOME_UNKNOWN,
            action=action,
            attempt_id=attempt_id,
            occurred_at=occurred_at,
            reason=f"resource returned unknown status: {status_str!r}",
            pccb_id=pccb_id,
            action_hash=action_hash,
        )

    def _build_non_success(
        self,
        *,
        state: ResourceOwnedExecutionState,
        action: Action,
        attempt_id: str,
        occurred_at: str,
        reason: str,
        pccb_id: str | None,
        action_hash: str | None,
    ) -> ModeAwareExecutionResult:
        return build_resource_owned_result(
            state=state,
            verified_by=self.verifier_identity,
            executed_by=self.resource_id,
            attempt_id=attempt_id,
            occurred_at=occurred_at,
            submission_reference=None,
            pccb_id=pccb_id,
            action_hash=action_hash,
            kernel_verifier_identity=self.verifier_identity,
        )


__all__ = [
    "BrokeredExecutionCoordinator",
    "ExecutionCoordinatorError",
    "ResourceOwnedSubmissionClient",
]
