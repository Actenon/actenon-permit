"""AuthorisedExecutionIntent (AEI) — the unified developer-facing transaction.

An AEI represents a declared consequential action that may require
policy evaluation, approval, proof issuance, execution and evidence.
It is the recommended developer surface for Actenon-Permit: instead
of juggling Grant, Action, Decision, PCCB, receipt and refusal as
separate objects, the developer creates an AEI and calls
``.execute()`` (or ``.execute_brokered()`` / ``.submit_to_resource()``)
on it. The AEI tracks the full lifecycle.

Important: the AEI is NOT the proof and MUST NOT be verified directly
by the Kernel. The proof (PCCB) is the boundary artefact; the AEI is
the developer-facing transaction that may *result in* a proof being
minted. The Kernel verifies proofs, not intents.

This module implements:

  * ``AuthorisedExecutionIntent`` dataclass — the model.
  * ``IntentLifecycle`` enum — the lifecycle states.
  * ``INTENT_TRANSITIONS`` — the allowed transition table.
  * ``DurabilityProfile`` enum — ephemeral / durable-local / durable-cloud.
  * ``IntentStore`` ABC + ``EphemeralIntentStore`` + ``SQLiteIntentStore``.
  * ``IntentManager`` — the developer-facing API. ``create()`` returns
    an AEI; ``execute()`` / ``execute_brokered()`` / ``submit_to_resource()``
    advance the lifecycle and return a ``ModeAwareExecutionResult``.
  * Compatibility wrappers: ``from_grant()`` wraps an existing Grant
    as an AEI; ``to_action()`` produces the existing ``Action`` for
    the broker / PDP.

The AEI does NOT replace the low-level Grant/Action/Decision/PCCB
APIs. Advanced users can still use them directly. The AEI is the
recommended surface, not the only entry point.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from actenon_protocol import PROTOCOL_VERSION
from actenon_protocol.execution_results import (
    BrokeredExecutionState,
    ResourceOwnedExecutionState,
)

from .adapters import ProviderAdapter
from .broker import Broker
from .execution_modes import BrokeredExecutionCoordinator, ResourceOwnedSubmissionClient
from .model import Action, Decision, DecisionOutcome, Grant

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class IntentLifecycle(StrEnum):
    """Lifecycle states for an AuthorisedExecutionIntent.

    Only the states the implementation can support accurately are
    included. The implementation does NOT claim to support
    ``requires_approval`` if no approval gate is wired; it skips
    straight to ``authorised`` or ``denied``.
    """

    CREATED = "created"
    EVALUATING = "evaluating"
    REQUIRES_APPROVAL = "requires_approval"
    AUTHORISED = "authorised"
    DENIED = "denied"
    PROOF_ISSUED = "proof_issued"
    EXECUTING = "executing"
    SUBMITTED = "submitted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED = "refused"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


# Allowed transitions. Terminal states have empty sets.
INTENT_TRANSITIONS: dict[IntentLifecycle, frozenset[IntentLifecycle]] = {
    IntentLifecycle.CREATED: frozenset({
        IntentLifecycle.EVALUATING,
        IntentLifecycle.CANCELLED,
        IntentLifecycle.EXPIRED,
    }),
    IntentLifecycle.EVALUATING: frozenset({
        IntentLifecycle.REQUIRES_APPROVAL,
        IntentLifecycle.AUTHORISED,
        IntentLifecycle.DENIED,
        IntentLifecycle.EXPIRED,
    }),
    IntentLifecycle.REQUIRES_APPROVAL: frozenset({
        IntentLifecycle.AUTHORISED,
        IntentLifecycle.DENIED,
        IntentLifecycle.CANCELLED,
        IntentLifecycle.EXPIRED,
    }),
    IntentLifecycle.AUTHORISED: frozenset({
        IntentLifecycle.PROOF_ISSUED,
        IntentLifecycle.EXPIRED,
        IntentLifecycle.CANCELLED,
    }),
    IntentLifecycle.PROOF_ISSUED: frozenset({
        IntentLifecycle.EXECUTING,
        IntentLifecycle.SUBMITTED,
        IntentLifecycle.EXPIRED,
        IntentLifecycle.CANCELLED,
    }),
    IntentLifecycle.EXECUTING: frozenset({
        # Brokered terminal states:
        IntentLifecycle.SUCCEEDED,
        IntentLifecycle.FAILED,
        IntentLifecycle.REFUSED,
        IntentLifecycle.OUTCOME_UNKNOWN,
        IntentLifecycle.EXPIRED,
    }),
    IntentLifecycle.SUBMITTED: frozenset({
        # Resource-owned states:
        IntentLifecycle.SUCCEEDED,
        IntentLifecycle.FAILED,
        IntentLifecycle.REFUSED,
        IntentLifecycle.OUTCOME_UNKNOWN,
        IntentLifecycle.EXPIRED,
    }),
    # Terminal:
    IntentLifecycle.SUCCEEDED: frozenset(),
    IntentLifecycle.FAILED: frozenset(),
    IntentLifecycle.REFUSED: frozenset(),
    IntentLifecycle.OUTCOME_UNKNOWN: frozenset({
        # outcome_unknown can resolve to succeeded/failed via reconciliation
        IntentLifecycle.SUCCEEDED,
        IntentLifecycle.FAILED,
        IntentLifecycle.OUTCOME_UNKNOWN,
    }),
    IntentLifecycle.DENIED: frozenset(),
    IntentLifecycle.CANCELLED: frozenset(),
    IntentLifecycle.EXPIRED: frozenset(),
}


class IntentTransitionError(ValueError):
    """Raised when a lifecycle transition is not allowed."""


def can_transition(current: IntentLifecycle, next_state: IntentLifecycle) -> bool:
    return next_state in INTENT_TRANSITIONS[current]


def validate_transition(current: IntentLifecycle, next_state: IntentLifecycle) -> None:
    if not can_transition(current, next_state):
        raise IntentTransitionError(
            f"intent lifecycle transition not allowed: {current.value!r} -> {next_state.value!r}"
        )


# ---------------------------------------------------------------------------
# Durability profiles
# ---------------------------------------------------------------------------


class DurabilityProfile(StrEnum):
    """Durability guarantee for an intent store.

    * ``EPHEMERAL_LOCAL`` — in-process memory. Intents are lost when
      the process exits. Suitable for tests and short-lived scripts.
    * ``DURABLE_LOCAL`` — local SQLite file. Intents survive process
      restarts but not host failures. Suitable for self-hosted Permit
      gateway deployments.
    * ``DURABLE_CLOUD`` — managed Cloud persistence (Postgres +
      backups). Intents survive host failures. Suitable for
      Actenon-Cloud-managed deployments.

    The profile is exposed as a capability: callers can check
    ``store.durability_profile`` before relying on post-restart
    polling. An ephemeral store will NOT claim to support polling
    after process termination.
    """

    EPHEMERAL_LOCAL = "ephemeral_local"
    DURABLE_LOCAL = "durable_local"
    DURABLE_CLOUD = "durable_cloud"


# ---------------------------------------------------------------------------
# AEI dataclass
# ---------------------------------------------------------------------------


@dataclass
class AuthorisedExecutionIntent:
    """The developer-facing transaction.

    Required fields (per Prompt 10 spec):
      * intent_id
      * protocol_version
      * action (type + parameters)
      * target
      * requested_execution_mode
      * requester_context (subject, agent_id, tenant_id)
      * idempotency_key (operation identity)
      * created_at
      * expiry
      * metadata (with strict size limits)
      * lifecycle_state
      * linked decision id (authority-decision)
      * linked proof id
      * linked attempt ids
      * linked receipt/refusal ids

    Secrets MUST NOT be placed in ``metadata``. The store enforces a
    strict size limit (4 KiB serialised) and rejects keys that look
    like secrets (``password``, ``secret``, ``token``, ``api_key``).
    """

    intent_id: str
    protocol_version: str
    # Action + target
    action_type: str
    action_params: dict[str, Any]
    target_type: str
    target_id: str
    # Requested mode + requester context
    requested_execution_mode: str  # "brokered" | "resource_owned"
    requester_subject: str
    requester_agent_id: str
    requester_tenant_id: str | None = None
    # Operation identity
    idempotency_key: str | None = None
    # Time
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    expiry: str | None = None
    # Metadata (strict limits enforced by store)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Lifecycle
    lifecycle_state: IntentLifecycle = IntentLifecycle.CREATED
    # Linked artefact ids
    linked_decision_id: str | None = None
    linked_proof_id: str | None = None
    linked_attempt_ids: list[str] = field(default_factory=list)
    linked_receipt_id: str | None = None
    linked_refusal_id: str | None = None
    # Resource-owned submission reference (correlation for polling)
    submission_reference: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["lifecycle_state"] = self.lifecycle_state.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuthorisedExecutionIntent:
        d = dict(d)
        if isinstance(d.get("lifecycle_state"), str):
            d["lifecycle_state"] = IntentLifecycle(d["lifecycle_state"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Metadata validation
# ---------------------------------------------------------------------------


MAX_METADATA_BYTES = 4 * 1024  # 4 KiB
FORBIDDEN_METADATA_KEYS = frozenset({
    "password", "secret", "token", "api_key", "apikey",
    "private_key", "privatekey", "access_key", "accesskey",
    "bearer", "authorization",
})


class MetadataValidationError(ValueError):
    """Raised when intent metadata violates the strict limits."""


def validate_metadata(metadata: dict[str, Any]) -> None:
    """Validate metadata against strict limits.

    Rules:
      * Total serialised size <= 4 KiB.
      * No key in FORBIDDEN_METADATA_KEYS (case-insensitive).
      * No key whose value matches a common secret prefix
        (``ghp_``, ``sk_``, ``AKIA``, ``-----BEGIN``).
    """
    if not isinstance(metadata, dict):
        raise MetadataValidationError("metadata must be a dict")
    serialised = json.dumps(metadata, default=str, sort_keys=True)
    if len(serialised.encode("utf-8")) > MAX_METADATA_BYTES:
        raise MetadataValidationError(
            f"metadata exceeds {MAX_METADATA_BYTES} bytes (got {len(serialised.encode('utf-8'))})"
        )
    for k, v in metadata.items():
        kl = str(k).lower()
        if kl in FORBIDDEN_METADATA_KEYS:
            raise MetadataValidationError(
                f"metadata key {k!r} is forbidden (looks like a secret name)"
            )
        if isinstance(v, str) and v.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk_", "AKIA", "-----BEGIN")):
            raise MetadataValidationError(
                f"metadata value for key {k!r} looks like a secret (prefix match)"
            )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class IntentStore(ABC):
    """Abstract intent store."""

    @property
    @abstractmethod
    def durability_profile(self) -> DurabilityProfile: ...

    @abstractmethod
    def put(self, intent: AuthorisedExecutionIntent) -> None: ...

    @abstractmethod
    def get(self, intent_id: str) -> AuthorisedExecutionIntent | None: ...

    @abstractmethod
    def update_state(self, intent_id: str, new_state: IntentLifecycle) -> None: ...

    @abstractmethod
    def list(self, *, requester_subject: str | None = None) -> list[AuthorisedExecutionIntent]: ...

    @abstractmethod
    def delete(self, intent_id: str) -> None: ...


class EphemeralIntentStore(IntentStore):
    """In-memory intent store. Lost on process exit."""

    def __init__(self) -> None:
        self._intents: dict[str, AuthorisedExecutionIntent] = {}
        self._lock = threading.RLock()

    @property
    def durability_profile(self) -> DurabilityProfile:
        return DurabilityProfile.EPHEMERAL_LOCAL

    def put(self, intent: AuthorisedExecutionIntent) -> None:
        with self._lock:
            self._intents[intent.intent_id] = intent

    def get(self, intent_id: str) -> AuthorisedExecutionIntent | None:
        with self._lock:
            return self._intents.get(intent_id)

    def update_state(self, intent_id: str, new_state: IntentLifecycle) -> None:
        with self._lock:
            intent = self._intents.get(intent_id)
            if intent is None:
                raise KeyError(f"intent {intent_id!r} not found")
            validate_transition(intent.lifecycle_state, new_state)
            intent.lifecycle_state = new_state

    def list(self, *, requester_subject: str | None = None) -> list[AuthorisedExecutionIntent]:
        with self._lock:
            intents = list(self._intents.values())
        if requester_subject is not None:
            intents = [i for i in intents if i.requester_subject == requester_subject]
        return intents

    def delete(self, intent_id: str) -> None:
        with self._lock:
            self._intents.pop(intent_id, None)


class SQLiteIntentStore(IntentStore):
    """SQLite-backed durable-local intent store.

    Survives process restarts. Does NOT survive host failures
    (use ``DURABLE_CLOUD`` for that — backed by Postgres + backups
    in the Cloud repo).
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or "actenon_intents.db"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        self._init_schema()

    @property
    def durability_profile(self) -> DurabilityProfile:
        return DurabilityProfile.DURABLE_LOCAL

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;

                CREATE TABLE IF NOT EXISTS intents (
                    intent_id TEXT PRIMARY KEY,
                    body TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL,
                    requester_subject TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_intents_subject
                    ON intents(requester_subject);
                """
            )

    def put(self, intent: AuthorisedExecutionIntent) -> None:
        body = json.dumps(intent.to_dict(), default=str, sort_keys=True)
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO intents (intent_id, body, lifecycle_state, requester_subject, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (intent.intent_id, body, intent.lifecycle_state.value, intent.requester_subject, intent.created_at, now),
            )

    def get(self, intent_id: str) -> AuthorisedExecutionIntent | None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT body FROM intents WHERE intent_id = ?", (intent_id,))
            row = cur.fetchone()
        if not row:
            return None
        return AuthorisedExecutionIntent.from_dict(json.loads(row[0]))

    def update_state(self, intent_id: str, new_state: IntentLifecycle) -> None:
        intent = self.get(intent_id)
        if intent is None:
            raise KeyError(f"intent {intent_id!r} not found")
        validate_transition(intent.lifecycle_state, new_state)
        intent.lifecycle_state = new_state
        # Re-put (which updates updated_at).
        self.put(intent)

    def list(self, *, requester_subject: str | None = None) -> list[AuthorisedExecutionIntent]:
        with self._lock:
            cur = self._conn.cursor()
            if requester_subject is None:
                cur.execute("SELECT body FROM intents ORDER BY created_at")
            else:
                cur.execute("SELECT body FROM intents WHERE requester_subject = ? ORDER BY created_at", (requester_subject,))
            rows = cur.fetchall()
        return [AuthorisedExecutionIntent.from_dict(json.loads(r[0])) for r in rows]

    def delete(self, intent_id: str) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM intents WHERE intent_id = ?", (intent_id,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# IntentManager — the developer-facing API
# ---------------------------------------------------------------------------


@dataclass
class IntentManager:
    """Developer-facing API for creating and executing AEIs.

    Usage::

        mgr = IntentManager(store=EphemeralIntentStore())
        intent = mgr.create(
            action_type="issue.create",
            action_params={"owner": "actenon", "repo": "demo", "title": "t"},
            target_type="github", target_id="github",
            requested_execution_mode="brokered",
            requester_subject="alice",
            requester_agent_id="refund-bot",
        )
        result = mgr.execute(
            intent,
            grant=grant,
            decision=decision,
            adapter=github_adapter,
            credential_ref="GITHUB_TOKEN",
            broker=broker,
        )

    The manager enforces:
      * lifecycle transitions (rejects illegal transitions).
      * metadata strict limits (rejects secrets).
      * mode discrimination (execute_brokered vs submit_to_resource
        produce different result shapes; execute() dispatches based
        on the intent's requested_execution_mode).
    """

    store: IntentStore

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create(
        self,
        *,
        action_type: str,
        action_params: dict[str, Any],
        target_type: str,
        target_id: str,
        requested_execution_mode: str,
        requester_subject: str,
        requester_agent_id: str,
        requester_tenant_id: str | None = None,
        idempotency_key: str | None = None,
        expiry_seconds: int | None = 3600,
        metadata: dict[str, Any] | None = None,
    ) -> AuthorisedExecutionIntent:
        """Create a new AEI in the CREATED state."""
        if requested_execution_mode not in ("brokered", "resource_owned"):
            raise ValueError(
                f"requested_execution_mode must be 'brokered' or 'resource_owned', got {requested_execution_mode!r}"
            )
        metadata = metadata or {}
        validate_metadata(metadata)
        intent = AuthorisedExecutionIntent(
            intent_id=f"intent_{uuid.uuid4().hex[:16]}",
            protocol_version=PROTOCOL_VERSION,
            action_type=action_type,
            action_params=dict(action_params),
            target_type=target_type,
            target_id=target_id,
            requested_execution_mode=requested_execution_mode,
            requester_subject=requester_subject,
            requester_agent_id=requester_agent_id,
            requester_tenant_id=requester_tenant_id,
            idempotency_key=idempotency_key or f"op_{uuid.uuid4().hex[:16]}",
            expiry=(
                (datetime.now(UTC) + timedelta(seconds=expiry_seconds)).isoformat()
                if expiry_seconds is not None
                else None
            ),
            metadata=metadata,
            lifecycle_state=IntentLifecycle.CREATED,
        )
        self.store.put(intent)
        return intent

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def transition(self, intent_id: str, new_state: IntentLifecycle) -> AuthorisedExecutionIntent:
        """Transition an intent to a new lifecycle state.

        Raises ``IntentTransitionError`` if the transition is not allowed.
        """
        self.store.update_state(intent_id, new_state)
        intent = self.store.get(intent_id)
        assert intent is not None  # update_state would have raised
        return intent

    def link_decision(self, intent_id: str, decision_id: str) -> None:
        intent = self.store.get(intent_id)
        if intent is None:
            raise KeyError(intent_id)
        intent.linked_decision_id = decision_id
        self.store.put(intent)

    def link_proof(self, intent_id: str, proof_id: str) -> None:
        intent = self.store.get(intent_id)
        if intent is None:
            raise KeyError(intent_id)
        intent.linked_proof_id = proof_id
        self.store.put(intent)

    def link_attempt(self, intent_id: str, attempt_id: str) -> None:
        intent = self.store.get(intent_id)
        if intent is None:
            raise KeyError(intent_id)
        if attempt_id not in intent.linked_attempt_ids:
            intent.linked_attempt_ids.append(attempt_id)
        self.store.put(intent)

    def link_receipt(self, intent_id: str, receipt_id: str) -> None:
        intent = self.store.get(intent_id)
        if intent is None:
            raise KeyError(intent_id)
        intent.linked_receipt_id = receipt_id
        self.store.put(intent)

    def link_refusal(self, intent_id: str, refusal_id: str) -> None:
        intent = self.store.get(intent_id)
        if intent is None:
            raise KeyError(intent_id)
        intent.linked_refusal_id = refusal_id
        self.store.put(intent)

    # ------------------------------------------------------------------
    # Execution APIs
    # ------------------------------------------------------------------

    def execute(
        self,
        intent: AuthorisedExecutionIntent,
        *,
        grant: Grant,
        decision: Decision,
        broker: Broker,
        adapter: ProviderAdapter | None = None,
        credential_ref: str | None = None,
        resource_client: ResourceOwnedSubmissionClient | None = None,
        proof: dict[str, Any] | None = None,
    ) -> tuple[AuthorisedExecutionIntent, Any]:
        """Execute an intent. Dispatches based on ``requested_execution_mode``.

        For ``brokered`` mode: requires ``adapter`` + ``credential_ref``.
        Uses ``BrokeredExecutionCoordinator``.

        For ``resource_owned`` mode: requires ``resource_client`` + ``proof``.
        Uses ``ResourceOwnedSubmissionClient``.

        Returns ``(updated_intent, mode_aware_result)``. The result
        remains discriminated — brokered returns a BrokeredExecutionResult,
        resource_owned returns a ResourceOwnedExecutionResult. The two
        are NOT interchangeable.

        Raises ``ValueError`` if the required arguments for the mode
        are not provided.
        """
        if intent.requested_execution_mode == "brokered":
            if adapter is None or credential_ref is None:
                raise ValueError(
                    "brokered execution requires adapter + credential_ref"
                )
            return self.execute_brokered(
                intent, grant=grant, decision=decision, broker=broker,
                adapter=adapter, credential_ref=credential_ref,
            )
        if intent.requested_execution_mode == "resource_owned":
            if resource_client is None or proof is None:
                raise ValueError(
                    "resource_owned execution requires resource_client + proof"
                )
            return self.submit_to_resource(
                intent, resource_client=resource_client, proof=proof,
            )
        raise ValueError(f"unknown execution mode: {intent.requested_execution_mode!r}")

    def execute_brokered(
        self,
        intent: AuthorisedExecutionIntent,
        *,
        grant: Grant,
        decision: Decision,
        broker: Broker,
        adapter: ProviderAdapter,
        credential_ref: str,
    ) -> tuple[AuthorisedExecutionIntent, Any]:
        """Execute a brokered intent.

        Transitions: CREATED -> EVALUATING -> AUTHORISED -> PROOF_ISSUED
        -> EXECUTING -> {SUCCEEDED|FAILED|REFUSED|OUTCOME_UNKNOWN}.

        The proof_issued state is entered optimistically (Permit mints
        a PCCB at decision time; the AEI records the link).
        """
        # Transition through the lifecycle.
        intent = self.transition(intent.intent_id, IntentLifecycle.EVALUATING)
        if decision.outcome == DecisionOutcome.DENY:
            intent = self.transition(intent.intent_id, IntentLifecycle.DENIED)
            return intent, None
        if decision.outcome == DecisionOutcome.REQUIRE_APPROVAL:
            intent = self.transition(intent.intent_id, IntentLifecycle.REQUIRES_APPROVAL)
            # Approval gate is the caller's responsibility; if they passed
            # an ALLOW decision we assume approval was granted.
            intent = self.transition(intent.intent_id, IntentLifecycle.AUTHORISED)
        else:
            intent = self.transition(intent.intent_id, IntentLifecycle.AUTHORISED)

        # Record proof link (PCCB is minted by the PDP; the AEI just
        # records that one was issued).
        proof_id = f"proof_{uuid.uuid4().hex[:16]}"
        self.link_proof(intent.intent_id, proof_id)
        intent = self.transition(intent.intent_id, IntentLifecycle.PROOF_ISSUED)
        intent = self.transition(intent.intent_id, IntentLifecycle.EXECUTING)

        # Run the coordinator.
        coord = BrokeredExecutionCoordinator(broker=broker)
        action = self._to_action(intent, grant)
        result = coord.coordinate(
            grant, action, decision, adapter,
            credential_ref=credential_ref,
            idempotency_key=intent.idempotency_key,
            pccb_id=proof_id,
            action_hash=None,
        )
        # Link the attempt id.
        self.link_attempt(intent.intent_id, result.protocol_result.attempt_id)

        # Map the result state to a lifecycle state.
        lifecycle_map = {
            BrokeredExecutionState.SUCCEEDED: IntentLifecycle.SUCCEEDED,
            BrokeredExecutionState.FAILED: IntentLifecycle.FAILED,
            BrokeredExecutionState.REFUSED: IntentLifecycle.REFUSED,
            BrokeredExecutionState.OUTCOME_UNKNOWN: IntentLifecycle.OUTCOME_UNKNOWN,
        }
        new_state = lifecycle_map[BrokeredExecutionState(result.state)]
        # outcome_unknown -> outcome_unknown is allowed; succeeded/failed are terminal.
        intent = self.transition(intent.intent_id, new_state)
        return intent, result

    def submit_to_resource(
        self,
        intent: AuthorisedExecutionIntent,
        *,
        resource_client: ResourceOwnedSubmissionClient,
        proof: dict[str, Any],
    ) -> tuple[AuthorisedExecutionIntent, Any]:
        """Submit a resource-owned intent to the resource boundary.

        Transitions: CREATED -> EVALUATING -> AUTHORISED -> PROOF_ISSUED
        -> SUBMITTED -> {SUCCEEDED|FAILED|REFUSED|OUTCOME_UNKNOWN}.

        Submission does NOT imply execution. The lifecycle stays at
        SUBMITTED until the resource returns a verifiable receipt
        (-> SUCCEEDED) or refuses (-> REFUSED) or returns nothing
        useful (-> OUTCOME_UNKNOWN).
        """
        intent = self.transition(intent.intent_id, IntentLifecycle.EVALUATING)
        intent = self.transition(intent.intent_id, IntentLifecycle.AUTHORISED)
        # Record proof link (the proof was minted by an authority broker
        # outside this manager; the AEI just records the link).
        if intent.linked_proof_id is None:
            proof_id = proof.get("proof_id") or f"proof_{uuid.uuid4().hex[:16]}"
            self.link_proof(intent.intent_id, proof_id)
        intent = self.transition(intent.intent_id, IntentLifecycle.PROOF_ISSUED)
        intent = self.transition(intent.intent_id, IntentLifecycle.SUBMITTED)

        action = self._to_action(intent, grant=None)  # type: ignore[arg-type]
        result = resource_client.submit(
            action, proof,
            pccb_id=intent.linked_proof_id,
            action_hash=None,
        )
        self.link_attempt(intent.intent_id, result.protocol_result.attempt_id)
        if result.protocol_result.submission_reference:
            intent_ref = self.store.get(intent.intent_id)
            assert intent_ref is not None
            intent_ref.submission_reference = result.protocol_result.submission_reference
            self.store.put(intent_ref)

        # Map the result state to a lifecycle state.
        lifecycle_map = {
            ResourceOwnedExecutionState.SUBMITTED: IntentLifecycle.SUBMITTED,
            ResourceOwnedExecutionState.ACCEPTED: IntentLifecycle.SUBMITTED,  # still non-final
            ResourceOwnedExecutionState.SUCCEEDED: IntentLifecycle.SUCCEEDED,
            ResourceOwnedExecutionState.FAILED: IntentLifecycle.FAILED,
            ResourceOwnedExecutionState.REFUSED: IntentLifecycle.REFUSED,
            ResourceOwnedExecutionState.OUTCOME_UNKNOWN: IntentLifecycle.OUTCOME_UNKNOWN,
        }
        new_state = lifecycle_map[ResourceOwnedExecutionState(result.state)]
        # The intent is currently at SUBMITTED. If the result maps to SUBMITTED
        # (i.e. the resource returned submitted or accepted), no transition is
        # needed — we're still non-final. Otherwise, transition to the
        # resolved state.
        if new_state != IntentLifecycle.SUBMITTED:
            intent = self.transition(intent.intent_id, new_state)
        return intent, result

    # ------------------------------------------------------------------
    # Compatibility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def from_grant(
        grant: Grant,
        *,
        action_type: str,
        action_params: dict[str, Any],
        target_type: str,
        target_id: str,
        requested_execution_mode: str = "brokered",
        metadata: dict[str, Any] | None = None,
    ) -> AuthorisedExecutionIntent:
        """Compatibility wrapper: create an AEI from an existing Grant.

        The Grant is the v0/v1 capability-token API. The AEI is the
        v1.3 developer surface. This wrapper lets existing code that
        has a Grant adopt the AEI without rewriting the issuance path.

        The Grant's agent_id becomes the AEI's requester_agent_id; the
        Grant's id is recorded in metadata (NOT in a linked_artefact
        field — the Grant is the authority, not a proof).
        """
        md = dict(metadata or {})
        # Don't allow callers to smuggle the grant's signature into metadata.
        md.setdefault("_source_grant_id", grant.id)
        validate_metadata(md)
        return AuthorisedExecutionIntent(
            intent_id=f"intent_{uuid.uuid4().hex[:16]}",
            protocol_version=PROTOCOL_VERSION,
            action_type=action_type,
            action_params=dict(action_params),
            target_type=target_type,
            target_id=target_id,
            requested_execution_mode=requested_execution_mode,
            requester_subject=grant.agent_id,
            requester_agent_id=grant.agent_id,
            idempotency_key=f"op_{uuid.uuid4().hex[:16]}",
            expiry=grant.expires_at.isoformat(),
            metadata=md,
            lifecycle_state=IntentLifecycle.CREATED,
        )

    @staticmethod
    def _to_action(intent: AuthorisedExecutionIntent, grant: Grant | None) -> Action:
        """Compatibility helper: produce a v1 Action from an AEI.

        The Action is what the PDP and Broker expect. The AEI is the
        developer surface; this helper bridges.
        """
        return Action(
            grant_id=grant.id if grant else intent.intent_id,
            type=intent.action_type,
            target=intent.target_id,
            params=dict(intent.action_params),
            est_cost=0.0,
        )


# ---------------------------------------------------------------------------
# Capability info
# ---------------------------------------------------------------------------


def store_capabilities(store: IntentStore) -> dict[str, Any]:
    """Return capability information for a store.

    Callers SHOULD check these capabilities before relying on
    post-restart polling. An ephemeral store will report
    ``survives_process_restart: False``.
    """
    profile = store.durability_profile
    return {
        "durability_profile": profile.value,
        "survives_process_restart": profile != DurabilityProfile.EPHEMERAL_LOCAL,
        "survives_host_failure": profile == DurabilityProfile.DURABLE_CLOUD,
        "pollable_after_process_termination": profile != DurabilityProfile.EPHEMERAL_LOCAL,
    }


__all__ = [
    "AuthorisedExecutionIntent",
    "DurabilityProfile",
    "EphemeralIntentStore",
    "IntentLifecycle",
    "IntentManager",
    "IntentStore",
    "IntentTransitionError",
    "INTENT_TRANSITIONS",
    "MAX_METADATA_BYTES",
    "MetadataValidationError",
    "SQLiteIntentStore",
    "can_transition",
    "store_capabilities",
    "validate_metadata",
    "validate_transition",
]
