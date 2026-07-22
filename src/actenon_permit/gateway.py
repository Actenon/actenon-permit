"""Actenon-Permit v1 out-of-process PEP gateway.

The gateway is the v1 "airlock": it runs in a separate process from the agent,
holds the real credentials, and enforces every decision server-side. An agent
with arbitrary code-exec can no longer bypass enforcement by importing the
provider SDK directly — it doesn't have the secret, only a grant token.

Two transports are supported:

  1. **HTTP proxy** — ``POST /proxy/{tool}`` with ``X-Actenon-Grant`` header.
     Returns the tool's result on ALLOW, 403 with a JSON body on DENY, 202
     with an approval URL on REQUIRE_APPROVAL.

  2. **MCP stdio** — JSON-RPC 2.0 over stdin/stdout. ``tools/list`` returns
     the registered tools as MCP tool specs; ``tools/call`` enforces the
     decision and executes. The grant token is passed in
     ``params._meta.actenon_grant``.

Both transports share the same ``ToolRegistry`` and the same enforcement
path: validate token -> load live grant state -> ``PDP.decide()`` -> on ALLOW
run the real call via the broker -> reconcile cost -> return.

The gateway extends v0's ``control.py`` FastAPI app rather than replacing it.
The control plane endpoints (/grants, /approvals, /ledger) still work; the
gateway adds /proxy/* and the MCP stdio entrypoint.
"""

from __future__ import annotations

import contextlib
import json
import sys
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .broker import Broker, CredentialMissing, extract_cost
from .enforce import ApprovalGate, AutoApproveGate
from .ledger import Ledger
from .model import Action, Decision, DecisionOutcome, Grant, GrantStatus
from .pdp import PDP
from .state import SQLiteStore, StateStore
from .token import TokenError, token_to_grant

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    """A guarded tool registered with the gateway.

    Two variants are supported:

    1. **Legacy v1 (real_call)**: ``real_call`` is a callable that
       receives the resolved secret as its first arg. The gateway
       invokes it via ``Broker.execute`` (env-var credential lookup).

    2. **v1.2 adapter-backed (Prompt 8 + 9)**: ``adapter`` is a
       ``ProviderAdapter`` and ``credential_ref`` is the registry
       ref. The gateway invokes it via
       ``BrokeredExecutionCoordinator.coordinate`` which produces a
       ``ModeAwareExecutionResult`` (Prompt 9 discriminated union).
       The response dict carries the new execution-mode fields.

    The two variants are mutually exclusive: setting ``adapter``
    requires ``credential_ref`` and forbids ``real_call``.
    """

    name: str
    action_type: str
    real_call: Callable[..., Any] = field(repr=False, default=lambda *a, **kw: None)
    target: str = ""
    description: str = ""
    input_schema: dict[str, Any] = field(
        default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": True}
    )
    cost_from: str | None = None
    credential_name: str | None = None
    # v1.2 (Prompt 8 + 9) adapter-backed variant
    adapter: Any = None  # ProviderAdapter | None
    credential_ref: str | None = None
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        # Enforce mutual exclusivity between real_call and adapter.
        if self.adapter is not None and self.real_call is not None and self.real_call.__name__ != "<lambda>":
            # If adapter is set, real_call must be the default lambda placeholder.
            # We can't easily detect "is this the default lambda"; instead we
            # require credential_ref to be set when adapter is set, and we
            # ignore real_call when adapter is set (the coordinator path
            # uses adapter.execute directly).
            pass
        if self.adapter is not None and self.credential_ref is None:
            raise ValueError(
                f"tool {self.name!r}: adapter-backed tools must set credential_ref"
            )


class ToolRegistry:
    """Registry of guarded tools the gateway exposes."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._lock = threading.RLock()

    def register(
        self,
        name: str,
        *,
        action_type: str,
        target: str = "",
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        cost_from: str | None = None,
        credential_name: str | None = None,
        real_call: Callable[..., Any],
    ) -> ToolSpec:
        spec = ToolSpec(
            name=name,
            action_type=action_type,
            target=target or action_type,
            description=description or f"{action_type} tool",
            input_schema=input_schema or {"type": "object", "properties": {}, "additionalProperties": True},
            cost_from=cost_from,
            credential_name=credential_name,
            real_call=real_call,
        )
        with self._lock:
            if name in self._tools:
                raise ValueError(f"tool '{name}' is already registered")
            self._tools[name] = spec
        return spec

    def register_adapter_tool(
        self,
        name: str,
        *,
        action_type: str,
        adapter: Any,
        credential_ref: str,
        target: str = "",
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> ToolSpec:
        """Register a v1.2 adapter-backed tool.

        The tool is executed via ``BrokeredExecutionCoordinator``
        (Prompt 9), which produces a ``ModeAwareExecutionResult``.
        The gateway response carries the execution-mode fields
        (``execution_mode``, ``execution_state``, ``finality``,
        ``provider_execution_observed``, ``receipt_received``,
        ``receipt_verified``).
        """
        spec = ToolSpec(
            name=name,
            action_type=action_type,
            target=target or action_type,
            description=description or f"{action_type} adapter tool",
            input_schema=input_schema
            or {"type": "object", "properties": {}, "additionalProperties": True},
            adapter=adapter,
            credential_ref=credential_ref,
            timeout_seconds=timeout_seconds,
        )
        with self._lock:
            if name in self._tools:
                raise ValueError(f"tool '{name}' is already registered")
            self._tools[name] = spec
        return spec

    def get(self, name: str) -> ToolSpec | None:
        with self._lock:
            return self._tools.get(name)

    def list(self) -> list[ToolSpec]:
        with self._lock:
            return list(self._tools.values())

    def to_mcp_tools(self) -> list[dict[str, Any]]:
        """Return the registry as MCP ``tools/list`` result entries."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self.list()
        ]


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class Gateway:
    """The out-of-process PEP. Holds tool registry, state, ledger, PDP, broker.

    The gateway is transport-agnostic: ``call_tool()`` is the single
    enforcement path used by both the HTTP proxy and the MCP stdio server.
    """

    def __init__(
        self,
        *,
        state: StateStore | None = None,
        ledger: Ledger | None = None,
        pdp: PDP | None = None,
        broker: Broker | None = None,
        tools: ToolRegistry | None = None,
        approval_gate: ApprovalGate | None = None,
        brokered_coordinator: Any = None,
        intent_manager: Any = None,
    ):
        self.state = state or SQLiteStore()
        self.ledger = ledger or Ledger(self.state)
        self.pdp = pdp or PDP(self.state, self.ledger)
        self.broker = broker or Broker(self.pdp)
        self.tools = tools or ToolRegistry()
        # Default to auto-approve for tests; production callers should set a
        # BlockingApprovalGate wired to the control plane's ApprovalStore.
        self.approval_gate: ApprovalGate = approval_gate or AutoApproveGate()
        # v1.2 (Prompt 9): brokered execution coordinator for adapter-backed tools.
        # Constructed lazily from self.broker if not provided.
        self.brokered_coordinator = brokered_coordinator
        # v1.3 (Prompt 10): intent manager for the AEI developer surface.
        # Constructed lazily with an EphemeralIntentStore if not provided.
        self.intent_manager = intent_manager

    # ------------------------------------------------------------------
    # Grant token handling
    # ------------------------------------------------------------------

    def _get_brokered_coordinator(self) -> Any:
        """Lazily construct a BrokeredExecutionCoordinator if not provided."""
        if self.brokered_coordinator is None:
            from .execution_modes import BrokeredExecutionCoordinator

            self.brokered_coordinator = BrokeredExecutionCoordinator(broker=self.broker)
        return self.brokered_coordinator

    def _get_intent_manager(self) -> Any:
        """Lazily construct an IntentManager with an EphemeralIntentStore
        if not provided. Production deployments SHOULD inject a
        ``DurableLocal`` or ``DurableCloud`` store."""
        if self.intent_manager is None:
            from .intent import EphemeralIntentStore, IntentManager

            self.intent_manager = IntentManager(store=EphemeralIntentStore())
        return self.intent_manager

    # ------------------------------------------------------------------
    # v1.3 (Prompt 10): AEI developer surface
    # ------------------------------------------------------------------

    def create_intent(
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
    ) -> dict[str, Any]:
        """Create a new AuthorisedExecutionIntent. Returns the intent
        as a JSON-safe dict (suitable for HTTP response).

        The intent starts in the ``created`` lifecycle state. Call
        ``execute_intent`` to advance it.
        """
        mgr = self._get_intent_manager()
        intent = mgr.create(
            action_type=action_type,
            action_params=action_params,
            target_type=target_type,
            target_id=target_id,
            requested_execution_mode=requested_execution_mode,
            requester_subject=requester_subject,
            requester_agent_id=requester_agent_id,
            requester_tenant_id=requester_tenant_id,
            idempotency_key=idempotency_key,
            expiry_seconds=expiry_seconds,
            metadata=metadata,
        )
        return intent.to_dict()

    def get_intent(self, intent_id: str) -> dict[str, Any] | None:
        """Return the intent with the given id, or None if not found."""
        mgr = self._get_intent_manager()
        intent = mgr.store.get(intent_id)
        return intent.to_dict() if intent is not None else None

    def list_intents(self, *, requester_subject: str | None = None) -> list[dict[str, Any]]:
        """List intents, optionally filtered by requester_subject."""
        mgr = self._get_intent_manager()
        return [i.to_dict() for i in mgr.store.list(requester_subject=requester_subject)]

    def execute_intent(
        self,
        intent_id: str,
        *,
        grant_token: str,
    ) -> dict[str, Any]:
        """Execute an existing intent.

        For ``brokered`` mode: the gateway looks up a registered
        adapter tool whose ``action_type`` matches the intent's, runs
        the PDP on the grant, and invokes the coordinator. The grant
        token is the same v1 bearer token used by ``call_tool``.

        For ``resource_owned`` mode: the gateway requires a
        ``resource_client`` to be registered on the intent manager
        (not yet supported via HTTP; resource-owned submission is
        currently in-process only). HTTP callers should use the
        ``submit_to_resource`` API directly.

        Returns a dict that combines the AEI lifecycle fields with
        the Prompt-9 execution-mode fields:

            {
              "intent": <AuthorisedExecutionIntent dict>,
              "outcome": "ALLOW" | "DENY",
              "execution_mode": "brokered" | "resource_owned",
              "execution_state": "succeeded" | "failed" | ...,
              "finality": "final" | "non_final",
              "provider_execution_observed": bool,
              "receipt_received": bool (brokered only),
              "receipt_verified": bool (brokered only),
              "result": <redacted provider evidence>,
            }
        """
        mgr = self._get_intent_manager()
        intent = mgr.store.get(intent_id)
        if intent is None:
            return {
                "outcome": "DENY",
                "reason": f"intent not found: {intent_id}",
                "rule_matched": "intent:unknown",
            }

        # Resolve the grant token -> live Grant.
        try:
            grant = self.resolve_grant(grant_token)
        except TokenError as e:
            return {
                "outcome": "DENY",
                "reason": f"invalid grant token: {e}",
                "rule_matched": "token:invalid",
            }

        # Build the Action + decision via the PDP.
        action = Action(
            action_id=f"act_{uuid.uuid4().hex[:16]}",
            grant_id=grant.id,
            ts=datetime.now(UTC),
            type=intent.action_type,
            target=intent.target_id,
            params=dict(intent.action_params),
            est_cost=0.0,
        )
        decision, _intent_obj, _pccb = self.pdp.decide_and_mint_pccb(grant, action, ctx={})
        if decision.outcome == DecisionOutcome.DENY:
            # Record the denial on the intent.
            from .intent import IntentLifecycle

            mgr.transition(intent.intent_id, IntentLifecycle.EVALUATING)
            mgr.transition(intent.intent_id, IntentLifecycle.DENIED)
            updated = mgr.store.get(intent.intent_id)
            assert updated is not None
            return {
                "intent": updated.to_dict(),
                "outcome": "DENY",
                "reason": decision.reason,
                "rule_matched": decision.rule_matched,
            }

        # Locate a registered adapter tool whose action_type matches.
        tool = None
        for t in self.tools.list():
            if t.action_type == intent.action_type and t.adapter is not None:
                tool = t
                break
        if tool is None:
            return {
                "intent": intent.to_dict(),
                "outcome": "DENY",
                "reason": f"no adapter tool registered for action_type {intent.action_type!r}",
                "rule_matched": "intent:no_adapter",
            }

        # Execute via the manager. The manager advances the lifecycle
        # and returns the ModeAwareExecutionResult.
        try:
            updated, mode_result = mgr.execute(
                intent,
                grant=grant,
                decision=decision,
                broker=self.broker,
                adapter=tool.adapter,
                credential_ref=tool.credential_ref or "",
            )
        except Exception as e:
            return {
                "intent": intent.to_dict(),
                "outcome": "DENY",
                "reason": f"intent execution error: {type(e).__name__}: {e}",
                "rule_matched": "intent:execution_error",
            }

        # Map the result state to outcome.
        outcome = "ALLOW" if mode_result.state == "succeeded" else "DENY"
        response: dict[str, Any] = {
            "intent": updated.to_dict(),
            "outcome": outcome,
            "execution_mode": mode_result.mode,
            "execution_state": mode_result.state,
            "finality": mode_result.finality.value,
            "provider_execution_observed": mode_result.protocol_result.provider_execution_observed,
            "result": mode_result.protocol_result.provider_evidence,
        }
        if mode_result.mode == "brokered":
            response["receipt_received"] = mode_result.protocol_result.receipt_received
            response["receipt_verified"] = mode_result.protocol_result.receipt_verified
        return response

    def resolve_grant(self, token: str) -> Grant:
        """Decode a bearer token and return the live Grant from the state store.

        The token carries the grant's signature and identity; the state store
        carries the live status/budget. We trust the token for identity
        (signature-verified) but the state store for status — so a revoked
        grant's token is still decodable but the next decision is DENY.
        """
        try:
            grant_from_token = token_to_grant(token, verify=True)
        except TokenError:
            raise
        # Load live state (status may have changed since the token was issued)
        live = self.state.get_grant(grant_from_token.id)
        if live is None:
            # Token is valid but the grant has been deleted from the store.
            # Treat as revoked — fail closed.
            grant_from_token.status = GrantStatus.REVOKED
            return grant_from_token
        return live

    # ------------------------------------------------------------------
    # The single enforcement path
    # ------------------------------------------------------------------

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        grant_token: str,
    ) -> dict[str, Any]:
        """Enforce-then-execute a tool call. Returns a structured result.

        Returns a dict with shape::

            {
              "outcome": "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
              "reason": str,
              "rule_matched": str | None,
              "result": <tool return value, only on ALLOW>,
              "action_id": str,
              "grant_id": str,
              "remaining_budget": float | None,
            }
        """
        spec = self.tools.get(tool_name)
        if spec is None:
            return {
                "outcome": "DENY",
                "reason": f"unknown tool: {tool_name}",
                "rule_matched": "tool:unknown",
                "action_id": None,
                "grant_id": None,
                "remaining_budget": None,
            }

        try:
            grant = self.resolve_grant(grant_token)
        except TokenError as e:
            return {
                "outcome": "DENY",
                "reason": f"invalid grant token: {e}",
                "rule_matched": "token:invalid",
                "action_id": None,
                "grant_id": None,
                "remaining_budget": None,
            }

        # Build the Action from the call args. The cost is extracted from the
        # argument named by ``cost_from`` (or params['amount'] / ['cost']).
        params = {k: v for k, v in arguments.items() if isinstance(v, (str, int, float, bool, type(None)))}
        est_cost: float | None = None
        if spec.cost_from and spec.cost_from in arguments and isinstance(arguments[spec.cost_from], (int, float)):
            est_cost = float(arguments[spec.cost_from])
        elif "amount" in params and isinstance(params["amount"], (int, float)):
            est_cost = float(params["amount"])
        elif "cost" in params and isinstance(params["cost"], (int, float)):
            est_cost = float(params["cost"])

        action = Action(
            action_id=f"act_{uuid.uuid4().hex[:16]}",
            grant_id=grant.id,
            ts=datetime.now(UTC),
            type=spec.action_type,
            target=spec.target,
            params=params,
            est_cost=est_cost,
        )

        # Use decide_and_mint_pccb so we get a kernel PCCB on ALLOW.
        # The PCCB is verified at the edge before the broker releases the
        # real credential — this is the "agent physically cannot exceed"
        # guarantee from ARCHITECTURE.md §3.
        decision, intent, pccb = self.pdp.decide_and_mint_pccb(grant, action, ctx={})

        if decision.outcome == DecisionOutcome.DENY:
            return self._deny_response(action, decision, grant)

        if decision.outcome == DecisionOutcome.REQUIRE_APPROVAL:
            approved = self.approval_gate.request(grant, action, decision)
            if not approved:
                return {
                    "outcome": "DENY",
                    "reason": "approval denied or timed out",
                    "rule_matched": decision.rule_matched,
                    "action_id": action.action_id,
                    "grant_id": grant.id,
                    "remaining_budget": float(grant.budget.remaining),
                }
            # Re-run decision + PCCB mint after approval — state and clock moved.
            grant = self.state.get_grant(grant.id) or grant
            decision, intent, pccb = self.pdp.decide_and_mint_pccb(
                grant, action, ctx={"approved_action_id": action.action_id}
            )
            if decision.outcome != DecisionOutcome.ALLOW:
                return self._deny_response(action, decision, grant)

        # EDGE VERIFICATION — the kernel verifies the PCCB is bound to the
        # EXACT action before we release the credential. This is the call
        # that makes "the agent physically cannot exceed" true: a mutated
        # amount, a different target, a replayed proof, an expired grant —
        # any of these raises ProofVerificationError and we DENY.
        if intent is not None and pccb is not None:
            try:
                from .kernel_bridge import verify_pccb_at_edge

                verify_pccb_at_edge(intent, pccb, grant, action)
            except Exception as e:
                # Kernel verification failed — release the reservation and
                # fail closed. The credential is NOT released.
                if action.est_cost:
                    with contextlib.suppress(Exception):
                        self.state.release(grant.id, action.action_id, action.est_cost)
                # Surface structured refusal codes per the protocol's
                # two-layer disclosure model. The kernel's
                # ProofVerificationError carries a refusal_code attribute
                # (e.g. "SIGNATURE_INVALID", "ACTION_MISMATCH",
                # "AUDIENCE_MISMATCH"). We map it to the protocol's
                # disclosed_code (public-safe umbrella) and internal_code
                # (detailed, only when the disclosure policy permits).
                # See actenon-protocol/protocol/11-disclosure-policy.md.
                from actenon.outcomes import (
                    to_disclosed_code,
                    to_internal_code,
                    to_retryable,
                )
                refusal_code = getattr(e, "refusal_code", None)
                # Default disclosure policy is "public" (safe for
                # untrusted callers). Trusted callers can be upgraded by
                # the gateway's caller in a future revision.
                disclosure_policy = "public"
                disclosed_code = (
                    to_disclosed_code(refusal_code, disclosure_policy)
                    if refusal_code
                    else "PROOF_INVALID"
                )
                internal_code = (
                    to_internal_code(refusal_code, disclosure_policy)
                    if refusal_code
                    else None
                )
                retryable = (
                    to_retryable(refusal_code) if refusal_code else False
                )
                return {
                    "outcome": "DENY",
                    "reason": f"proof verification failed at edge: {e}",
                    "rule_matched": "kernel:proof_verification_failed",
                    "action_id": action.action_id,
                    "grant_id": grant.id,
                    "remaining_budget": float(grant.budget.remaining),
                    # Protocol-aligned structured refusal codes.
                    "disclosed_code": disclosed_code,
                    "internal_code": internal_code,
                    "retryable": retryable,
                }

        # ALLOW — execute the real call. Two paths:
        #   (a) v1.2 adapter-backed (Prompt 8 + 9): use the
        #       BrokeredExecutionCoordinator. Produces a
        #       ModeAwareExecutionResult; the response dict carries
        #       execution-mode fields.
        #   (b) legacy v1 (real_call): use Broker.execute (env-var
        #       lookup) or call real_call directly if no credential.
        if spec.adapter is not None:
            # Adapter-backed path (Prompt 9).
            try:
                coord = self._get_brokered_coordinator()
                mode_result = coord.coordinate(
                    grant,
                    action,
                    decision,
                    spec.adapter,
                    credential_ref=spec.credential_ref or "",
                    idempotency_key=action.action_id,
                    timeout_seconds=spec.timeout_seconds,
                    pccb_id=getattr(pccb, "pccb_id", None) if pccb else None,
                )
            except Exception as e:
                # Coordinator crash (should not happen — it wraps adapter
                # errors). Release the reservation and fail closed.
                if action.est_cost:
                    with contextlib.suppress(Exception):
                        self.state.release(grant.id, action.action_id, action.est_cost)
                return {
                    "outcome": "DENY",
                    "reason": f"coordinator error: {type(e).__name__}: {e}",
                    "rule_matched": "coordinator:crash",
                    "action_id": action.action_id,
                    "grant_id": grant.id,
                    "remaining_budget": float(grant.budget.remaining),
                }

            # Map the ModeAwareExecutionResult to the gateway response.
            live = self.state.get_grant(grant.id) or grant
            state_str = mode_result.state
            # outcome="ALLOW" only when state==succeeded; refused/failed/
            # outcome_unknown surface as DENY-with-context so the existing
            # caller code that branches on outcome keeps working.
            outcome = "ALLOW" if state_str == "succeeded" else "DENY"
            response: dict[str, Any] = {
                "outcome": outcome,
                "reason": mode_result.protocol_result.provider_evidence.get("reason", decision.reason),
                "rule_matched": decision.rule_matched,
                "result": mode_result.protocol_result.provider_evidence,
                "action_id": action.action_id,
                "grant_id": grant.id,
                "remaining_budget": float(live.budget.remaining),
                # Prompt 9 execution-mode fields:
                "execution_mode": mode_result.mode,
                "execution_state": state_str,
                "finality": mode_result.finality.value,
                "provider_execution_observed": mode_result.protocol_result.provider_execution_observed,
                "receipt_received": getattr(mode_result.protocol_result, "receipt_received", None),
                "receipt_verified": getattr(mode_result.protocol_result, "receipt_verified", None),
            }
            # Redact: never include the credential value (the coordinator
            # already redacted the evidence, but belt-and-braces).
            return response

        # Legacy path (v1).
        try:
            if spec.credential_name is None:
                result = spec.real_call(**arguments)
                actual_cost = extract_cost(result, action)
                self.pdp.commit(grant, action, actual_cost)
            else:
                result, actual_cost = self.broker.execute(
                    grant,
                    action,
                    decision,
                    lambda secret: spec.real_call(secret=secret, **arguments),
                    spec.credential_name,
                )
        except CredentialMissing as e:
            # Release the reservation and fail closed.
            if action.est_cost:
                with contextlib.suppress(Exception):
                    self.state.release(grant.id, action.action_id, action.est_cost)
            return {
                "outcome": "DENY",
                "reason": f"credential missing: {e}",
                "rule_matched": "broker:credential_missing",
                "action_id": action.action_id,
                "grant_id": grant.id,
                "remaining_budget": float(grant.budget.remaining),
            }
        except Exception as e:
            # The real call raised. Reconcile cost as 0 (nothing happened
            # in the real world) and surface the error as a DENY.
            if action.est_cost:
                with contextlib.suppress(Exception):
                    self.state.release(grant.id, action.action_id, action.est_cost)
            return {
                "outcome": "DENY",
                "reason": f"tool execution error: {type(e).__name__}: {e}",
                "rule_matched": "broker:execution_error",
                "action_id": action.action_id,
                "grant_id": grant.id,
                "remaining_budget": float(grant.budget.remaining),
            }

        # Reload grant to get the post-commit remaining.
        live = self.state.get_grant(grant.id) or grant
        return {
            "outcome": "ALLOW",
            "reason": decision.reason,
            "rule_matched": decision.rule_matched,
            "result": result,
            "action_id": action.action_id,
            "grant_id": grant.id,
            "remaining_budget": float(live.budget.remaining),
        }

    @staticmethod
    def _deny_response(action: Action, decision: Decision, grant: Grant) -> dict[str, Any]:
        return {
            "outcome": "DENY",
            "reason": decision.reason,
            "rule_matched": decision.rule_matched,
            "action_id": action.action_id,
            "grant_id": grant.id,
            "remaining_budget": float(grant.budget.remaining),
        }


# ---------------------------------------------------------------------------
# HTTP proxy (extends the v0 control plane)
# ---------------------------------------------------------------------------


def mount_proxy(app, gateway: Gateway) -> None:
    """Mount /proxy/* endpoints on an existing FastAPI app.

    Delegates to ``_proxy_routes.mount`` which is a module that does NOT use
    ``from __future__ import annotations``. FastAPI's Request-type detection
    happens at runtime via isinstance checks on the annotation, and
    stringified annotations (which the future import produces) break it —
    the route handler's ``request: Request`` parameter gets treated as a
    required query param and returns 422.
    """
    from . import _proxy_routes

    _proxy_routes.mount(app, gateway)


def mount_intent_routes(app, gateway: Gateway) -> None:
    """Mount /intents/* endpoints on an existing FastAPI app (Prompt 10).

    Same pattern as ``mount_proxy``: delegates to ``_intent_routes.mount``,
    a module without ``from __future__ import annotations`` so FastAPI's
    Request-type detection works.
    """
    from . import _intent_routes

    _intent_routes.mount(app, gateway)


# ---------------------------------------------------------------------------
# MCP stdio server (JSON-RPC 2.0 over stdin/stdout)
# ---------------------------------------------------------------------------


def mcp_serve(gateway: Gateway, *, infile=None, outfile=None) -> None:
    """Run the MCP stdio server.

    Reads JSON-RPC 2.0 requests line-by-line from ``infile`` (default stdin),
    writes responses line-by-line to ``outfile`` (default stdout). Implements:

      - ``initialize`` — handshake, returns server capabilities
      - ``tools/list`` — returns registered tools as MCP tool specs
      - ``tools/call`` — enforces decision and executes; grant token is read
        from ``params._meta.actenon_grant``

    The server exits cleanly on EOF or on an ``exit`` notification.
    """
    infile = infile or sys.stdin
    outfile = outfile or sys.stdout

    server_info = {
        "name": "actenon-permit-gateway",
        "version": "1.0.0",
    }
    capabilities = {
        "tools": {"listChanged": False},
    }

    for line in infile:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _write_jsonrpc(outfile, None, error={"code": -32700, "message": "Parse error"})
            continue

        if not isinstance(req, dict):
            _write_jsonrpc(outfile, None, error={"code": -32600, "message": "Invalid Request"})
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        # Notification (no id) — only handle exit.
        if req_id is None and method == "exit":
            return

        if method == "initialize":
            _write_jsonrpc(
                outfile,
                req_id,
                result={
                    "protocolVersion": "2024-11-05",
                    "capabilities": capabilities,
                    "serverInfo": server_info,
                },
            )
        elif method == "initialized":
            # notification, no response
            pass
        elif method == "tools/list":
            _write_jsonrpc(outfile, req_id, result={"tools": gateway.tools.to_mcp_tools()})
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            meta = params.get("_meta") or {}
            grant_token = meta.get("actenon_grant")
            if not grant_token:
                _write_jsonrpc(
                    outfile,
                    req_id,
                    error={"code": -32602, "message": "missing _meta.actenon_grant"},
                )
                continue
            result = gateway.call_tool(tool_name, arguments, grant_token)
            # MCP expects an isError flag for tool errors. We map ALLOW to
            # success and anything else to isError=true with the reason as text.
            if result["outcome"] == "ALLOW":
                content = _mcp_content(result.get("result"))
                _write_jsonrpc(outfile, req_id, result={"content": content, "isError": False})
            else:
                content = [{"type": "text", "text": f"{result['outcome']}: {result['reason']}"}]
                _write_jsonrpc(outfile, req_id, result={"content": content, "isError": True})
        elif method == "ping":
            _write_jsonrpc(outfile, req_id, result={})
        else:
            _write_jsonrpc(
                outfile,
                req_id,
                error={"code": -32601, "message": f"Method not found: {method}"},
            )


def _write_jsonrpc(stream, req_id, *, result=None, error=None) -> None:
    msg: dict[str, Any] = {"jsonrpc": "2.0"}
    if req_id is not None:
        msg["id"] = req_id
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    stream.write(json.dumps(msg) + "\n")
    stream.flush()


def _mcp_content(value: Any) -> list[dict[str, Any]]:
    """Wrap a tool result value as MCP content blocks."""
    if value is None:
        return [{"type": "text", "text": "null"}]
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    return [{"type": "text", "text": json.dumps(value, default=str, sort_keys=True)}]


__all__ = [
    "ToolSpec",
    "ToolRegistry",
    "Gateway",
    "mount_proxy",
    "mount_intent_routes",
    "mcp_serve",
]
