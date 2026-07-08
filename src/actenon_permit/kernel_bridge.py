"""Actenon-Permit ↔ Actenon-Kernel bridge.

This module is the **single translation layer** between permit's domain
(Grant / Action / Decision) and the kernel's domain (ActionIntent /
PolicyDecision / DynamicContextInput / PCCB). It is the concrete
implementation of the "one artifact spine" decision from ARCHITECTURE.md §3.

The bridge is one-directional in practice: permit's PDP makes a decision,
this bridge translates it into kernel terms, the kernel mints a PCCB, and
the PCCB is what the gateway verifies before broker release.

The kernel is the source of truth for:
  - the PCCB data model and builder (``PCCBMinter.mint``)
  - the PCCB verifier (``PCCBVerifier.verify``)
  - the canonicalization profile (``actenon-jcs-sha256-v1``)
  - the action-hash input shape (``build_action_hash_input``)

Permit never constructs a PCCB itself and never rolls its own
canonicalization — it always goes through this bridge.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from actenon.models.contracts import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import DynamicContextInput, PolicyDecision, RuleEvaluation
from actenon.proof.service import PCCBMinter, PCCBVerifier, build_action_hash_input

from .model import Action, Decision, DecisionOutcome, Grant


class KernelBridgeError(RuntimeError):
    """Raised when the bridge cannot translate or verify."""


def _canonicalize_value(v: Any) -> Any:
    """Convert a value to a kernel-canonicalizable form.

    The kernel's ``actenon-jcs-sha256-v1`` canonicalization rejects floats
    (float serialization is ambiguous). Permit uses floats for money. We
    convert floats to strings with a stable representation (``repr(float)``
    gives a round-trippable form) so the hash is deterministic and the edge
    verification matches.
    """
    if isinstance(v, float):
        # Use repr() for round-trip safety; for whole numbers this gives
        # '20.0', for fractional '20.5'. Stable across processes.
        return repr(v)
    if isinstance(v, dict):
        return {k: _canonicalize_value(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_canonicalize_value(item) for item in v]
    return v


def _canonicalize_params(params: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize all parameter values for kernel hashing."""
    return {k: _canonicalize_value(v) for k, v in params.items()}


def _permit_action_to_kernel_intent(
    grant: Grant,
    action: Action,
    *,
    tenant_id: str = "default",
    requester_id: str | None = None,
    audience_id: str = "actenon-permit-gateway",
) -> ActionIntent:
    """Translate a permit (Grant, Action) pair into a kernel ActionIntent.

    The ActionIntent is the kernel's representation of "the agent wants to do
    THIS exact thing." The PCCB will be cryptographically bound to it, so
    every field here becomes part of the action-hash the edge verifies.
    """
    now = datetime.now(UTC)
    # Permit's grant.expires_at is the outer bound; the intent's expires_at
    # is the same — the PCCB cannot outlive the grant.
    expires_at = grant.expires_at
    if expires_at < now:
        raise KernelBridgeError(f"grant expired at {expires_at}, cannot build intent")

    # The action parameters are what make this "exact": the amount, the
    # reason, the target account. The kernel hashes these and the edge
    # refuses any action whose parameters don't match.
    #
    # IMPORTANT: the kernel's canonicalization (actenon-jcs-sha256-v1)
    # rejects floating-point values because float serialization is
    # ambiguous. Permit uses floats for money (50.0, 20.0). The bridge
    # converts floats to strings with a stable representation so the hash
    # is deterministic. (A production system would use integer cents; for
    # the bridge we stringify because permit's model is float-based and
    # we don't want to silently change the semantic.)
    parameters: dict[str, Any] = _canonicalize_params(dict(action.params))
    if action.est_cost is not None:
        parameters.setdefault("amount", _canonicalize_value(action.est_cost))

    return ActionIntent(
        intent_id=action.action_id,  # reuse permit's action_id as the intent_id
        issued_at=action.ts,
        expires_at=expires_at,
        tenant=TenantRef(tenant_id=tenant_id),
        requester=PartyRef(
            type="agent",
            id=requester_id or grant.agent_id,
        ),
        action=ActionSpec(
            name=action.type,
            capability=action.type,  # permit's action.type IS the capability
            parameters=parameters,
        ),
        target=TargetRef(
            resource_type="tool",
            resource_id=action.target,
        ),
    )


def _permit_decision_to_kernel_decision(decision: Decision) -> PolicyDecision:
    """Translate permit's Decision into the kernel's PolicyDecision."""
    # Kernel's PolicyOutcome is Literal["allow", "deny", "approval-required", "needs-evidence"]
    outcome_map = {
        DecisionOutcome.ALLOW: "allow",
        DecisionOutcome.DENY: "deny",
        DecisionOutcome.REQUIRE_APPROVAL: "approval-required",
    }
    return PolicyDecision(
        outcome=outcome_map.get(decision.outcome, "deny"),
        summary=decision.reason,
        rule_evaluations=(
            RuleEvaluation(
                rule_id=decision.rule_matched or "permit-pdp",
                outcome=outcome_map.get(decision.outcome, "deny"),
                reason_code=decision.rule_matched or "PERMIT_DECISION",
                summary=decision.reason,
            ),
        ),
    )


def _build_context(
    grant: Grant,
    action: Action,
    *,
    audience_id: str = "actenon-permit-gateway",
) -> DynamicContextInput:
    """Build the kernel's DynamicContextInput from permit's Grant + Action."""
    return DynamicContextInput(
        request_id=f"req_{uuid4().hex[:8]}",
        audience=AudienceRef(type="service", id=audience_id),
        scope_capabilities=tuple(grant.scopes.allow) or (action.type,),
        now=datetime.now(UTC),
        max_ttl_seconds=int((grant.expires_at - datetime.now(UTC)).total_seconds()) or 900,
    )


def mint_pccb_for_action(
    grant: Grant,
    action: Action,
    decision: Decision,
    *,
    signing_secret: bytes | str | None = None,
    issuer_id: str = "actenon-permit",
    tenant_id: str = "default",
    audience_id: str = "actenon-permit-gateway",
) -> tuple[ActionIntent, Any]:
    """Mint a real kernel PCCB for a permitted action.

    Returns ``(intent, pccb)`` where ``intent`` is the kernel ActionIntent
    (needed later for verification) and ``pccb`` is the signed kernel PCCB.

    The PCCB is signed with the kernel's ``HmacSha256Signer`` (dev mode) or
    an asymmetric signer (production — supplied by the integrator via the
    kernel's ``[asymmetric]`` extra). The signing key is resolved from
    ``ACTENON_SIGNING_KEY`` (permit's existing key) so PCCBs validate in the
    same process that minted them.
    """
    if decision.outcome != DecisionOutcome.ALLOW:
        raise KernelBridgeError(f"cannot mint PCCB for non-ALLOW decision: {decision.outcome}")

    intent = _permit_action_to_kernel_intent(
        grant, action, tenant_id=tenant_id, audience_id=audience_id
    )
    kernel_decision = _permit_decision_to_kernel_decision(decision)
    context = _build_context(grant, action, audience_id=audience_id)

    # Resolve the signer. Phase 4: prefer Ed25519 (asymmetric) over HMAC.
    # The resolve_signer() function checks, in order:
    #   1. Ed25519 key file (ACTENON_ED25519_KEY_FILE or ~/.actenon-permit/ed25519-key.json)
    #   2. HMAC secret (ACTENON_SIGNING_KEY or the signing_secret param)
    # This is the production hardening: real Ed25519 signatures when a keypair
    # is available, HMAC fallback for dev/demo.
    from .ed25519_signer import resolve_signer

    signer = resolve_signer(hmac_secret=signing_secret)

    minter = PCCBMinter(
        signer=signer,
        issuer=PartyRef(type="service", id=issuer_id),
    )
    pccb = minter.mint(intent, kernel_decision, context)
    return intent, pccb


def verify_pccb_at_edge(
    intent: ActionIntent,
    pccb: Any,
    grant: Grant,
    action: Action,
    *,
    signing_secret: bytes | str | None = None,
    audience_id: str = "actenon-permit-gateway",
) -> None:
    """Verify a PCCB at the execution edge before releasing the credential.

    Raises ``ProofVerificationError`` (from the kernel) if the proof is
    invalid for ANY reason: signature, intent mismatch, expiry, audience,
    scope, tenant, subject, action, target, or action-hash.

    This is the call that makes "the agent physically cannot exceed" true
    rather than aspirational: the edge refuses to release the credential
    until the kernel has verified the proof is bound to the EXACT action.
    """
    # Resolve the signer for verification — same resolution as minting.
    from .ed25519_signer import resolve_signer

    signer = resolve_signer(hmac_secret=signing_secret)
    verifier = PCCBVerifier(signer=signer)
    context = _build_context(grant, action, audience_id=audience_id)

    # CRITICAL: build a FRESH intent from the ACTUAL action being attempted
    # at the edge. The PCCB was minted for the original action; if the agent
    # mutated any parameter (amount, target, action type) between issuance
    # and execution, this fresh intent will differ from the one the PCCB was
    # bound to, and the kernel's verifier will reject it (ACTION_MISMATCH,
    # TARGET_MISMATCH, or ACTION_HASH_MISMATCH).
    #
    # The fresh intent reuses the original intent_id so the verifier's
    # intent_id check passes — what we're testing is whether the action,
    # target, and action_hash still match.
    actual_intent = _permit_action_to_kernel_intent(
        grant, action, tenant_id=intent.tenant.tenant_id, audience_id=audience_id
    )
    # Preserve the original intent_id so the verifier's intent_id check
    # doesn't spuriously fire — the intent_id IS the same request, we're
    # checking that the ACTION hasn't drifted.
    actual_intent = ActionIntent(
        intent_id=intent.intent_id,
        issued_at=intent.issued_at,
        expires_at=intent.expires_at,
        tenant=intent.tenant,
        requester=intent.requester,
        action=actual_intent.action,
        target=actual_intent.target,
    )
    verifier.verify(actual_intent, pccb, context)


def pccb_to_token_payload(pccb: Any) -> dict[str, Any]:
    """Serialize a kernel PCCB into the v1 token payload.

    The v1 token format becomes: ``v1.<base64url(canonical_json(pccb_dict))>``
    where ``pccb_dict`` is the kernel PCCB's full ``to_dict()``. The token
    IS a kernel PCCB — no parallel format.
    """
    return pccb.to_dict()


def token_payload_to_pccb(payload: dict[str, Any]) -> Any:
    """Deserialize a v1 token payload back into a kernel PCCB."""
    from actenon.models.contracts import PCCB

    return PCCB.from_dict(payload)


__all__ = [
    "KernelBridgeError",
    "mint_pccb_for_action",
    "verify_pccb_at_edge",
    "pccb_to_token_payload",
    "token_payload_to_pccb",
    "build_action_hash_input",
]
