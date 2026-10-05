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

import hashlib
import json
from datetime import UTC, datetime, timedelta
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
from actenon_protocol import is_concrete_capability

from .model import Action, Decision, DecisionOutcome, Grant


class KernelBridgeError(RuntimeError):
    """Raised when the bridge cannot translate or verify."""


# A PCCB authorises one execution, so it lives seconds-to-minutes, never as
# long as the grant: revoking a grant cannot recall a proof already minted,
# so this is the window in which a revoked grant's last proof is usable.
PCCB_TTL_SECONDS = 120

# Glob metacharacters. A proof names one concrete capability; a pattern is a
# grant scope, not something the kernel can compare exactly.


def proof_capability(grant: Grant, action: Action) -> str:
    """The single concrete capability a PCCB may carry.

    Scan-named powers and every other allow entry are matched by the PDP.
    The proof then names that one action. It does not copy the allow list,
    and it does not substitute the attempted action when the allow list is
    empty (that list is permissive at ``decide`` and would widen here).
    """
    capability = action.type
    if not is_concrete_capability(capability):
        raise KernelBridgeError(
            "proof capability must name one concrete action; a wildcard is not a capability"
        )
    if not grant.scopes.allow:
        raise KernelBridgeError(
            "empty allow-list cannot mint a proof; refusing to widen to the attempted action"
        )
    return capability


def _canonicalize_value(v: Any) -> Any:
    """Copy a typed JSON value without changing its semantic type.

    Proof parameters are JSON values, not Python coercions. In particular,
    1.0 must never become "1.0" and a tuple must not silently become a list.
    Decimal budget accounting is separate from execution parameters.
    """
    if v is None or type(v) in (str, int, bool):
        return v
    if type(v) is dict:
        if any(type(k) is not str for k in v):
            raise KernelBridgeError("proof parameters require string object keys")
        return {k: _canonicalize_value(val) for k, val in v.items()}
    if type(v) is list:
        return [_canonicalize_value(item) for item in v]
    raise KernelBridgeError("unsupported proof parameter type: " + type(v).__name__)


def _canonicalize_params(params: dict[str, Any]) -> dict[str, Any]:
    """Validate before policy and copy without an authority/dispatch coercion."""
    from actenon_protocol.canonicalisation import canonicalize_bytes

    try:
        snapshot = _canonicalize_value(params)
        # Normative limits/Unicode/integer encoding belong to Protocol.
        # Validate the owned snapshot, not caller memory that could change
        # between validation and copying.
        canonicalize_bytes(snapshot)
        return snapshot
    except (ValueError, TypeError, RecursionError) as exc:
        raise KernelBridgeError("unsupported proof parameter representation") from exc


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

    Phase 7 additions:
      - ``operation_id`` is placed in the intent's metadata so the Kernel's
        idempotency store can detect idempotent replays (Phase 6).
      - ``authority_ref`` is a stable digest of (grant_id, grant_signature,
        action_hash) that the Kernel can verify without querying Permit
        synchronously. It proves WHICH declared authority produced the proof.
      - ``execution_mode`` is set to "brokered" because Permit-issued proofs
        are used in the brokered execution path.
    """
    now = datetime.now(UTC)
    if grant.expires_at < now:
        raise KernelBridgeError(f"grant expired at {grant.expires_at}, cannot build intent")
    # The proof window starts at the action's timestamp (so the intent built
    # at mint time and the one rebuilt at the edge are identical) and is
    # PCCB_TTL_SECONDS long, bounded by the grant: never the grant's lifetime.
    expires_at = min(grant.expires_at, action.ts + timedelta(seconds=PCCB_TTL_SECONDS))
    if expires_at < now:
        raise KernelBridgeError(
            f"proof window for action {action.action_id} closed at {expires_at}"
        )

    # The action parameters are what make this "exact": the amount, the
    # reason, the target account. The kernel hashes these and the edge
    # refuses any action whose parameters don't match.
    # Exactly the action's parameters: nothing synthetic (a derived "amount"
    # would bind a value the caller never sent).
    parameters: dict[str, Any] = _canonicalize_params(dict(action.params))

    # ── Phase 7: authority_ref digest ──────────────────────────────
    # A stable digest of (grant_id, grant_signature, action_id) that the
    # Kernel can verify without querying Permit. This proves WHICH declared
    # authority produced the proof, not that the authority was correct.
    authority_ref_input = {
        "grant_id": grant.id,
        "grant_signature": grant.signature,
        "action_id": action.action_id,
        "parent_grant_id": grant.parent_grant_id,
        "delegation_depth": grant.delegation_depth,
    }
    authority_ref = (
        "authref_"
        + hashlib.sha256(
            json.dumps(authority_ref_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:32]
    )

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
        metadata={
            "operation_id": action.action_id,  # Phase 6 idempotency support
            "authority_ref": authority_ref,  # Phase 7: verifiable authority reference
            "grant_id": grant.id,  # Phase 7: grant linkage for revocation cascade
            "execution_mode": "brokered",  # Phase 7: explicit execution mode
        },
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
    # Exact capability. Grant scopes may be patterns (``payments.*``); the PDP
    # has already matched them. Kernel verifiers compare capabilities as exact
    # strings, so the proof must not carry ``*`` or the rest of the allow list.
    # An empty tuple would hit the kernel minter's ``or (intent.capability,)``
    # fallback and widen an unnamed action into the proof.
    capability = proof_capability(grant, action)
    return DynamicContextInput(
        request_id=f"req_{uuid4().hex[:8]}",
        audience=AudienceRef(type="service", id=audience_id),
        # The proof names the exact capability. Grant scopes may be patterns
        # (payments.*); the PDP has already matched them, and verifiers compare
        # capabilities exactly (actenon-protocol protocol/13 E1).
        scope_capabilities=(capability,),
        now=datetime.now(UTC),
        max_ttl_seconds=max(
            1, min(PCCB_TTL_SECONDS, int((grant.expires_at - datetime.now(UTC)).total_seconds()))
        ),
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
    prepared_intent: ActionIntent | None = None,
    effect_reference: dict[str, Any] | None = None,
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
    if not grant.verify():
        raise KernelBridgeError("grant signature could not be verified")
    proof_capability(grant, action)

    intent = prepared_intent or _permit_action_to_kernel_intent(
        grant, action, tenant_id=tenant_id, audience_id=audience_id
    )
    if effect_reference is not None:
        from actenon_protocol.types.effects import EffectReference

        EffectReference.model_validate(effect_reference)
        if intent.intent_id != effect_attempt_id(action):
            raise KernelBridgeError("effect proof must bind the actual execution attempt")
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
    # Signed, revocable authority reference: every edge must consult this
    # grant's revocation state before executing (protocol/13 E5).
    authority = {"issuer": f"service:{issuer_id}", "grant_id": grant.id, "revocable": True}
    extensions = {"authority": authority}
    if effect_reference is not None:
        extensions["effect"] = dict(effect_reference)
    pccb = minter.mint(intent, kernel_decision, context, extensions=extensions)
    return intent, pccb


def verify_pccb_at_edge(
    intent: ActionIntent,
    pccb: Any,
    grant: Grant,
    action: Action,
    *,
    signing_secret: bytes | str | None = None,
    audience_id: str = "actenon-permit-gateway",
    store: Any = None,
    effect_protector: Any = None,
) -> None:
    """Verify a PCCB at the execution edge before releasing the credential.

    ``store`` is the grant state the revocation check consults (default: the
    process's default store). A revoked grant, or a revoked ancestor, refuses
    with ``AUTHORITY_REVOKED``.

    Raises ``ProofVerificationError`` (from the kernel) if the proof is
    invalid for ANY reason: signature, intent mismatch, expiry, audience,
    scope, tenant, subject, action, target, or action-hash.

    This is the call that makes "the agent physically cannot exceed" true
    rather than aspirational: the edge refuses to release the credential
    until the kernel has verified the proof is bound to the EXACT action.
    """
    # Resolve the signer for verification — same resolution as minting.
    from .ed25519_signer import resolve_signer
    from .revocation import StoreRevocationChecker
    from .state import get_default_store

    signer = resolve_signer(hmac_secret=signing_secret)
    verifier = PCCBVerifier(
        signer=signer,
        revocation_checker=StoreRevocationChecker(
            store if store is not None else get_default_store()
        ),
    )
    context = _build_context(grant, action, audience_id=audience_id)

    # Build a FRESH intent from the ACTUAL action being attempted at the edge.
    # The fresh intent uses the CURRENT action's action_id as intent_id —
    # NOT the original. This means:
    #   - Normal flow (same action): intent_id matches → passes
    #   - Replay (different action_id): intent_id mismatches → INTENT_MISMATCH
    #   - Mutation (same action_id, different params): intent_id matches but
    #     action_hash differs → ACTION_HASH_MISMATCH
    # SECURITY: do NOT preserve the original intent_id — that would allow
    # replay attacks (found by adversarial testing).
    actual_intent = _permit_action_to_kernel_intent(
        grant, action, tenant_id=intent.tenant.tenant_id, audience_id=audience_id
    )
    if "effect" in pccb.extensions:
        from dataclasses import replace

        actual_intent = replace(actual_intent, intent_id=effect_attempt_id(action))
    verifier.verify(actual_intent, pccb, context)
    if "effect" in pccb.extensions or effect_protector is not None:
        from actenon.core.errors import ProofVerificationError
        from actenon.models.runtime import ProtectedExecutionRequest

        if effect_protector is None:
            raise ProofVerificationError(
                "POLICY_REFUSAL",
                "Effect-bearing proof requires authoritative edge ownership verification.",
            )
        effect_protector.claim_request(
            ProtectedExecutionRequest(intent=actual_intent, pccb=pccb, context=context)
        )


def build_execution_receipt(
    intent: ActionIntent,
    pccb: Any,
    grant: Grant,
    action: Action,
    evidence: dict[str, Any],
    *,
    audience_id: str = "actenon-permit-gateway",
) -> Any:
    """Build the kernel execution Receipt for a brokered action that ran.

    The receipt is linked to ``intent`` and ``pccb`` (intent id, tenant,
    subject, action, target, ``correlation.pccb_id`` and action hash), so
    ``actenon-kernel verify-receipt --receipt ... --intent ... --pccb ...``
    can check it offline. ``evidence`` must already be redacted.
    """
    from actenon.receipts import ReceiptFactory

    receipt = ReceiptFactory().create_execution_receipt(
        intent,
        _build_context(grant, action, audience_id=audience_id),
        pccb_id=pccb.pccb_id,
        escrow_id=None,
        payload=dict(evidence),
        action_hash=pccb.action_hash,
    )
    if receipt.intent_id != intent.intent_id or receipt.correlation.pccb_id != pccb.pccb_id:
        raise KernelBridgeError("execution receipt is not linked to the verified proof")
    return receipt


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
    "PCCB_TTL_SECONDS",
    "KernelBridgeError",
    "proof_capability",
    "mint_pccb_for_action",
    "verify_pccb_at_edge",
    "build_execution_receipt",
    "pccb_to_token_payload",
    "token_payload_to_pccb",
    "build_action_hash_input",
]


def effect_attempt_id(action: Action) -> str:
    """Portable execution-attempt ID, independent of the logical effect ID."""
    return "exec_" + hashlib.sha256(action.action_id.encode("utf-8")).hexdigest()[:32]


def claim_effect_at_edge(reference, request, *, store) -> bool:
    """Kernel's ledger hook; exact signed bindings are checked atomically."""
    from actenon_protocol import parse_authority_extension

    authority = parse_authority_extension(request.pccb.extensions)
    return store.claim_effect(
        reference=reference.to_dict(),
        grant_id=authority["grant_id"],
        principal=request.intent.requester.id,
        action_hash=request.pccb.action_hash.value,
    )
