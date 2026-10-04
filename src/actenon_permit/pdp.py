"""Actenon-Permit Policy Decision Point (PDP).

The PDP is the deterministic engine that decides ``ALLOW | DENY |
REQUIRE_APPROVAL`` for a given (grant, action, ctx). It is fail-closed: any
exception inside the engine resolves to ``DENY("engine error, failing
closed")``.

Decision algorithm (exact order, top-to-bottom):

    0. grant signature does not verify -> DENY("grant signature could not be verified")
    1. status != active              -> DENY
    2. now > expires_at              -> set status=expired -> DENY("expired")
    3. action matches scopes.deny    -> DENY("scope denied: <rule>")
    4. scopes.allow non-empty AND
       action not matched            -> DENY("out of scope")
    5. rate exceeded                 -> DENY("rate limit")
    6. would exceed budget           -> DENY("would exceed <currency> <limit> budget")
    7. approval_rule matches         -> REQUIRE_APPROVAL(rule)
    8. else                          -> ALLOW

An unknown action type (not matched by a non-empty allow list) is step 4.
An empty allow list stays permissive here, per SPEC §4. Minting a proof for
that case is refused separately so the empty list is not widened into the
attempted action.

On ALLOW, the PDP calls ``state.reserve(...)`` atomically (which both
decrements budget.remaining and bumps the rate counter in one transaction).
The caller is then responsible for committing the actual cost after the real
call returns.

Approval rules
--------------
Two rule shapes are supported (matching the SPEC):

- ``"email.send"``                — matches by action type (exact)
- ``"payment.refund > 20"``       — matches by type + numeric threshold on
                                    ``params['amount']`` (or ``est_cost``)
"""

from __future__ import annotations

import contextlib
import fnmatch
import math
import re
from datetime import UTC, datetime
from typing import Any

from actenon.outcomes import FailureCode

from .ledger import Ledger
from .model import Action, Decision, DecisionOutcome, Grant, GrantStatus
from .state import StateStore

# Match "type > amount" approval rules.
_THRESHOLD_RE = re.compile(r"^(?P<type>[^\s>]+)\s*>\s*(?P<amount>[0-9.]+)\s*$")


class PermitDenied(Exception):
    """Raised by the PEP when a guarded action is denied."""

    def __init__(self, reason: str, rule_matched: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.rule_matched = rule_matched


class PermitApprovalRequired(Exception):
    """Raised by the PEP when a guarded action requires human approval."""

    def __init__(self, reason: str, rule_matched: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.rule_matched = rule_matched


# Backward-compat aliases for the pre-rename names. The product was originally
# called "Leash" internally; it's now "Permit". These aliases keep old code
# working but the canonical names are PermitDenied / PermitApprovalRequired.
# Kept in 2.0.0 (tests/test_nits.py asserts them). Any removal will be announced
# in CHANGELOG.md one major version ahead.
LeashDenied = PermitDenied
LeashApprovalRequired = PermitApprovalRequired


def _scope_matches(patterns: list[str], action_type: str) -> str | None:
    """Return the first pattern in ``patterns`` that matches ``action_type``,
    else None. Matching is glob-style (``shell.*`` matches ``shell.exec``),
    falling back to exact-equality.
    """
    for p in patterns:
        if p == action_type:
            return p
        if fnmatch.fnmatch(action_type, p):
            return p
    return None


def _approval_rule_matches(rule: str, action: Action) -> bool:
    """True iff ``rule`` matches ``action``.

    - Bare type (``"email.send"``): exact match on action.type
    - Threshold (``"payment.refund > 20"``): exact match on type AND
      (params['amount'] or est_cost) > threshold. An amount that is not a
      finite number (``"abc"``, NaN, a list) cannot be shown to be under
      the threshold, so the rule matches (fail closed).
    """
    rule = rule.strip()
    m = _THRESHOLD_RE.match(rule)
    if m:
        rtype = m.group("type")
        threshold = float(m.group("amount"))
        if action.type != rtype:
            return False
        amount = action.params.get("amount")
        if amount is None:
            amount = action.est_cost or 0.0
        try:
            value = float(amount)
        except (TypeError, ValueError):
            return True
        return not math.isfinite(value) or value > threshold
    # bare type match
    return action.type == rule


def _build_authority_boundary(grant: Grant, action: Action) -> dict[str, Any]:
    """Build the authority_boundary for the ledger entry."""
    return {
        "authorized_action_hash": None,  # null if no PCCB; set by gateway path
        "attempted_action_hash": None,  # can be computed by kernel bridge
        "envelope": {
            "scopes_allow": list(grant.scopes.allow),
            "scopes_deny": list(grant.scopes.deny),
            "budget_remaining_at_decision": float(grant.budget.remaining),
            "expires_at": grant.expires_at.isoformat(),
            "rate_max": grant.rate.max,
            "rate_per_seconds": grant.rate.per_seconds,
        },
    }


class PDP:
    """Policy Decision Point. Stateless except for the state-store and ledger
    references it consults for rate/budget counting and audit logging.
    """

    def __init__(self, state: StateStore, ledger: Ledger):
        self.state = state
        self.ledger = ledger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decide(
        self,
        grant: Grant,
        action: Action,
        ctx: dict[str, Any] | None = None,
        *,
        _effect_reservation: dict[str, Any] | None = None,
    ) -> Decision:
        """Run the decision algorithm. Fail-closed on any exception."""
        ctx = ctx or {}
        try:
            return self._decide_inner(grant, action, ctx, _effect_reservation=_effect_reservation)
        except Exception as e:  # noqa: BLE001 — fail-closed is the contract
            # Try to record the failure in the ledger too.
            with contextlib.suppress(Exception):
                self.ledger.append(
                    action_id=action.action_id,
                    grant_id=action.grant_id,
                    ts=action.ts,
                    action_type=action.type,
                    target=action.target,
                    params=action.params,
                    est_cost=action.est_cost,
                    outcome=DecisionOutcome.DENY.value,
                    reason=f"engine error, failing closed: {type(e).__name__}: {e}",
                    rule_matched=None,
                    state_delta={},
                    failure_code=FailureCode.ENGINE_ERROR,
                    authority_boundary=_build_authority_boundary(grant, action),
                )
            return Decision(
                outcome=DecisionOutcome.DENY,
                reason=f"engine error, failing closed: {type(e).__name__}: {e}",
                rule_matched=None,
                state_delta={},
                failure_code=FailureCode.ENGINE_ERROR,
            )

    # ------------------------------------------------------------------
    # Inner decision
    # ------------------------------------------------------------------

    def _decide_inner(
        self,
        grant: Grant,
        action: Action,
        ctx: dict[str, Any],
        *,
        _effect_reservation: dict[str, Any] | None = None,
    ) -> Decision:
        # 0. Signature over the authority fields. Live status and remaining
        # budget are not signed; a tampered scope, cap, or stripped signature
        # is not authority and must not reach a later ALLOW.
        if not grant.verify():
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason="grant signature could not be verified",
                rule_matched="signature",
                failure_code=FailureCode.SIGNATURE_INVALID,
            )
            self.ledger.append(
                action_id=action.action_id,
                grant_id=grant.id,
                ts=action.ts,
                action_type=action.type,
                target=action.target,
                params=action.params,
                est_cost=action.est_cost,
                outcome=d.outcome.value,
                reason=d.reason,
                rule_matched=d.rule_matched,
                state_delta={},
                failure_code=d.failure_code,
                authority_boundary=_build_authority_boundary(grant, action),
            )
            return d

        # 1. status check
        if grant.status != GrantStatus.ACTIVE:
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason=f"grant status is {grant.status.value}",
                rule_matched="status",
                failure_code=(
                    FailureCode.REVOKED
                    if grant.status == GrantStatus.REVOKED
                    else FailureCode.NOT_ACTIVE
                ),
            )
            self.ledger.append(
                action_id=action.action_id,
                grant_id=grant.id,
                ts=action.ts,
                action_type=action.type,
                target=action.target,
                params=action.params,
                est_cost=action.est_cost,
                outcome=d.outcome.value,
                reason=d.reason,
                rule_matched=d.rule_matched,
                state_delta={},
                failure_code=d.failure_code,
                authority_boundary=_build_authority_boundary(grant, action),
            )
            return d

        # 2. expiry check — if expired, transition the grant
        now = datetime.now(UTC)
        if now > grant.expires_at:
            with contextlib.suppress(Exception):
                self.state.set_status(grant.id, GrantStatus.EXPIRED)
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason="expired",
                rule_matched="expiry",
                state_delta={"status": "expired"},
                failure_code=FailureCode.EXPIRED,
            )
            self.ledger.append(
                action_id=action.action_id,
                grant_id=grant.id,
                ts=action.ts,
                action_type=action.type,
                target=action.target,
                params=action.params,
                est_cost=action.est_cost,
                outcome=d.outcome.value,
                reason=d.reason,
                rule_matched=d.rule_matched,
                state_delta=d.state_delta,
                failure_code=d.failure_code,
                authority_boundary=_build_authority_boundary(grant, action),
            )
            return d

        # 3. deny scopes
        matched_deny = _scope_matches(grant.scopes.deny, action.type)
        if matched_deny is not None:
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason=f"scope denied: {matched_deny}",
                rule_matched=f"deny:{matched_deny}",
                failure_code=FailureCode.SCOPE_DENIED,
            )
            self.ledger.append(
                action_id=action.action_id,
                grant_id=grant.id,
                ts=action.ts,
                action_type=action.type,
                target=action.target,
                params=action.params,
                est_cost=action.est_cost,
                outcome=d.outcome.value,
                reason=d.reason,
                rule_matched=d.rule_matched,
                state_delta={},
                failure_code=d.failure_code,
                authority_boundary=_build_authority_boundary(grant, action),
            )
            return d

        # 4. allow scopes (default-deny when allow is non-empty)
        if grant.scopes.allow:
            matched_allow = _scope_matches(grant.scopes.allow, action.type)
            if matched_allow is None:
                d = Decision(
                    outcome=DecisionOutcome.DENY,
                    reason="out of scope",
                    rule_matched="allow:default-deny",
                    failure_code=FailureCode.OUT_OF_SCOPE,
                )
                self.ledger.append(
                    action_id=action.action_id,
                    grant_id=grant.id,
                    ts=action.ts,
                    action_type=action.type,
                    target=action.target,
                    params=action.params,
                    est_cost=action.est_cost,
                    outcome=d.outcome.value,
                    reason=d.reason,
                    rule_matched=d.rule_matched,
                    state_delta={},
                    failure_code=d.failure_code,
                    authority_boundary=_build_authority_boundary(grant, action),
                )
                return d

        # 5. rate limit (consult state store — it's the authority for live
        # counters). We also pass it through reserve() below for the atomic
        # check, but doing a pre-check here gives a clean DENY reason without
        # touching budget.
        if grant.rate.max > 0:
            n = self.state.rate_count(grant.id, grant.rate.per_seconds)
            if n >= grant.rate.max:
                d = Decision(
                    outcome=DecisionOutcome.DENY,
                    reason="rate limit",
                    rule_matched=f"rate:{grant.rate.max}/{grant.rate.per_seconds}s",
                    failure_code=FailureCode.RATE_LIMITED,
                )
                self.ledger.append(
                    action_id=action.action_id,
                    grant_id=grant.id,
                    ts=action.ts,
                    action_type=action.type,
                    target=action.target,
                    params=action.params,
                    est_cost=action.est_cost,
                    outcome=d.outcome.value,
                    reason=d.reason,
                    rule_matched=d.rule_matched,
                    state_delta={},
                    failure_code=d.failure_code,
                    authority_boundary=_build_authority_boundary(grant, action),
                )
                return d

        # Protected effects never use the legacy caller's action-id approval
        # shortcut. Exact signed single-use approval is a separate contract.
        # Until supplied, a matching human rule remains REQUIRE_APPROVAL;
        # neither an effect nor budget is reserved for a waiting request.
        if _effect_reservation is not None:
            for rule in grant.approval_rules:
                if _approval_rule_matches(rule, action):
                    d = Decision(
                        outcome=DecisionOutcome.REQUIRE_APPROVAL,
                        reason=f"exact effect approval required: {rule}",
                        rule_matched=f"approval:{rule}",
                        state_delta={},
                        failure_code=FailureCode.APPROVAL_REQUIRED,
                    )
                    self.ledger.append(
                        action_id=action.action_id,
                        grant_id=grant.id,
                        ts=action.ts,
                        action_type=action.type,
                        target=action.target,
                        params=action.params,
                        est_cost=action.est_cost,
                        outcome=d.outcome.value,
                        reason=d.reason,
                        rule_matched=d.rule_matched,
                        state_delta={},
                        failure_code=d.failure_code,
                        authority_boundary=_build_authority_boundary(grant, action),
                    )
                    return d

        # 6 + reserve. Atomic reserve-then-record. If reserve fails, it
        # failed because of budget or a race — DENY with the reason reserve
        # returned.
        est_cost = action.est_cost or 0.0
        if _effect_reservation is not None:
            ok, reserve_reason, snapshot = self.state.reserve_effect(
                grant_id=grant.id,
                amount=est_cost,
                rate_max=grant.rate.max,
                rate_per_seconds=grant.rate.per_seconds,
                **_effect_reservation,
            )
        else:
            ok, reserve_reason, snapshot = self.state.reserve(
                grant_id=grant.id,
                action_id=action.action_id,
                amount=est_cost,
                rate_max=grant.rate.max,
                rate_per_seconds=grant.rate.per_seconds,
            )
        if not ok:
            # Map the reserve_reason onto a structured FailureCode so callers
            # and the ledger get a stable taxonomy, not free-text prose.
            r = (reserve_reason or "").lower()
            if "revoked" in r:
                fc = FailureCode.REVOKED
            elif "rate limit" in r:
                fc = FailureCode.RATE_LIMITED
            elif "budget" in r or "exceed" in r:
                fc = FailureCode.BUDGET_EXCEEDED
            else:
                fc = FailureCode.ENGINE_ERROR
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason=reserve_reason,
                rule_matched="reserve",
                state_delta=snapshot,
                failure_code=fc,
            )
            self.ledger.append(
                action_id=action.action_id,
                grant_id=grant.id,
                ts=action.ts,
                action_type=action.type,
                target=action.target,
                params=action.params,
                est_cost=action.est_cost,
                outcome=d.outcome.value,
                reason=d.reason,
                rule_matched=d.rule_matched,
                state_delta=snapshot,
                failure_code=d.failure_code,
                authority_boundary=_build_authority_boundary(grant, action),
            )
            return d

        # 7. approval rules — check AFTER budget reserve so the agent can't
        # spam approval requests to exhaust the budget. But we DO need to
        # release the reservation if we're going to REQUIRE_APPROVAL, because
        # the action isn't actually firing yet — it will re-reserve when the
        # human approves and we re-run from step 1.
        #
        # Skip this check entirely when ctx["approved_action_id"] == action_id,
        # which is what the PEP sets after the human approves — otherwise the
        # re-run would just return REQUIRE_APPROVAL again.
        approved_action_id = ctx.get("approved_action_id") if ctx else None
        skip_approval = approved_action_id == action.action_id

        if not skip_approval:
            for rule in grant.approval_rules:
                if _approval_rule_matches(rule, action):
                    # Release the reservation AND the rate_events row — the
                    # action hasn't fired, and re-running decide() after
                    # approval would otherwise collide on the rate_events
                    # action_id PRIMARY KEY.
                    with contextlib.suppress(Exception):
                        self.state.release(grant.id, action.action_id, est_cost)
                    d = Decision(
                        outcome=DecisionOutcome.REQUIRE_APPROVAL,
                        reason=f"approval required: {rule}",
                        rule_matched=f"approval:{rule}",
                        state_delta={"released": est_cost},
                        failure_code=FailureCode.APPROVAL_REQUIRED,
                    )
                    self.ledger.append(
                        action_id=action.action_id,
                        grant_id=grant.id,
                        ts=action.ts,
                        action_type=action.type,
                        target=action.target,
                        params=action.params,
                        est_cost=action.est_cost,
                        outcome=d.outcome.value,
                        reason=d.reason,
                        rule_matched=d.rule_matched,
                        state_delta=d.state_delta,
                        failure_code=d.failure_code,
                        authority_boundary=_build_authority_boundary(grant, action),
                    )
                    return d

        # 8. ALLOW
        d = Decision(
            outcome=DecisionOutcome.ALLOW,
            reason="allowed",
            rule_matched=None,
            state_delta=snapshot,
            failure_code=FailureCode.ALLOWED,
        )
        self.ledger.append(
            action_id=action.action_id,
            grant_id=grant.id,
            ts=action.ts,
            action_type=action.type,
            target=action.target,
            params=action.params,
            est_cost=action.est_cost,
            outcome=d.outcome.value,
            reason=d.reason,
            rule_matched=d.rule_matched,
            state_delta=snapshot,
            failure_code=d.failure_code,
            authority_boundary=_build_authority_boundary(grant, action),
        )
        return d

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------

    def commit(self, grant: Grant, action: Action, actual_cost: float) -> float:
        """Commit the actual cost of an ALLOWED action and return new remaining.

        Called by the broker after the real-world call returns. Releases the
        difference between the reservation (action.est_cost) and the actual
        cost back to the grant's budget.
        """
        reserved = action.est_cost or 0.0
        return self.state.commit(grant.id, action.action_id, actual_cost, reserved)

    # ------------------------------------------------------------------
    # Kernel PCCB emission (the spine wire)
    # ------------------------------------------------------------------

    def decide_and_mint_pccb(
        self,
        grant: Grant,
        action: Action,
        ctx: dict[str, Any] | None = None,
        *,
        effect_namespace: str | None = None,
        effect_descriptor_builder: Any = None,
    ) -> tuple[Decision, Any, Any]:
        """Run the decision algorithm AND, on ALLOW, mint a kernel PCCB.

        Returns ``(decision, intent, pccb)``. On non-ALLOW outcomes,
        ``intent`` and ``pccb`` are ``None``.

        The PCCB is the kernel-signed proof bound to the exact action. The
        gateway verifies it before broker release — see
        ``kernel_bridge.verify_pccb_at_edge``.

        This method is the concrete implementation of ARCHITECTURE.md §3:
        permit issues real kernel PCCBs, not parallel HMAC grants.
        """
        from .kernel_bridge import KernelBridgeError, build_action_hash_input, proof_capability

        if grant.verify():
            # Refuse an unmintable capability before decide() reserves budget.
            # Unmatched concrete actions fall through so the reason stays
            # "out of scope". Unsigned grants fall through to the signature DENY.
            try:
                proof_capability(grant, action)
            except KernelBridgeError as exc:
                d = Decision(
                    outcome=DecisionOutcome.DENY,
                    reason=str(exc),
                    rule_matched="proof:capability",
                    failure_code=FailureCode.OUT_OF_SCOPE,
                )
                self.ledger.append(
                    action_id=action.action_id,
                    grant_id=grant.id,
                    ts=action.ts,
                    action_type=action.type,
                    target=action.target,
                    params=action.params,
                    est_cost=action.est_cost,
                    outcome=d.outcome.value,
                    reason=d.reason,
                    rule_matched=d.rule_matched,
                    state_delta={},
                    failure_code=d.failure_code,
                    authority_boundary=_build_authority_boundary(grant, action),
                )
                return d, None, None

        effect_reservation = None
        prepared_intent = None
        if effect_namespace is not None:
            # Trusted adapter configuration derives identity. Nothing in ctx
            # or the agent's nonce can choose the resource-owner namespace.
            try:
                from actenon.proof.canonical import sha256_hex
                from actenon_protocol.effects import EFFECT_PROFILE, effect_identity

                from .kernel_bridge import _permit_action_to_kernel_intent, effect_attempt_id

                prepared_intent = _permit_action_to_kernel_intent(grant, action)
                from dataclasses import replace

                prepared_intent = replace(prepared_intent, intent_id=effect_attempt_id(action))
                descriptor = {
                    "profile": EFFECT_PROFILE,
                    "namespace": effect_namespace,
                    "kind": "exact",
                    "action_type": prepared_intent.action.capability,
                    "target": {
                        "type": prepared_intent.target.resource_type,
                        "id": prepared_intent.target.resource_id,
                    },
                    "parameters": prepared_intent.action.parameters,
                }
                if effect_descriptor_builder is not None:
                    from actenon_protocol.canonicalisation import canonicalize_bytes

                    expected = descriptor
                    descriptor = dict(effect_descriptor_builder(prepared_intent))
                    for field in ("profile", "namespace", "action_type", "target"):
                        if canonicalize_bytes(descriptor.get(field)) != canonicalize_bytes(
                            expected[field]
                        ):
                            raise ValueError("effect descriptor changed the exact request")
                    if descriptor.get("kind") == "exact" and canonicalize_bytes(
                        descriptor.get("parameters")
                    ) != canonicalize_bytes(expected["parameters"]):
                        raise ValueError("exact descriptor dropped consequential parameters")
                effect_identity(descriptor)  # refuse malformed before debit
                effect_reservation = {
                    "action_id": prepared_intent.intent_id,
                    "descriptor": descriptor,
                    "action_hash": sha256_hex(build_action_hash_input(prepared_intent)),
                    "principal": prepared_intent.requester.id,
                }
            except Exception:
                return (
                    Decision(
                        outcome=DecisionOutcome.DENY,
                        reason="effect identity could not be derived — failing closed",
                        rule_matched="effect:identity",
                        failure_code=FailureCode.ENGINE_ERROR,
                    ),
                    None,
                    None,
                )
        elif effect_descriptor_builder is not None:
            return (
                Decision(
                    outcome=DecisionOutcome.DENY,
                    reason="effect namespace must be owner configured",
                    rule_matched="effect:namespace",
                    failure_code=FailureCode.ENGINE_ERROR,
                ),
                None,
                None,
            )

        decision = self.decide(grant, action, ctx, _effect_reservation=effect_reservation)
        if decision.outcome != DecisionOutcome.ALLOW:
            return decision, None, None

        # Import here so the kernel dep is only required when PCCB emission
        # is actually used (keeps `permit demo` working even if the kernel
        # isn't installed, for the v0 in-process path).
        from .kernel_bridge import mint_pccb_for_action

        try:
            if prepared_intent is not None:
                intent, pccb = mint_pccb_for_action(
                    grant,
                    action,
                    decision,
                    prepared_intent=prepared_intent,
                    effect_reference=decision.state_delta["effect"],
                )
            else:
                intent, pccb = mint_pccb_for_action(grant, action, decision)
            return decision, intent, pccb
        except Exception:
            # If the kernel bridge fails for ANY reason (including
            # JSONInputTooLargeError from oversized params), fail closed:
            # downgrade the decision to DENY. We never release a credential
            # without a valid PCCB. Found by adversarial testing (round 3).
            return (
                Decision(
                    outcome=DecisionOutcome.DENY,
                    reason="PCCB emission failed — failing closed",
                    rule_matched="kernel_bridge:emission_failed",
                    state_delta=decision.state_delta,
                    failure_code=FailureCode.ENGINE_ERROR,
                ),
                None,
                None,
            )
