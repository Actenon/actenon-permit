"""Actenon-Permit Policy Decision Point (PDP).

The PDP is the deterministic engine that decides ``ALLOW | DENY |
REQUIRE_APPROVAL`` for a given (grant, action, ctx). It is fail-closed: any
exception inside the engine resolves to ``DENY("engine error, failing
closed")``.

Decision algorithm (exact order, top-to-bottom):

    1. status != active              -> DENY
    2. now > expires_at              -> set status=expired -> DENY("expired")
    3. action matches scopes.deny    -> DENY("scope denied: <rule>")
    4. scopes.allow non-empty AND
       action not matched            -> DENY("out of scope")
    5. rate exceeded                 -> DENY("rate limit")
    6. would exceed budget           -> DENY("would exceed <currency> <limit> budget")
    7. approval_rule matches         -> REQUIRE_APPROVAL(rule)
    8. else                          -> ALLOW

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
import re
from datetime import UTC, datetime
from typing import Any

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
# TODO: remove these aliases in v2.0.
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
      (params['amount'] or est_cost) > threshold
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
            return float(amount) > threshold
        except (TypeError, ValueError):
            return False
    # bare type match
    return action.type == rule


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

    def decide(self, grant: Grant, action: Action, ctx: dict[str, Any] | None = None) -> Decision:
        """Run the decision algorithm. Fail-closed on any exception."""
        ctx = ctx or {}
        try:
            return self._decide_inner(grant, action, ctx)
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
                )
            return Decision(
                outcome=DecisionOutcome.DENY,
                reason=f"engine error, failing closed: {type(e).__name__}: {e}",
                rule_matched=None,
                state_delta={},
            )

    # ------------------------------------------------------------------
    # Inner decision
    # ------------------------------------------------------------------

    def _decide_inner(self, grant: Grant, action: Action, ctx: dict[str, Any]) -> Decision:
        # 1. status check
        if grant.status != GrantStatus.ACTIVE:
            return Decision(
                outcome=DecisionOutcome.DENY,
                reason=f"grant status is {grant.status.value}",
                rule_matched="status",
            )

        # 2. expiry check — if expired, transition the grant
        now = datetime.now(UTC)
        if now > grant.expires_at:
            with contextlib.suppress(Exception):
                self.state.set_status(grant.id, GrantStatus.EXPIRED)
            self.ledger.append(
                action_id=action.action_id,
                grant_id=grant.id,
                ts=action.ts,
                action_type=action.type,
                target=action.target,
                params=action.params,
                est_cost=action.est_cost,
                outcome=DecisionOutcome.DENY.value,
                reason="expired",
                rule_matched="expiry",
                state_delta={"status": "expired"},
            )
            return Decision(
                outcome=DecisionOutcome.DENY,
                reason="expired",
                rule_matched="expiry",
                state_delta={"status": "expired"},
            )

        # 3. deny scopes
        matched_deny = _scope_matches(grant.scopes.deny, action.type)
        if matched_deny is not None:
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason=f"scope denied: {matched_deny}",
                rule_matched=f"deny:{matched_deny}",
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
                )
                return d

        # 6 + reserve. Atomic reserve-then-record. If reserve fails, it
        # failed because of budget or a race — DENY with the reason reserve
        # returned.
        est_cost = action.est_cost or 0.0
        ok, reserve_reason, snapshot = self.state.reserve(
            grant_id=grant.id,
            action_id=action.action_id,
            amount=est_cost,
            rate_max=grant.rate.max,
            rate_per_seconds=grant.rate.per_seconds,
        )
        if not ok:
            d = Decision(
                outcome=DecisionOutcome.DENY,
                reason=reserve_reason,
                rule_matched="reserve",
                state_delta=snapshot,
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
                    )
                    return d

        # 8. ALLOW
        d = Decision(
            outcome=DecisionOutcome.ALLOW,
            reason="allowed",
            rule_matched=None,
            state_delta=snapshot,
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
        decision = self.decide(grant, action, ctx)
        if decision.outcome != DecisionOutcome.ALLOW:
            return decision, None, None

        # Import here so the kernel dep is only required when PCCB emission
        # is actually used (keeps `permit demo` working even if the kernel
        # isn't installed, for the v0 in-process path).
        from .kernel_bridge import KernelBridgeError, mint_pccb_for_action

        try:
            intent, pccb = mint_pccb_for_action(grant, action, decision)
            return decision, intent, pccb
        except KernelBridgeError:
            # If the kernel bridge fails, fail closed: downgrade the decision
            # to DENY. We never release a credential without a valid PCCB.
            return (
                Decision(
                    outcome=DecisionOutcome.DENY,
                    reason="PCCB emission failed — failing closed",
                    rule_matched="kernel_bridge:emission_failed",
                    state_delta=decision.state_delta,
                ),
                None,
                None,
            )
