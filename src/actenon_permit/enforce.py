"""Actenon-Permit enforcement layer — the in-process Policy Enforcement Point
(PEP).

The PEP is what the agent actually sees. A guarded tool has the same signature
as the underlying function — the agent calls it normally, and the PEP:

    1. Builds an Action from the call's args (using ``action_type``,
       ``target``, and ``cost_from`` hints).
    2. Loads the live grant state from the store (so revoke/expiry are
       honoured even if the agent has a stale grant object).
    3. Calls ``PDP.decide()``.
    4. On ALLOW: invokes the underlying fn via the broker, reconciles cost.
    5. On DENY: raises ``LeashDenied`` — the agent sees only the reason.
    6. On REQUIRE_APPROVAL: blocks until the control plane returns
       approve/deny/timeout, then re-runs from step 2.

In v0 the PEP is in-process cooperative enforcement. v1 (roadmap) moves it to
an out-of-process proxy / MCP-gateway PEP so even an agent with arbitrary
code-exec cannot import the provider SDK directly to bypass the wrapper.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from .broker import Broker, CredentialMissing, extract_cost
from .model import Action, Decision, DecisionOutcome, Grant
from .pdp import PDP, LeashDenied
from .state import StateStore

# ---------------------------------------------------------------------------
# Approval gate protocol
# ---------------------------------------------------------------------------


class ApprovalGate(Protocol):
    """How the PEP asks the control plane for a human decision.

    The default ``BlockingApprovalGate`` polls the control plane. The demo
    installs an ``AutoApproveGate`` so tests don't block.
    """

    def request(self, grant: Grant, action: Action, decision: Decision) -> bool: ...


class AutoApproveGate:
    """Approves every request immediately. Used by the demo in --auto-approve mode."""

    def request(self, grant: Grant, action: Action, decision: Decision) -> bool:  # noqa: ARG002
        return True


class BlockingApprovalGate:
    """Polls an approval store until a decision is made or timeout hits.

    ``approval_store`` is any object with ``get_status(action_id) -> 'pending'|
    'approved'|'denied'|None`` and ``create_pending(action_id, grant_id,
    action_type, reason) -> None``. ``control.py`` provides a concrete impl.
    """

    def __init__(self, approval_store: Any, timeout_seconds: float = 300.0, poll_interval: float = 0.2):
        self.store = approval_store
        self.timeout = timeout_seconds
        self.poll_interval = poll_interval

    def request(self, grant: Grant, action: Action, decision: Decision) -> bool:
        with contextlib.suppress(Exception):
            self.store.create_pending(
                action_id=action.action_id,
                grant_id=grant.id,
                action_type=action.type,
                reason=decision.reason,
            )

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            status = self.store.get_status(action.action_id)
            if status == "approved":
                return True
            if status == "denied":
                return False
            time.sleep(self.poll_interval)
        return False  # timeout -> treat as deny


# ---------------------------------------------------------------------------
# Guard registry — the PEP needs to know what tools exist
# ---------------------------------------------------------------------------


class GuardRegistry:
    """Tracks the live grant + approval gate for guarded tools."""

    def __init__(self, state: StateStore, pdp: PDP, broker: Broker):
        self.state = state
        self.pdp = pdp
        self.broker = broker
        self._grant_id: str | None = None
        self._gate: ApprovalGate = AutoApproveGate()
        self._lock = threading.RLock()

    def set_grant(self, grant_id: str) -> None:
        with self._lock:
            self._grant_id = grant_id

    def set_approval_gate(self, gate: ApprovalGate) -> None:
        with self._lock:
            self._gate = gate

    @property
    def grant_id(self) -> str | None:
        return self._grant_id

    @property
    def gate(self) -> ApprovalGate:
        return self._gate


# ---------------------------------------------------------------------------
# Decorator + wrap
# ---------------------------------------------------------------------------


def _extract_amount_from_args(
    bound_args: dict[str, Any], cost_from: str | None, params: dict[str, Any]
) -> float | None:
    """Find a numeric cost from the call args.

    Priority:
    1. ``cost_from`` names a kwarg or positional arg name; if present and
       numeric, use it.
    2. ``params['amount']`` if present and numeric.
    3. ``params['cost']`` if present and numeric.
    4. None (no estimated cost).
    """
    if cost_from and cost_from in bound_args:
        v = bound_args[cost_from]
        if isinstance(v, (int, float)):
            return float(v)
    if "amount" in params and isinstance(params["amount"], (int, float)):
        return float(params["amount"])
    if "cost" in params and isinstance(params["cost"], (int, float)):
        return float(params["cost"])
    return None


def guard(
    action_type: str,
    *,
    target: str = "",
    cost_from: str | None = None,
    credential_name: str | None = None,
    registry: GuardRegistry,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that wraps a tool function with PEP enforcement.

    The wrapped function MUST accept the resolved secret as its first
    parameter (so the broker can pass it in without the agent ever seeing it).
    Convention: ``def my_tool(secret: str, ...) -> dict``.

    Usage::

        @guard("payment.refund", target="stripe", cost_from="amount",
               credential_name="MOCK_STRIPE_KEY", registry=reg)
        def refund(secret: str, amount: float, reason: str = "") -> dict:
            ...  # call stripe with `secret`
            return {"amount": amount, "id": "ch_..."}

    The agent calls ``refund(amount=20, reason="...")`` — it never sees
    ``secret``. The PEP supplies it from the broker.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            grant_id = registry.grant_id
            if not grant_id:
                raise LeashDenied("no grant is bound to this registry")

            grant = registry.state.get_grant(grant_id)
            if grant is None:
                raise LeashDenied(f"grant {grant_id} not found in state store")

            # Bind args to the underlying signature so we can extract cost
            # by name and build a clean params dict for the Action.
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                bound_args = dict(bound.arguments)
            except TypeError:
                # Args don't bind to the signature — fail closed.
                raise LeashDenied("tool arguments do not match its signature") from None

            # The first param of the wrapped fn is the secret; do NOT put it
            # in the Action params (the agent never sees it, and it must not
            # be logged).
            secret_param_name = next(iter(sig.parameters), None)
            params = {k: v for k, v in bound_args.items() if k != secret_param_name}

            est_cost = _extract_amount_from_args(bound_args, cost_from, params)

            action = Action(
                action_id=f"act_{uuid.uuid4().hex[:16]}",
                grant_id=grant.id,
                ts=datetime.now(UTC),
                type=action_type,
                target=target or action_type,
                params={k: v for k, v in params.items() if isinstance(v, (str, int, float, bool, type(None)))},
                est_cost=est_cost,
            )

            decision = registry.pdp.decide(grant, action, ctx={})

            if decision.outcome == DecisionOutcome.DENY:
                raise LeashDenied(decision.reason, decision.rule_matched)

            if decision.outcome == DecisionOutcome.REQUIRE_APPROVAL:
                approved = registry.gate.request(grant, action, decision)
                if not approved:
                    raise LeashDenied("approval denied or timed out", decision.rule_matched)
                # Re-run decision after approval — state and clock have moved.
                # Pass approved_action_id so the PDP skips the approval-rule
                # step on this re-run (otherwise it would loop forever).
                grant = registry.state.get_grant(grant_id) or grant
                decision = registry.pdp.decide(
                    grant, action, ctx={"approved_action_id": action.action_id}
                )
                if decision.outcome != DecisionOutcome.ALLOW:
                    raise LeashDenied(decision.reason, decision.rule_matched)

            # ALLOW — invoke the real call via the broker.
            if credential_name is None:
                # No secret needed — just call the fn directly.
                result = fn(*args, **kwargs)
                actual_cost = extract_cost(result, action)
                registry.pdp.commit(grant, action, actual_cost)
                return result

            try:
                result, actual_cost = registry.broker.execute(
                    grant, action, decision, lambda s: fn(s, *args, **kwargs), credential_name
                )
            except CredentialMissing as e:
                # Fail closed — release the reservation and surface as DENY.
                if action.est_cost:
                    with contextlib.suppress(Exception):
                        registry.state.release(grant.id, action.action_id, action.est_cost)
                raise LeashDenied(f"credential missing: {e}") from e

            return result

        wrapper.__actenon_guard__ = {  # type: ignore[attr-defined]
            "action_type": action_type,
            "target": target,
            "cost_from": cost_from,
            "credential_name": credential_name,
            "original": fn,
        }
        return wrapper

    return decorator


def wrap(
    fn: Callable[..., Any],
    *,
    action_type: str,
    target: str = "",
    cost_from: str | None = None,
    credential_name: str | None = None,
    registry: GuardRegistry,
) -> Callable[..., Any]:
    """Functional equivalent of ``@guard(...)``."""
    return guard(
        action_type,
        target=target,
        cost_from=cost_from,
        credential_name=credential_name,
        registry=registry,
    )(fn)
