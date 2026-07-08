"""Actenon-Permit credential broker.

The broker is the airlock between an ALLOW decision and the real-world call.
It resolves a credential by NAME (e.g. ``"stripe_key"``) from the environment
at call time — the secret is never passed to or returned to the agent. Only
after a prior ALLOW does the broker invoke the real call, passing the secret
only to that call.

In v0 the broker is in-process. v1 (roadmap) moves it to an out-of-process
proxy / MCP-gateway PEP so even an agent with arbitrary code-exec cannot
import the provider SDK directly to bypass the wrapper.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from .model import Action, Decision, Grant
from .pdp import PDP


class CredentialMissing(RuntimeError):
    """Raised when a referenced credential name is not present in the environment."""


class Broker:
    """Resolves credentials by name and runs guarded real-world calls."""

    def __init__(self, pdp: PDP):
        self.pdp = pdp

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    @staticmethod
    def resolve(name: str) -> str:
        """Look up a credential by NAME in the environment.

        The returned value NEVER leaves the broker — it is passed only to the
        ``real_call`` callable inside ``execute``. If the env var is missing,
        raises CredentialMissing (which the PEP must surface as a DENY).
        """
        val = os.environ.get(name)
        if val is None or val == "":
            raise CredentialMissing(f"credential '{name}' is not set in the environment")
        return val

    # ------------------------------------------------------------------
    # Guarded execution
    # ------------------------------------------------------------------

    def execute(
        self,
        grant: Grant,
        action: Action,
        decision: Decision,
        real_call: Callable[[str], Any],
        credential_name: str,
    ) -> tuple[Any, float]:
        """Run ``real_call(resolved_secret)`` after a prior ALLOW.

        Returns ``(result, actual_cost)`` where ``actual_cost`` is whatever
        ``real_call`` reports (see ``cost_key`` / return contract below).

        ``real_call`` may return:
        - a dict with an ``"amount"`` key (used as actual_cost)
        - a dict with a ``"cost"`` key
        - a plain number (used as actual_cost)
        - anything else (actual_cost defaults to ``action.est_cost``)

        After the call returns, the broker reconciles cost with the PDP.
        """
        if not decision or decision.outcome.value != "ALLOW":
            raise RuntimeError("broker.execute called without a prior ALLOW")

        secret = self.resolve(credential_name)
        # The secret is a local variable. It is NEVER returned, NEVER logged,
        # NEVER passed anywhere except to real_call.
        result = real_call(secret)

        actual_cost = self._extract_cost(result, action)
        self.pdp.commit(grant, action, actual_cost)
        return result, actual_cost

    @staticmethod
    def _extract_cost(result: Any, action: Action) -> float:
        if isinstance(result, (int, float)):
            return float(result)
        if isinstance(result, dict):
            for k in ("amount", "cost", "actual_cost", "charged"):
                if k in result and isinstance(result[k], (int, float)):
                    return float(result[k])
        # Fall back to the reservation. The broker does NOT inflate cost.
        return float(action.est_cost or 0.0)
