"""Actenon-Permit: an open-source authority broker for AI agents.

Public API:
    from actenon_permit import Grant, Action, Decision
    from actenon_permit import PDP, Broker, SQLiteStore, Ledger
    from actenon_permit import guard, wrap, GuardRegistry
    from actenon_permit import compile_policy, load_policy
"""

from __future__ import annotations

__version__ = "0.1.0"

from .broker import Broker, CredentialMissing
from .enforce import (
    AutoApproveGate,
    BlockingApprovalGate,
    GuardRegistry,
    guard,
    wrap,
)
from .ledger import Ledger
from .model import (
    Action,
    Budget,
    Decision,
    DecisionOutcome,
    Grant,
    GrantStatus,
    Rate,
    Scopes,
    canonical_json,
    parse_duration,
    sign,
    verify_signature,
)
from .pdp import PDP, LeashApprovalRequired, LeashDenied
from .policy import PolicyError, compile_policy, load_policy
from .state import SQLiteStore, StateError, StateStore, get_default_store

__all__ = [
    "__version__",
    # model
    "Grant",
    "Action",
    "Decision",
    "DecisionOutcome",
    "GrantStatus",
    "Scopes",
    "Budget",
    "Rate",
    "canonical_json",
    "sign",
    "verify_signature",
    "parse_duration",
    # state
    "SQLiteStore",
    "StateStore",
    "StateError",
    "get_default_store",
    # ledger
    "Ledger",
    # pdp
    "PDP",
    "LeashDenied",
    "LeashApprovalRequired",
    # broker
    "Broker",
    "CredentialMissing",
    # enforce
    "guard",
    "wrap",
    "GuardRegistry",
    "AutoApproveGate",
    "BlockingApprovalGate",
    # policy
    "compile_policy",
    "load_policy",
    "PolicyError",
]
