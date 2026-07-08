"""Actenon-Permit: an open-source authority broker for AI agents.

Public API:
    from actenon_permit import Grant, Action, Decision
    from actenon_permit import PDP, Broker, SQLiteStore, Ledger
    from actenon_permit import guard, wrap, GuardRegistry
    from actenon_permit import compile_policy, load_policy
    # v1:
    from actenon_permit import Gateway, ToolRegistry, grant_to_token, token_to_grant
    from actenon_permit import remote_guard, RemoteGuardRegistry
"""

from __future__ import annotations

__version__ = "1.0.0"

from .broker import Broker, CredentialMissing
from .enforce import (
    AutoApproveGate,
    BlockingApprovalGate,
    GuardRegistry,
    guard,
    wrap,
)
from .gateway import Gateway, ToolRegistry, ToolSpec, mcp_serve, mount_proxy
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
from .pep_client import (
    RemoteGuardDenied,
    RemoteGuardError,
    RemoteGuardRegistry,
    remote_guard,
    remote_wrap,
)
from .policy import PolicyError, compile_policy, load_policy
from .state import SQLiteStore, StateError, StateStore, get_default_store
from .token import TokenError, grant_to_token, token_to_grant

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
    # enforce (v0 in-process PEP)
    "guard",
    "wrap",
    "GuardRegistry",
    "AutoApproveGate",
    "BlockingApprovalGate",
    # policy
    "compile_policy",
    "load_policy",
    "PolicyError",
    # v1: token wire format
    "grant_to_token",
    "token_to_grant",
    "TokenError",
    # v1: out-of-process gateway
    "Gateway",
    "ToolRegistry",
    "ToolSpec",
    "mount_proxy",
    "mcp_serve",
    # v1: remote PEP client
    "remote_guard",
    "remote_wrap",
    "RemoteGuardRegistry",
    "RemoteGuardError",
    "RemoteGuardDenied",
]
