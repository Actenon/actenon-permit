"""Actenon-Permit: an open-source authority broker for AI agents.

Public API:
    from actenon_permit import Grant, Action, Decision
    from actenon_permit import PDP, Broker, SQLiteStore, Ledger
    from actenon_permit import guard, wrap, GuardRegistry
    from actenon_permit import compile_policy, load_policy
    # v1:
    from actenon_permit import Gateway, ToolRegistry, grant_to_token, token_to_grant
    from actenon_permit import remote_guard, RemoteGuardRegistry
    # v1.1 (Prompt 8 — brokered execution + provider adapter contract):
    from actenon_permit import (
        BrokerExecutionError,
        CredentialProvider,
        CredentialProviderRegistry,
        CredentialResolutionError,
        EnvironmentSecretProvider,
        LocalDevSecretProvider,
        CloudManagedRefProvider,
        OIDCShortLivedProvider,
        CustomerResolverProvider,
        ProviderAdapter,
        ProviderResponse,
        ValidationResult,
        AdapterError,
        UnsupportedActionError,
        InvalidParametersError,
        ProviderTimeoutError,
        ProviderPartialResponseError,
        ReconciliationConflictError,
        GitHubAdapter,
    )
"""

from __future__ import annotations

__version__ = "1.1.0"

from .adapters import (
    AdapterError,
    InvalidParametersError,
    ProviderAdapter,
    ProviderPartialResponseError,
    ProviderResponse,
    ProviderTimeoutError,
    ReconciliationConflictError,
    UnsupportedActionError,
    ValidationResult,
)
from .adapters.github import GitHubAdapter
from .broker import Broker, BrokerExecutionError, CredentialMissing, extract_cost
from .credentials import (
    CloudManagedRefProvider,
    Credential,
    CredentialProvider,
    CredentialProviderRegistry,
    CredentialResolutionError,
    CustomerResolverProvider,
    EnvironmentSecretProvider,
    LocalDevSecretProvider,
    OIDCShortLivedProvider,
)
from .enforce import (
    AutoApproveGate,
    BlockingApprovalGate,
    GuardRegistry,
    StdinApprovalGate,
    guard,
    wrap,
)
from .execution_modes import (
    BrokeredExecutionCoordinator,
    ExecutionCoordinatorError,
    ResourceOwnedSubmissionClient,
)
from .gateway import Gateway, ToolRegistry, ToolSpec, mcp_serve, mount_proxy
from .intent import (
    INTENT_TRANSITIONS,
    MAX_METADATA_BYTES,
    AuthorisedExecutionIntent,
    DurabilityProfile,
    EphemeralIntentStore,
    IntentLifecycle,
    IntentManager,
    IntentStore,
    IntentTransitionError,
    MetadataValidationError,
    SQLiteIntentStore,
    can_transition,
    store_capabilities,
    validate_metadata,
    validate_transition,
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
from .pdp import PDP, PermitApprovalRequired, PermitDenied
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

# Backward-compat aliases for the pre-rename names. The product was originally
# called "Leash" internally; it's now "Permit". These aliases keep old code
# working but the canonical names are PermitDenied / PermitApprovalRequired.
# TODO: remove these aliases in v2.0.
LeashDenied = PermitDenied
LeashApprovalRequired = PermitApprovalRequired

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
    "PermitDenied",
    "PermitApprovalRequired",
    # backward-compat aliases (pre-rename; remove in v2.0)
    "LeashDenied",
    "LeashApprovalRequired",
    # broker
    "Broker",
    "CredentialMissing",
    "extract_cost",
    # enforce (v0 in-process PEP)
    "guard",
    "wrap",
    "GuardRegistry",
    "AutoApproveGate",
    "BlockingApprovalGate",
    "StdinApprovalGate",
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
    # v1.1 (Prompt 8): credential providers + adapter contract
    "BrokerExecutionError",
    "Credential",
    "CredentialProvider",
    "CredentialProviderRegistry",
    "CredentialResolutionError",
    "CustomerResolverProvider",
    "EnvironmentSecretProvider",
    "LocalDevSecretProvider",
    "CloudManagedRefProvider",
    "OIDCShortLivedProvider",
    "ProviderAdapter",
    "ProviderResponse",
    "ValidationResult",
    "AdapterError",
    "UnsupportedActionError",
    "InvalidParametersError",
    "ProviderTimeoutError",
    "ProviderPartialResponseError",
    "ReconciliationConflictError",
    "GitHubAdapter",
    # v1.2 (Prompt 9): brokered + resource_owned execution coordinators
    "BrokeredExecutionCoordinator",
    "ResourceOwnedSubmissionClient",
    "ExecutionCoordinatorError",
    # v1.3 (Prompt 10): AuthorisedExecutionIntent + lifecycle + stores
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

