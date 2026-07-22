"""Actenon client — the main entry point for the SDK.

Provides ``Actenon.local()`` for in-process execution and
``Actenon.cloud()`` for HTTP transport to a Cloud-managed gateway.

The client is synchronous. An async variant is available via
``Actenon.async_local()`` (returns an ``AsyncActenonClient``).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import warnings
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import CapabilityInfo, CloudTransportConfig, LocalRuntimeConfig
from .exceptions import (
    ActenonError,
    ExecutionFailedError,
    ExecutionRefusedError,
    OutcomeUnknownError,
)
from .models import (
    BrokeredResult,
    ExecutionResult,
    IntentHandle,
    ResourceOwnedResult,
)


class _AuthorisedExecutionIntentsAPI:
    """The ``client.authorised_execution_intents`` namespace.

    Provides ``create()`` which returns an ``IntentHandle``. The handle
    has ``.execute()`` and ``.submit_to_resource()`` methods.
    """

    def __init__(self, client: ActenonClient) -> None:
        self._client = client

    def create(
        self,
        *,
        action: str,
        target: str,
        parameters: dict[str, Any] | None = None,
        requested_execution_mode: str = "brokered",
        idempotency_key: str | None = None,
        expiry_seconds: int = 3600,
        metadata: dict[str, Any] | None = None,
    ) -> IntentHandle:
        """Create a new AuthorisedExecutionIntent.

        Returns an ``IntentHandle`` with ``.execute()`` and
        ``.submit_to_resource()`` methods.
        """
        return self._client._create_intent(
            action=action,
            target=target,
            parameters=parameters or {},
            requested_execution_mode=requested_execution_mode,
            idempotency_key=idempotency_key,
            expiry_seconds=expiry_seconds,
            metadata=metadata or {},
        )


class ActenonClient:
    """Base client. Use ``Actenon.local()`` or ``Actenon.cloud()`` to construct."""

    def __init__(self) -> None:
        self.authorised_execution_intents = _AuthorisedExecutionIntentsAPI(self)

    def _create_intent(self, **kwargs: Any) -> IntentHandle:
        raise NotImplementedError

    def _execute_intent(self, intent_id: str) -> ExecutionResult:
        raise NotImplementedError

    def _submit_intent(self, intent_id: str, proof: dict[str, Any]) -> ExecutionResult:
        raise NotImplementedError

    @property
    def capabilities(self) -> CapabilityInfo:
        raise NotImplementedError


class LocalActenonClient(ActenonClient):
    """In-process client. Uses a Permit Gateway with adapters.

    This is the default for local development and self-hosted Permit.
    """

    def __init__(self, config: LocalRuntimeConfig) -> None:
        super().__init__()
        self._config = config
        self._setup_gateway()

    def _setup_gateway(self) -> None:
        cfg = self._config

        # Lazy imports to avoid circular dependency at package load time.
        from .. import (
            PDP,
            AutoApproveGate,
            Broker,
            CredentialProviderRegistry,
            EphemeralIntentStore,
            Gateway,
            IntentManager,
            Ledger,
            SQLiteStore,
            ToolRegistry,
        )
        from ..model import Budget, Grant, Rate, Scopes
        from ..token import grant_to_token

        # Set signing key (or generate ephemeral with warning).
        if cfg.signing_key:
            os.environ["ACTENON_SIGNING_KEY"] = cfg.signing_key

        # State store.
        state_path = cfg.intent_store_path or ":memory:"
        if state_path == ":memory:":
            # Use a temp file for SQLite (Permit's SQLiteStore needs a path).
            import tempfile

            state_path = tempfile.mktemp(suffix=".db")
        self._state = SQLiteStore(state_path)
        self._ledger = Ledger(self._state)
        self._pdp = PDP(self._state, self._ledger)

        # Credential provider (development-only local secrets).
        self._cred_registry = CredentialProviderRegistry()

        # Broker.
        self._broker = Broker(
            self._pdp,
            credential_providers=self._cred_registry,
            production_mode=cfg.production_mode,
        )

        # Tool registry.
        self._tools = ToolRegistry()

        # Intent store (ephemeral by default).
        self._intent_store = EphemeralIntentStore()
        self._intent_manager = IntentManager(store=self._intent_store)

        # Gateway.
        self._gateway = Gateway(
            state=self._state,
            ledger=self._ledger,
            pdp=self._pdp,
            broker=self._broker,
            tools=self._tools,
            approval_gate=AutoApproveGate(),
            intent_manager=self._intent_manager,
        )

        # Issue a grant for this agent.
        self._grant = Grant(
            agent_id=cfg.agent_id,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=24),
            scopes=Scopes(allow=cfg.scopes),
            budget=Budget(currency=cfg.budget_currency, limit=cfg.budget_limit, remaining=cfg.budget_limit),
            rate=Rate(max=100, per_seconds=60),
        )
        self._grant.sign()
        self._state.put_grant(self._grant)
        self._grant_token = grant_to_token(self._grant)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_credential(self, ref: str, value: str, *, development_only: bool = True) -> None:
        """Register a credential for brokered execution.

        MARKED DEVELOPMENT-ONLY by default. The broker will refuse
        development-only credentials in production_mode.

        For production, use environment-injected or Cloud-managed
        credentials instead.
        """
        from .. import LocalDevSecretProvider

        provider = LocalDevSecretProvider({ref: value})
        self._cred_registry.register(ref, provider)
        if development_only:
            warnings.warn(
                f"register_credential('{ref}', ...) is development-only. "
                f"The credential is stored in process memory and will be "
                f"refused in production_mode. For production, use "
                f"EnvironmentSecretProvider or CloudManagedRefProvider.",
                stacklevel=2,
            )

    def register_adapter_tool(
        self,
        name: str,
        *,
        action_type: str,
        adapter: Any,
        credential_ref: str,
        target: str = "",
    ) -> None:
        """Register an adapter-backed tool for brokered execution."""
        self._tools.register_adapter_tool(
            name,
            action_type=action_type,
            adapter=adapter,
            credential_ref=credential_ref,
            target=target or action_type,
        )

    def register_resource_client(self, resource_id: str, client: Any) -> None:
        """Register a ResourceOwnedSubmissionClient for resource-owned execution."""
        self._gateway.register_resource_client(resource_id, client)

    @property
    def capabilities(self) -> CapabilityInfo:
        return CapabilityInfo(
            transport="local",
            supports_brokered=True,
            supports_resource_owned=len(self._gateway.resource_clients) > 0,
            supports_async=True,
            supports_polling=False,  # ephemeral store
            durable=self._config.intent_store_path is not None,
            production_mode=self._config.production_mode,
        )

    # ------------------------------------------------------------------
    # Internal: intent create / execute / submit
    # ------------------------------------------------------------------

    def _create_intent(self, **kwargs: Any) -> IntentHandle:
        # Translate SDK parameter names to IntentManager parameter names.
        mgr_kwargs = {
            "action_type": kwargs["action"],
            "action_params": kwargs["parameters"],
            "target_type": "unknown",
            "target_id": kwargs["target"],
            "requested_execution_mode": kwargs["requested_execution_mode"],
            "requester_subject": self._config.agent_id if hasattr(self, "_config") else "sdk-client",
            "requester_agent_id": self._config.agent_id if hasattr(self, "_config") else "sdk-client",
            "idempotency_key": kwargs.get("idempotency_key"),
            "expiry_seconds": kwargs.get("expiry_seconds", 3600),
            "metadata": kwargs.get("metadata", {}),
        }
        intent = self._intent_manager.create(**mgr_kwargs)
        return IntentHandle(
            intent_id=intent.intent_id,
            lifecycle_state=intent.lifecycle_state.value,
            _client=self,
        )

    def _execute_intent(self, intent_id: str) -> ExecutionResult:
        response = self._gateway.execute_intent(intent_id, grant_token=self._grant_token)
        return self._map_response_to_result(intent_id, response)

    def _submit_intent(self, intent_id: str, proof: dict[str, Any]) -> ExecutionResult:
        response = self._gateway.submit_intent_to_resource(intent_id, proof=proof)
        return self._map_response_to_result(intent_id, response)

    @staticmethod
    def _map_response_to_result(intent_id: str, response: dict[str, Any]) -> ExecutionResult:
        """Map a gateway response dict to a typed ExecutionResult.

        Raises structured exceptions for non-succeeded states.
        """
        state = response.get("execution_state")
        mode = response.get("execution_mode", "brokered")

        # If the gateway returned a plain DENY without execution_state
        # (e.g. PDP denial, unknown intent, token error), raise
        # ExecutionRefusedError with the gateway's reason.
        if state is None:
            raise ExecutionRefusedError(
                response.get("reason", "execution refused"),
                rule=response.get("rule_matched"),
                reason=response.get("reason", ""),
            )

        if mode == "brokered":
            result = BrokeredResult(
                intent_id=intent_id,
                state=state,
                finality=response.get("finality", "non_final"),
                provider_execution_observed=response.get("provider_execution_observed", False),
                receipt_received=response.get("receipt_received", False),
                receipt_verified=response.get("receipt_verified", False),
                evidence=response.get("result", {}),
                attempt_id=response.get("intent", {}).get("linked_attempt_ids", [None])[0]
                if response.get("intent", {}).get("linked_attempt_ids")
                else None,
            )
        else:
            result = ResourceOwnedResult(
                intent_id=intent_id,
                state=state,
                finality=response.get("finality", "non_final"),
                provider_execution_observed=response.get("provider_execution_observed", False),
                resource_receipt_received=response.get("resource_receipt_received", False),
                resource_receipt_verified=response.get("resource_receipt_verified", False),
                submission_reference=response.get("submission_reference"),
                evidence=response.get("result", {}),
                attempt_id=response.get("intent", {}).get("linked_attempt_ids", [None])[0]
                if response.get("intent", {}).get("linked_attempt_ids")
                else None,
            )

        # Raise structured exceptions for non-succeeded states.
        if state == "succeeded":
            return result
        if state == "refused":
            raise ExecutionRefusedError(
                response.get("reason", "execution refused"),
                rule=response.get("rule_matched"),
                reason=response.get("reason", ""),
            )
        if state == "failed":
            raise ExecutionFailedError(
                response.get("reason", "execution failed"),
                rule=response.get("rule_matched"),
            )
        if state == "outcome_unknown":
            raise OutcomeUnknownError(
                response.get("reason", "outcome unknown"),
                rule=response.get("rule_matched"),
            )
        # submitted / accepted — non-final, return the result (no exception).
        return result


class CloudActenonClient(ActenonClient):
    """HTTP transport client. Talks to a Cloud-managed Permit Gateway."""

    def __init__(self, config: CloudTransportConfig) -> None:
        super().__init__()
        self._config = config

    @property
    def capabilities(self) -> CapabilityInfo:
        return CapabilityInfo(
            transport="cloud",
            supports_brokered=self._config.grant_token is not None,
            supports_resource_owned=True,
            supports_async=True,
            supports_polling=True,
            durable=True,
            production_mode=True,
        )

    def _create_intent(self, **kwargs: Any) -> IntentHandle:
        body = {
            "action_type": kwargs["action"],
            "action_params": kwargs["parameters"],
            "target_type": "unknown",
            "target_id": kwargs["target"],
            "requested_execution_mode": kwargs["requested_execution_mode"],
            "requester_subject": "sdk-cloud-client",
            "requester_agent_id": "sdk-cloud-client",
            "idempotency_key": kwargs.get("idempotency_key"),
            "expiry_seconds": kwargs.get("expiry_seconds", 3600),
            "metadata": kwargs.get("metadata", {}),
        }
        resp = self._http_post("/intents", body)
        return IntentHandle(
            intent_id=resp["intent_id"],
            lifecycle_state=resp["lifecycle_state"],
            _client=self,
        )

    def _execute_intent(self, intent_id: str) -> ExecutionResult:
        if self._config.grant_token is None:
            raise ActenonError("CloudActenonClient.execute() requires a grant_token")
        resp = self._http_post(
            f"/intents/{intent_id}/execute",
            body={},
            headers={"X-Actenon-Grant": self._config.grant_token},
        )
        return LocalActenonClient._map_response_to_result(intent_id, resp)

    def _submit_intent(self, intent_id: str, proof: dict[str, Any]) -> ExecutionResult:
        resp = self._http_post(
            f"/intents/{intent_id}/submit",
            body={"proof": proof},
        )
        return LocalActenonClient._map_response_to_result(intent_id, resp)

    def _http_post(self, path: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        url = self._config.base_url.rstrip("/") + path
        data = json.dumps(body).encode("utf-8")
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "actenon-sdk-python/1.4.0",
        }
        if self._config.grant_token and "X-Actenon-Grant" not in (headers or {}):
            hdrs["X-Actenon-Grant"] = self._config.grant_token
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_body = {"error": str(e)}
            raise ActenonError(
                f"HTTP {e.code} from {url.split('?')[0]}: {err_body.get('error', err_body.get('reason', str(e)))}",
                rule=err_body.get("rule_matched"),
            ) from e


# ---------------------------------------------------------------------------
# Public constructor class
# ---------------------------------------------------------------------------


class Actenon:
    """The main entry point for the Actenon SDK.

    Usage::

        from actenon_permit import Actenon

        client = Actenon.local(agent_id="my-agent", scopes=["github.*"])
        intent = client.authorised_execution_intents.create(
            action="github.issue.create",
            target="Actenon/example",
            parameters={"title": "Hello"},
        )
        result = intent.execute()
    """

    @staticmethod
    def local(
        *,
        agent_id: str = "dev-agent",
        scopes: list[str] | None = None,
        budget_limit: float = 100.0,
        signing_key: str | None = None,
        intent_store_path: str | None = None,
        production_mode: bool = False,
    ) -> LocalActenonClient:
        """Create a local (in-process) client.

        This is the default for development and self-hosted Permit.
        Uses an in-process Gateway with adapters. The raw provider
        credential is never given to the agent — the broker resolves
        it internally and passes it only to the adapter.

        Args:
            agent_id: The agent identity for grants.
            scopes: Allowed action scopes (glob-style). Default ["*"].
            budget_limit: Budget limit in USD.
            signing_key: HMAC signing key for grants. If None, an
                ephemeral dev key is generated (with a warning).
            intent_store_path: Path to SQLite intent store. If None,
                uses an ephemeral in-memory store.
            production_mode: If True, development-only credentials are
                refused.
        """
        config = LocalRuntimeConfig(
            agent_id=agent_id,
            scopes=scopes or ["*"],
            budget_limit=budget_limit,
            signing_key=signing_key,
            intent_store_path=intent_store_path,
            production_mode=production_mode,
        )
        return LocalActenonClient(config)

    @staticmethod
    def cloud(
        *,
        base_url: str,
        grant_token: str | None = None,
        timeout_seconds: float = 30.0,
        verify_tls: bool = True,
    ) -> CloudActenonClient:
        """Create a Cloud (HTTP transport) client.

        Talks to a Cloud-managed Permit Gateway over HTTP. The raw
        provider credential is never given to the agent — the Cloud
        gateway resolves it internally.

        Args:
            base_url: The Cloud gateway base URL.
            grant_token: The v1 bearer token for brokered execution.
                Not required for resource-owned submission.
            timeout_seconds: HTTP timeout.
            verify_tls: Whether to verify TLS certificates.
        """
        config = CloudTransportConfig(
            base_url=base_url,
            grant_token=grant_token,
            timeout_seconds=timeout_seconds,
            verify_tls=verify_tls,
        )
        return CloudActenonClient(config)


__all__ = [
    "Actenon",
    "ActenonClient",
    "CloudActenonClient",
    "LocalActenonClient",
]
