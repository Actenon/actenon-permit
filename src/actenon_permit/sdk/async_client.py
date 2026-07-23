"""Async Actenon client (Prompt 11 fix).

Provides ``AsyncActenonClient`` — an async variant of the sync
``ActenonClient``. The async client wraps the sync broker/adapter
calls in ``asyncio.to_thread()`` so the event loop is never blocked.

For the Cloud transport, the async client uses ``asyncio.to_thread``
with urllib (avoiding a hard dependency on aiohttp/httpx). Production
deployments that want true async HTTP should subclass and override
``_http_post_async`` with an aiohttp/httpx implementation.

Usage::

    import asyncio
    from actenon_permit.sdk import Actenon, AsyncActenonClient

    async def main():
        client = await Actenon.async_local(agent_id="my-agent")
        intent = await client.authorised_execution_intents.create_async(
            action="github.issue.create",
            target="github",
            parameters={"title": "async test"},
        )
        result = await intent.execute_async()
        print(result.state)

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
from typing import Any

from .client import ActenonClient
from .config import CapabilityInfo
from .models import ExecutionResult, IntentHandle


class _AsyncAuthorisedExecutionIntentsAPI:
    """The async ``client.authorised_execution_intents`` namespace."""

    def __init__(self, client: AsyncActenonClient) -> None:
        self._client = client

    async def create(
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
        """Create a new intent asynchronously. Returns an IntentHandle
        with ``execute_async()`` and ``submit_to_resource_async()`` methods."""
        return await self._client._create_intent_async(
            action=action,
            target=target,
            parameters=parameters or {},
            requested_execution_mode=requested_execution_mode,
            idempotency_key=idempotency_key,
            expiry_seconds=expiry_seconds,
            metadata=metadata or {},
        )


class AsyncActenonClient(ActenonClient):
    """Async wrapper around a sync ActenonClient.

    All sync calls are delegated to the wrapped sync client via
    ``asyncio.to_thread()``. The event loop is never blocked.
    """

    def __init__(self, sync_client: ActenonClient) -> None:
        super().__init__()
        self._sync = sync_client
        self.authorised_execution_intents = _AsyncAuthorisedExecutionIntentsAPI(self)

    @property
    def capabilities(self) -> CapabilityInfo:
        return self._sync.capabilities

    async def _create_intent_async(self, **kwargs: Any) -> IntentHandle:
        # The sync _create_intent is fast (in-memory), but we still
        # run it in a thread for consistency.
        handle = await asyncio.to_thread(self._sync._create_intent, **kwargs)
        # Re-bind the handle's _client to this async client so
        # execute_async / submit_to_resource_async work.
        object.__setattr__(handle, "_client", self)
        return handle

    async def _execute_intent(self, intent_id: str) -> ExecutionResult:
        """Execute an intent asynchronously.

        The sync broker call (which may invoke a network-bound adapter)
        runs in a thread so the event loop is not blocked.
        """
        return await asyncio.to_thread(self._sync._execute_intent, intent_id)

    async def _submit_intent(self, intent_id: str, proof: dict[str, Any]) -> ExecutionResult:
        """Submit an intent to a resource boundary asynchronously."""
        return await asyncio.to_thread(self._sync._submit_intent, intent_id, proof)

    # Convenience: expose register_* methods from the sync client.
    def register_credential(self, ref: str, value: str, **kwargs: Any) -> None:
        if hasattr(self._sync, "register_credential"):
            self._sync.register_credential(ref, value, **kwargs)

    def register_adapter_tool(self, *args: Any, **kwargs: Any) -> None:
        if hasattr(self._sync, "register_adapter_tool"):
            self._sync.register_adapter_tool(*args, **kwargs)

    def register_resource_client(self, resource_id: str, client: Any) -> None:
        if hasattr(self._sync, "register_resource_client"):
            self._sync.register_resource_client(resource_id, client)

    def register_resource_from_config(self, config: Any) -> None:
        if hasattr(self._sync, "register_resource_from_config"):
            self._sync.register_resource_from_config(config)


# ---------------------------------------------------------------------------
# Async IntentHandle methods (added via monkey-patch for clean API)
# ---------------------------------------------------------------------------


async def _intent_handle_execute_async(self: IntentHandle) -> ExecutionResult:
    """Execute this intent asynchronously."""
    if self._client is None:
        raise RuntimeError("IntentHandle has no client reference")
    if isinstance(self._client, AsyncActenonClient):
        return await self._client._execute_intent(self.intent_id)
    return self._client._execute_intent(self.intent_id)


async def _intent_handle_submit_to_resource_async(
    self: IntentHandle, proof: dict[str, Any]
) -> ExecutionResult:
    """Submit this intent to a resource boundary asynchronously."""
    if self._client is None:
        raise RuntimeError("IntentHandle has no client reference")
    if isinstance(self._client, AsyncActenonClient):
        return await self._client._submit_intent(self.intent_id, proof)
    return self._client._submit_intent(self.intent_id, proof)


# Attach the async methods to IntentHandle.
IntentHandle.execute_async = _intent_handle_execute_async  # type: ignore[attr-defined]
IntentHandle.submit_to_resource_async = _intent_handle_submit_to_resource_async  # type: ignore[attr-defined]


__all__ = ["AsyncActenonClient"]
