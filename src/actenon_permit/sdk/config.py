"""Configuration for the Actenon SDK.

Two configuration profiles:

  * ``LocalRuntimeConfig`` — for local development and self-hosted
    Permit gateway. Uses an in-process Permit Gateway with an
    EphemeralIntentStore (or SQLiteIntentStore for durable-local).

  * ``CloudTransportConfig`` — for Cloud-managed deployments. Uses
    HTTP transport to talk to a remote Permit Gateway.

Both profiles expose capability information so callers can check
what's supported before relying on it.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field


@dataclass(frozen=True)
class LocalRuntimeConfig:
    """Configuration for local (in-process) runtime.

    Attributes:
        agent_id: The agent identity for grants.
        scopes: Allowed action scopes (glob-style, e.g. ``["github.*"]``).
        budget_limit: Budget limit in USD (default 100.0).
        budget_currency: Budget currency (default "USD").
        signing_key: HMAC signing key for grants. If None, an
            ephemeral dev key is generated (with a warning).
        intent_store_path: Path to SQLite intent store. If None,
            uses an ephemeral in-memory store.
        production_mode: If True, development-only credentials are
            refused. Default False.
    """

    agent_id: str = "dev-agent"
    scopes: list[str] = field(default_factory=lambda: ["*"])
    budget_limit: float = 100.0
    budget_currency: str = "USD"
    signing_key: str | None = None
    intent_store_path: str | None = None
    production_mode: bool = False

    def __post_init__(self) -> None:
        if self.signing_key is None:
            warnings.warn(
                "Actenon.local() is using an ephemeral dev signing key. "
                "Grants will NOT validate after this process exits. "
                "Set signing_key=... or ACTENON_SIGNING_KEY for stable keys. "
                "This is development-only and MUST NOT be used in production.",
                stacklevel=3,
            )


@dataclass(frozen=True)
class CloudTransportConfig:
    """Configuration for Cloud (HTTP) transport.

    Attributes:
        base_url: The Cloud gateway base URL (e.g.
            ``"https://cloud.actenon.example"``).
        grant_token: The v1 bearer token for the Permit gateway.
            Required for brokered execution. NOT required for
            resource-owned submission (the proof is the authority).
        timeout_seconds: HTTP timeout (default 30.0).
        verify_tls: Whether to verify TLS certificates (default True).
        extra_headers: Additional HTTP headers (e.g. for auth proxies).
    """

    base_url: str
    grant_token: str | None = None
    timeout_seconds: float = 30.0
    verify_tls: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError(
                f"CloudTransportConfig.base_url must start with http:// or https://, "
                f"got {self.base_url!r}"
            )
        if self.base_url.startswith("http://") and not self.base_url.startswith("http://localhost") and not self.base_url.startswith("http://127.0.0.1"):
            warnings.warn(
                f"CloudTransportConfig.base_url is using plain HTTP (not localhost). "
                f"This is insecure — use HTTPS in production. "
                f"base_url={self.base_url!r}",
                stacklevel=3,
            )


@dataclass(frozen=True)
class CapabilityInfo:
    """Capability information for a client.

    Callers can check these before relying on specific features.
    """

    transport: str  # "local" or "cloud"
    supports_brokered: bool = True
    supports_resource_owned: bool = True
    supports_async: bool = True
    supports_polling: bool = True
    durable: bool = False  # True if intents survive process restart
    production_mode: bool = False


__all__ = [
    "CapabilityInfo",
    "CloudTransportConfig",
    "LocalRuntimeConfig",
]
