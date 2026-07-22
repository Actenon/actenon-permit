"""Configuration for the Actenon SDK.

Two configuration profiles:

  * ``LocalRuntimeConfig`` — for local development and self-hosted
    Permit gateway. Uses an in-process Permit Gateway with an
    EphemeralIntentStore (or SQLiteIntentStore for durable-local).

  * ``CloudTransportConfig`` — for Cloud-managed deployments. Uses
    HTTP transport to talk to a remote Permit Gateway.

Both profiles expose capability information so callers can check
what's supported before relying on it.

Signing-key resolution (LocalRuntimeConfig):
  1. ``signing_key=`` argument (explicit)
  2. ``ACTENON_SIGNING_KEY`` env var
  3. ``~/.actenon-permit/dev-signing-key`` (auto-generated on first use)
  4. Ephemeral in-memory key (with a warning — last resort)

The auto-generated dev key (step 3) eliminates the one-line friction
of having to pass ``signing_key=`` on every ``Actenon.local()`` call
while still being stable across process restarts. The key is marked
development-only and is refused in production_mode.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import warnings
from dataclasses import dataclass, field
from pathlib import Path


def _dev_signing_key_path() -> Path:
    """The default location for the auto-generated dev signing key."""
    return Path.home() / ".actenon-permit" / "dev-signing-key"


def _load_or_create_dev_signing_key() -> str:
    """Load the persisted dev signing key, creating it on first use.

    The key is stored at ``~/.actenon-permit/dev-signing-key`` as a
    hex string. It persists across process restarts, so grants minted
    in one process validate in another.

    This is development-only. Production deployments MUST set
    ``ACTENON_SIGNING_KEY`` explicitly or use asymmetric signing.
    """
    key_path = _dev_signing_key_path()
    try:
        if key_path.is_file():
            key = key_path.read_text(encoding="utf-8").strip()
            if key:
                return key
        # Create the key.
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_hex(32)
        key_path.write_text(key, encoding="utf-8")
        # Best-effort permissions (0600). On Windows this is a no-op.
        with contextlib.suppress(OSError):
            key_path.chmod(0o600)
        warnings.warn(
            f"Actenon generated a dev signing key at {key_path}. "
            f"This key is development-only and MUST NOT be used in production. "
            f"Set ACTENON_SIGNING_KEY or pass signing_key= for production.",
            stacklevel=4,
        )
        return key
    except OSError:
        # Can't read or write the key file (e.g. read-only filesystem).
        # Fall back to an ephemeral key with a warning.
        warnings.warn(
            "Actenon could not persist a dev signing key (filesystem not writable). "
            "Using an ephemeral in-memory key — grants will NOT validate after "
            "this process exits. Set ACTENON_SIGNING_KEY for stable keys.",
            stacklevel=4,
        )
        return secrets.token_hex(32)


@dataclass(frozen=True)
class LocalRuntimeConfig:
    """Configuration for local (in-process) runtime.

    Attributes:
        agent_id: The agent identity for grants.
        scopes: Allowed action scopes (glob-style, e.g. ``["github.*"]``).
        budget_limit: Budget limit in USD (default 100.0).
        budget_currency: Budget currency (default "USD").
        signing_key: HMAC signing key for grants. If None, the SDK
            resolves the key from (1) ACTENON_SIGNING_KEY env var,
            (2) ~/.actenon-permit/dev-signing-key (auto-generated),
            (3) ephemeral in-memory key (with warning).
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
            # Try env var first.
            env_key = os.environ.get("ACTENON_SIGNING_KEY", "").strip()
            if env_key:
                # Use object.__setattr__ because the dataclass is frozen.
                object.__setattr__(self, "signing_key", env_key)
            else:
                # Auto-generate / load a persisted dev key.
                object.__setattr__(self, "signing_key", _load_or_create_dev_signing_key())


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
class ResourceClientConfig:
    """Configuration for a resource-owned submission client.

    Used by ``ActenonClient.register_resource_from_config()`` to
    register a ``ResourceOwnedSubmissionClient`` without the caller
    having to construct the verifier + client manually.

    Attributes:
        resource_id: The resource identifier (must match the intent's
            ``target_id``).
        endpoint_url: The resource boundary's HTTP endpoint.
        signing_key_id: The key id the resource uses to sign receipts.
        signing_key_secret: The resource's signing key secret (bytes).
        timeout_seconds: HTTP timeout for submissions (default 30.0).
    """

    resource_id: str
    endpoint_url: str
    signing_key_id: str
    signing_key_secret: bytes
    timeout_seconds: float = 30.0


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
    "ResourceClientConfig",
]
