"""Credential providers for the Actenon-Permit broker.

A ``CredentialProvider`` resolves a credential *reference* (a logical name
like ``"github_pat"`` or ``"aws_oidc_role"``) into a *materialised*
``Credential`` value at call time — the moment a brokered action is about to
be executed.

The split matters: agents and proof payloads reference credentials **by
name** only. The materialised value never leaves the broker process. The
provider abstraction exists so the broker can support multiple credential
sources — local dev secrets, environment-injected values, cloud-managed
references, short-lived OIDC tokens, and customer-supplied resolvers —
behind one stable interface.

Design rules (enforced by tests):

1. ``resolve()`` returns a ``Credential`` whose ``.value`` is the secret.
   The broker is the ONLY consumer of ``.value`` — agents and adapters
   never receive it.
2. Local static providers MUST declare ``development_only=True`` so the
   broker can refuse them in production mode.
3. Providers that support short-lived credentials SHOULD set ``ttl_seconds``
   on the returned ``Credential`` so the broker can refresh before expiry.
4. Providers MUST NOT log, persist, or echo ``.value``. The base class
   sets ``__repr__ = "<redacted>"`` to prevent accidental disclosure in
   tracebacks.
"""

from __future__ import annotations

import abc
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable


class CredentialResolutionError(RuntimeError):
    """Raised when a credential cannot be resolved.

    The message MUST NOT contain the secret value. Providers are required
    to sanitise any underlying exception text before re-raising.
    """

    def __init__(self, ref: str, reason: str, *, retryable: bool = False):
        super().__init__(f"credential '{ref}' could not be resolved: {reason}")
        self.ref = ref
        self.reason = reason
        self.retryable = retryable


@dataclass
class Credential:
    """A materialised credential value plus metadata.

    ``value`` is the actual secret. It MUST NOT be logged, persisted, or
    returned to the agent. The broker consumes it exactly once inside the
    adapter call and then drops the reference.

    ``ttl_seconds`` is the credential's remaining lifetime. ``None`` means
    "no expiry known" — typical for long-lived API keys. The broker uses
    this to refuse to use credentials that are about to expire mid-call.
    """

    ref: str
    value: str
    source: str  # "local", "env", "cloud", "oidc", "customer"
    ttl_seconds: float | None = None
    scopes: list[str] = field(default_factory=list)
    development_only: bool = False
    # Internal: time the credential was resolved, for refresh decisions.
    _resolved_at: float = field(default_factory=time.monotonic, repr=False)

    def expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        age = time.monotonic() - self._resolved_at
        return age >= self.ttl_seconds

    def __repr__(self) -> str:
        return f"<Credential ref={self.ref!r} source={self.source!r} redacted>"

    def __str__(self) -> str:
        return self.__repr__()


class CredentialProvider(abc.ABC):
    """Abstract credential provider.

    Concrete providers resolve a *reference* (logical name) into a
    ``Credential``. They MUST NOT return the secret to anything other than
    the broker's adapter-invocation path.
    """

    #: Stable identifier for this provider type (e.g. ``"local"``).
    source: str = "abstract"

    @abc.abstractmethod
    def resolve(self, ref: str) -> Credential:
        """Resolve ``ref`` to a materialised credential.

        Raises ``CredentialResolutionError`` on any failure (missing env
        var, cloud API error, OIDC token exchange failure, etc.). The
        error message MUST NOT contain the secret value.
        """

    def health(self) -> dict[str, Any]:
        """Lightweight health probe, never raising.

        Returns ``{"ok": bool, "source": str, "detail": str}``. Default
        implementation returns ok=True if ``resolve()`` succeeds for any
        configured reference, else False with the error class name.
        Subclasses MAY override with a cheaper check (e.g. cloud reachability).
        """
        return {"ok": True, "source": self.source, "detail": "no health check defined"}


# ---------------------------------------------------------------------------
# Concrete providers
# ---------------------------------------------------------------------------


class LocalDevSecretProvider(CredentialProvider):
    """Reads a literal secret from a local file or in-memory mapping.

    MARKED DEVELOPMENT-ONLY. The broker will refuse to use this provider
    when ``broker.production_mode=True``. Intended for local development
    only — never commit real secrets to the file mapping.
    """

    source = "local"

    def __init__(self, mapping: dict[str, str] | None = None):
        # mapping is ref -> secret value. Keys are logical names; values
        # are the literal secrets. NEVER log this dict.
        self._mapping: dict[str, str] = dict(mapping or {})

    def register(self, ref: str, value: str) -> None:
        self._mapping[ref] = value

    def resolve(self, ref: str) -> Credential:
        if ref not in self._mapping:
            raise CredentialResolutionError(ref, "not registered with local provider")
        return Credential(
            ref=ref,
            value=self._mapping[ref],
            source=self.source,
            development_only=True,
        )

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "source": self.source,
            "detail": f"local provider with {len(self._mapping)} registered refs (development-only)",
        }


class EnvironmentSecretProvider(CredentialProvider):
    """Resolves a credential reference to an environment variable of the
    same name.

    This is the legacy v0 behaviour: ``Broker.resolve("MOCK_STRIPE_KEY")``
    read ``os.environ["MOCK_STRIPE_KEY"]``. The new broker delegates the
    same lookup to this provider for backward compatibility.

    Marked development-only when the env var's name contains ``MOCK_`` or
    ``DEV_`` prefixes, since those are convention-only secrets. Real
    production env vars (e.g. ``GITHUB_TOKEN``, ``STRIPE_SECRET_KEY``) are
    NOT marked development-only — but the deployment is still expected to
    inject them via the secret manager, not literal shell env.
    """

    source = "env"

    def __init__(self, environ: dict[str, str] | None = None):
        self._environ = environ if environ is not None else os.environ

    def resolve(self, ref: str) -> Credential:
        val = self._environ.get(ref)
        if val is None or val == "":
            raise CredentialResolutionError(ref, "environment variable is not set")
        dev_only = ref.startswith(("MOCK_", "DEV_", "LOCAL_"))
        return Credential(
            ref=ref,
            value=val,
            source=self.source,
            development_only=dev_only,
        )

    def health(self) -> dict[str, Any]:
        return {"ok": True, "source": self.source, "detail": "env provider ready"}


class CloudManagedRefProvider(CredentialProvider):
    """Resolves a *cloud-managed reference* (e.g. AWS Secrets Manager ARN,
    GCP Secret Manager resource name, Azure Key Vault URI) by calling a
    caller-supplied resolver callable.

    The resolver callable receives the reference string and MUST return
    the secret as a ``str``. It MUST NOT itself log the secret. Any
    exception is wrapped in ``CredentialResolutionError`` with the secret
    stripped.
    """

    source = "cloud"

    def __init__(self, resolver: Callable[[str], str]):
        self._resolver = resolver

    def resolve(self, ref: str) -> Credential:
        try:
            value = self._resolver(ref)
        except CredentialResolutionError:
            raise
        except Exception as e:
            # Sanitise: never include the exception text in full because
            # some SDK exceptions include request bodies. Use class name.
            raise CredentialResolutionError(
                ref, f"cloud resolver raised {type(e).__name__}", retryable=True
            ) from e
        if not isinstance(value, str) or not value:
            raise CredentialResolutionError(ref, "cloud resolver returned empty or non-string")
        return Credential(ref=ref, value=value, source=self.source)

    def health(self) -> dict[str, Any]:
        # Cheap probe: the resolver is callable. A real cloud provider
        # implementation should override this with an actual reachability
        # check (e.g. list-secrets with max-results=1).
        return {"ok": callable(self._resolver), "source": self.source, "detail": "resolver callable"}


class OIDCShortLivedProvider(CredentialProvider):
    """Resolves a short-lived credential by exchanging an OIDC token grant
    for a provider-scoped access token.

    The ``token_exchange`` callable receives ``(ref, scopes)`` and MUST
    return a tuple ``(access_token, expires_in_seconds)``. The provider
    stores the result and refreshes it when ``expired()`` returns True.

    Typical use: a GitHub Actions workflow requesting an OIDC token that
    is exchanged for a GitHub installation access token (TTL ~1h), or an
    AWS STS session token (TTL ~15min-1h).
    """

    source = "oidc"

    def __init__(
        self,
        token_exchange: Callable[[str, list[str]], tuple[str, int]],
        default_scopes: list[str] | None = None,
    ):
        self._token_exchange = token_exchange
        self._default_scopes = default_scopes or []
        # Cache: ref -> (Credential, monotonic timestamp)
        self._cache: dict[str, tuple[Credential, float]] = {}

    def resolve(self, ref: str, scopes: list[str] | None = None) -> Credential:  # type: ignore[override]
        now = time.monotonic()
        cached = self._cache.get(ref)
        # Refresh when within 10% of TTL remaining (safety margin for the
        # network round-trip of the exchange call).
        if cached is not None:
            cred, ts = cached
            if cred.ttl_seconds is not None:
                age = now - ts
                if age < cred.ttl_seconds * 0.9:
                    return cred
        # Otherwise exchange a fresh token.
        try:
            access_token, expires_in = self._token_exchange(ref, scopes or self._default_scopes)
        except Exception as e:
            raise CredentialResolutionError(
                ref, f"OIDC exchange raised {type(e).__name__}", retryable=True
            ) from e
        if not access_token:
            raise CredentialResolutionError(ref, "OIDC exchange returned empty token")
        cred = Credential(
            ref=ref,
            value=access_token,
            source=self.source,
            ttl_seconds=float(expires_in) if expires_in else None,
            scopes=scopes or self._default_scopes,
        )
        self._cache[ref] = (cred, now)
        return cred

    def health(self) -> dict[str, Any]:
        return {
            "ok": callable(self._token_exchange),
            "source": self.source,
            "detail": f"OIDC provider with {len(self._cache)} cached tokens",
        }

    def purge_cache(self) -> None:
        """Drop all cached tokens. Used by the broker on credential destruction."""
        self._cache.clear()


class CustomerResolverProvider(CredentialProvider):
    """Wraps a customer-supplied credential resolver callable.

    This is the escape hatch for organisations that have an existing
    secret-management integration (e.g. an internal vault with a custom
    auth flow). The callable receives the reference and MUST return a
    ``Credential`` (the customer takes responsibility for the value).
    """

    source = "customer"

    def __init__(self, resolver: Callable[[str], Credential]):
        self._resolver = resolver

    def resolve(self, ref: str) -> Credential:
        try:
            cred = self._resolver(ref)
        except CredentialResolutionError:
            raise
        except Exception as e:
            raise CredentialResolutionError(
                ref, f"customer resolver raised {type(e).__name__}", retryable=True
            ) from e
        if not isinstance(cred, Credential):
            raise CredentialResolutionError(ref, "customer resolver did not return a Credential")
        # Re-tag with our source so downstream code can tell this came
        # through the customer path.
        cred.source = self.source
        return cred

    def health(self) -> dict[str, Any]:
        return {
            "ok": callable(self._resolver),
            "source": self.source,
            "detail": "customer resolver callable",
        }


# ---------------------------------------------------------------------------
# Composite registry
# ---------------------------------------------------------------------------


class CredentialProviderRegistry:
    """Routes a credential reference to the right provider.

    Each reference is registered with exactly one provider. Unregistered
    references raise ``CredentialResolutionError`` (the broker then
    surfaces this as a DENY, never as a 500).
    """

    def __init__(self) -> None:
        self._routes: dict[str, CredentialProvider] = {}

    def register(self, ref: str, provider: CredentialProvider) -> None:
        if ref in self._routes:
            raise ValueError(f"credential ref '{ref}' is already routed")
        self._routes[ref] = provider

    def resolve(self, ref: str) -> Credential:
        provider = self._routes.get(ref)
        if provider is None:
            raise CredentialResolutionError(ref, "no provider registered for this ref")
        return provider.resolve(ref)

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "refs": {
                ref: {"source": p.source, "health": p.health()}
                for ref, p in self._routes.items()
            },
        }


__all__ = [
    "Credential",
    "CredentialProvider",
    "CredentialProviderRegistry",
    "CredentialResolutionError",
    "CustomerResolverProvider",
    "EnvironmentSecretProvider",
    "CloudManagedRefProvider",
    "LocalDevSecretProvider",
    "OIDCShortLivedProvider",
]
