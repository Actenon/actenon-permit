# Actenon Python SDK

The official Python SDK for [Actenon-Permit](https://github.com/Actenon/actenon-permit) —
the open-source authority broker for AI agents. Bounded, revocable capability
grants with hard runtime limits, proof-required execution, and a brokered
credential boundary that ensures the agent never sees the raw provider
credential.

## Installation

```bash
pip install actenon-permit
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add actenon-permit
```

For development:

```bash
git clone https://github.com/Actenon/actenon-permit.git
cd actenon-permit
uv sync --extra dev
```

## Hero quickstart

```python
from actenon_permit import Actenon, GitHubAdapter

# 1. Create a local client. The signing key is auto-generated and
#    persisted to ~/.actenon-permit/dev-signing-key on first use.
client = Actenon.local(
    agent_id="my-agent",
    scopes=["github.issue.create"],
)

# 2. Register a development-only GitHub token. The agent NEVER sees
#    this value — the broker resolves it internally and passes it
#    only to the adapter.
client.register_credential("GITHUB_TOKEN", "ghp_YOUR_TOKEN_HERE")

# 3. Register the GitHub adapter tool (test_mode = no network).
client.register_adapter_tool(
    "github_issue",
    action_type="github.issue.create",
    adapter=GitHubAdapter(test_mode=True),
    credential_ref="GITHUB_TOKEN",
    target="github",
)

# 4. Create an intent and execute it.
intent = client.authorised_execution_intents.create(
    action="github.issue.create",
    target="github",
    parameters={
        "owner": "Actenon",
        "repo": "example",
        "title": "Created through authorised execution.",
    },
)

result = intent.execute()
print(f"state={result.state}  finality={result.finality}")
print(f"evidence: {result.evidence}")
```

**Output:**

```
state=succeeded  finality=final
evidence: {'issue_number': 42, 'issue_url': 'https://github.com/Actenon/example/issues/42', ...}
```

### What just happened?

1. **A permitted action executed.** The intent's action (`github.issue.create`)
   was in the grant's scopes, so the PDP allowed it. The broker resolved the
   credential, passed it to the adapter, and the adapter executed the action.
2. **A proofless action is refused.** If you create an intent for an action
   not in the grant's scopes (e.g. `github.repo.delete`), the PDP denies it
   and `intent.execute()` raises `ExecutionRefusedError`.
3. **A parameter-mutated action is refused.** If you add an unknown parameter
   (e.g. `malicious_field`), the adapter rejects it and `intent.execute()`
   raises `ExecutionRefusedError`.
4. **A replay is refused.** If you call `intent.execute()` twice, the second
   call raises `ExecutionRefusedError` — the lifecycle state machine prevents
   transitions from terminal states.
5. **A receipt is returned.** The result carries `receipt_received=True` and
   `receipt_verified=True`.
6. **The raw provider credential is never given to the agent.** The GitHub
   token never appears in the result, the evidence, or any log.

## Async API

For async frameworks (FastAPI, aiohttp, etc.), use `Actenon.async_local()` or
`Actenon.async_cloud()`:

```python
import asyncio
from actenon_permit import Actenon, GitHubAdapter

async def main():
    client = Actenon.async_local(
        agent_id="my-async-agent",
        scopes=["github.issue.create"],
        signing_key="stable-dev-key-not-for-production",
    )
    client.register_credential("GITHUB_TOKEN", "ghp_YOUR_TOKEN_HERE")
    client.register_adapter_tool(
        "github_issue",
        action_type="github.issue.create",
        adapter=GitHubAdapter(test_mode=True),
        credential_ref="GITHUB_TOKEN",
        target="github",
    )

    intent = await client.authorised_execution_intents.create(
        action="github.issue.create",
        target="github",
        parameters={"owner": "Actenon", "repo": "example", "title": "async test"},
    )
    result = await intent.execute_async()
    print(f"state={result.state}  finality={result.finality}")

asyncio.run(main())
```

The async client wraps the sync broker/adapter calls in `asyncio.to_thread()`
so the event loop is never blocked.

## Cloud transport

For Cloud-managed deployments, use `Actenon.cloud()`:

```python
from actenon_permit import Actenon

client = Actenon.cloud(
    base_url="https://cloud.actenon.example",
    grant_token="v1.YOUR_GRANT_TOKEN",
)

intent = client.authorised_execution_intents.create(
    action="github.issue.create",
    target="github",
    parameters={"owner": "Actenon", "repo": "example", "title": "via cloud"},
)
result = intent.execute()
```

The Cloud client talks to a remote Permit Gateway over HTTP. The raw provider
credential is never given to the agent — the Cloud gateway resolves it
internally.

## Resource-owned execution

For resource-owned mode (the resource boundary independently verifies the
proof and executes), register a resource client from config:

```python
from actenon_permit import Actenon, ResourceClientConfig

client = Actenon.local(agent_id="my-agent", scopes=["iam.grant_role"])
client.register_resource_from_config(ResourceClientConfig(
    resource_id="iam-control-plane",
    endpoint_url="https://iam.example.invalid/submit",
    signing_key_id="iam-key-1",
    signing_key_secret=b"the-secret-bytes",
))

intent = client.authorised_execution_intents.create(
    action="iam.grant_role",
    target="iam-control-plane",
    parameters={"subject": "alice", "role": "viewer"},
    requested_execution_mode="resource_owned",
)

# The proof is obtained from the authority broker (outside the SDK).
proof = {"proof_id": "proof_abc", "execution_mode": "resource_owned"}
result = intent.submit_to_resource(proof)
print(f"state={result.state}  resource_receipt_verified={result.resource_receipt_verified}")
```

## Result models

Every execution returns a **discriminated** result. The two result types are
NOT interchangeable — callers MUST branch on `isinstance` or on the `mode`
field before reading mode-specific attributes.

### BrokeredResult (brokered mode)

```python
from actenon_permit import BrokeredResult

result = intent.execute()
if isinstance(result, BrokeredResult):
    print(f"mode={result.mode}")                    # "brokered"
    print(f"state={result.state}")                  # "succeeded" | "failed" | "refused" | "outcome_unknown"
    print(f"finality={result.finality}")            # "final" | "non_final"
    print(f"provider_execution_observed={result.provider_execution_observed}")
    print(f"receipt_received={result.receipt_received}")
    print(f"receipt_verified={result.receipt_verified}")
    print(f"evidence={result.evidence}")            # redacted provider evidence
    print(f"succeeded={result.succeeded}")          # True iff state == "succeeded"
    print(f"is_final={result.is_final}")            # True iff finality == "final"
```

### ResourceOwnedResult (resource_owned mode)

```python
from actenon_permit import ResourceOwnedResult

result = intent.submit_to_resource(proof)
if isinstance(result, ResourceOwnedResult):
    print(f"mode={result.mode}")                    # "resource_owned"
    print(f"state={result.state}")                  # "submitted" | "accepted" | "refused" | "succeeded" | "failed" | "outcome_unknown"
    print(f"finality={result.finality}")            # "final" | "non_final"
    print(f"resource_receipt_received={result.resource_receipt_received}")
    print(f"resource_receipt_verified={result.resource_receipt_verified}")
    print(f"submission_reference={result.submission_reference}")
```

## Structured exceptions

All SDK exceptions inherit from `ActenonError`. Error messages NEVER contain
credentials, secrets, or provider tokens.

| Exception | Raised when | Retryable |
|---|---|---|
| `ExecutionRefusedError` | Action was refused (proof invalid, out of scope, parameter validation failed, credential resolution failed) | No |
| `ExecutionFailedError` | Provider call was attempted and failed | No |
| `OutcomeUnknownError` | Provider call timed out, returned partial response, or reconciliation is pending | **Yes** |
| `ProviderError` | Adapter raised an unexpected exception | Depends |
| `IntentNotFoundError` | Intent id not found in the store | No |
| `ProofMissingError` | Resource-owned submission attempted without a proof | No |

```python
from actenon_permit import (
    ActenonError,
    ExecutionRefusedError,
    OutcomeUnknownError,
)

try:
    result = intent.execute()
except ExecutionRefusedError as e:
    print(f"refused: {e}  rule={e.rule}")
except OutcomeUnknownError as e:
    print(f"outcome unknown (retryable): {e}")
    # Safe to retry with the same idempotency key.
```

## Retry guidance

The SDK does NOT retry automatically — retries must be explicit. Use the
`with_retry()` helper for safe retries with exponential backoff + jitter:

```python
from actenon_permit.sdk import with_retry

result = with_retry(
    lambda: intent.execute(),
    max_attempts=5,
    base_delay_seconds=2.0,
)
```

`with_retry()` only retries on `OutcomeUnknownError` and `RetryableError`. It
does NOT retry on `ExecutionRefusedError` (the action was refused — retrying
won't help).

## Receipt verification

Verify resource receipts independently, without trusting the broker:

```python
from actenon_permit.sdk import verify_resource_receipt

verified = verify_resource_receipt(
    receipt={"charge_id": "ch_123", "signing_key_id": "rk_1", "signature": "..."},
    signing_keys={"rk_1": b"the-secret-bytes"},
)
if not verified:
    raise ValueError("forged receipt!")
```

## Capability discovery

Check what a client supports before relying on specific features:

```python
client = Actenon.local(agent_id="my-agent", scopes=["*"])
caps = client.capabilities
print(f"transport: {caps.transport}")               # "local" | "cloud"
print(f"supports_brokered: {caps.supports_brokered}")
print(f"supports_resource_owned: {caps.supports_resource_owned}")
print(f"supports_async: {caps.supports_async}")
print(f"durable: {caps.durable}")                   # True if intents survive process restart
print(f"production_mode: {caps.production_mode}")
```

## Configuration

### Local runtime

```python
from actenon_permit import Actenon

client = Actenon.local(
    agent_id="my-agent",                # default: "dev-agent"
    scopes=["github.issue.create"],      # default: ["*"]
    budget_limit=100.0,                  # default: 100.0 (USD)
    budget_currency="USD",               # default: "USD"
    signing_key="my-stable-key",         # default: auto-generated + persisted
    intent_store_path="/tmp/intents.db", # default: None (ephemeral)
    production_mode=False,               # default: False
)
```

**Signing-key resolution** (in priority order):
1. Explicit `signing_key=` argument
2. `ACTENON_SIGNING_KEY` env var
3. `~/.actenon-permit/dev-signing-key` (auto-generated on first use, persisted with `0600` permissions)
4. Ephemeral in-memory key (with warning — last resort)

### Cloud transport

```python
from actenon_permit import Actenon

client = Actenon.cloud(
    base_url="https://cloud.actenon.example",
    grant_token="v1.YOUR_GRANT_TOKEN",   # required for brokered; not for resource-owned
    timeout_seconds=30.0,                 # default: 30.0
    verify_tls=True,                      # default: True
)
```

## Migration from low-level APIs

If you're already using the low-level Grant/Action/Decision/Broker APIs,
here's how to migrate to the SDK.

### Before (low-level)

```python
from actenon_permit import (
    Grant, Action, Decision, DecisionOutcome,
    PDP, Broker, SQLiteStore, Ledger,
    CredentialProviderRegistry, LocalDevSecretProvider,
    GitHubAdapter, BrokeredExecutionCoordinator,
    IntentManager, EphemeralIntentStore,
)
from datetime import UTC, datetime, timedelta

# 1. Set up state
store = SQLiteStore("actenon.db")
ledger = Ledger(store)
pdp = PDP(store, ledger)

# 2. Issue a grant
grant = Grant(
    agent_id="my-agent",
    issued_at=datetime.now(UTC),
    expires_at=datetime.now(UTC) + timedelta(hours=1),
    scopes=Scopes(allow=["github.issue.create"]),
    budget=Budget(currency="USD", limit=100.0, remaining=100.0),
    rate=Rate(max=100, per_seconds=60),
)
grant.sign()
store.put_grant(grant)

# 3. Set up the broker
cred_registry = CredentialProviderRegistry()
cred_registry.register("GITHUB_TOKEN", LocalDevSecretProvider({"GITHUB_TOKEN": "ghp_..."}))
broker = Broker(pdp, credential_providers=cred_registry)

# 4. Build the action + decision
action = Action(grant_id=grant.id, type="github.issue.create", target="github",
                params={"owner": "a", "repo": "b", "title": "t"}, est_cost=0.0)
decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action, ctx={})

# 5. Execute via the coordinator
adapter = GitHubAdapter(test_mode=True)
coord = BrokeredExecutionCoordinator(broker=broker)
result, cost = coord.coordinate(grant, action, decision, adapter,
                                 credential_ref="GITHUB_TOKEN")
```

### After (SDK)

```python
from actenon_permit import Actenon, GitHubAdapter

client = Actenon.local(agent_id="my-agent", scopes=["github.issue.create"])
client.register_credential("GITHUB_TOKEN", "ghp_...")
client.register_adapter_tool(
    "github_issue",
    action_type="github.issue.create",
    adapter=GitHubAdapter(test_mode=True),
    credential_ref="GITHUB_TOKEN",
    target="github",
)

intent = client.authorised_execution_intents.create(
    action="github.issue.create",
    target="github",
    parameters={"owner": "a", "repo": "b", "title": "t"},
)
result = intent.execute()
```

**Lines of code:** 25 → 10. The SDK handles grant issuance, PDP setup, broker
construction, action building, and coordinator invocation internally.

### What the SDK hides (and what it doesn't)

**Hidden:**
- Grant issuance (the SDK issues a 24-hour grant automatically)
- PDP + broker + ledger construction
- Action + decision building
- Coordinator invocation
- Lifecycle state transitions

**NOT hidden:**
- The raw provider credential (never given to the agent)
- The discriminated result (brokered vs resource-owned)
- The finality status (final vs non_final)
- The receipt verification status
- The lifecycle state (you can still inspect `intent.lifecycle_state`)

### When to use the low-level APIs

The SDK is the recommended surface for most use cases. Use the low-level APIs
when you need:
- Custom grant lifecycles (attenuation, delegation chains)
- Custom PDP policies (per-action approval rules, custom rate limits)
- Custom credential providers (Cloud-managed, OIDC, customer-supplied)
- Direct access to the Kernel PCCB verifier
- Integration with the v1 HTTP gateway (`Gateway.call_tool()`)

The low-level APIs are stable and will NOT be removed. The SDK is the
recommended surface, not the only entry point.

## Development-only warnings

The SDK emits explicit warnings for development-only defaults:

- **Ephemeral signing key:** `UserWarning: Actenon generated a dev signing
  key at ~/.actenon-permit/dev-signing-key. This key is development-only
  and MUST NOT be used in production.`
- **register_credential():** `UserWarning: register_credential('GITHUB_TOKEN',
  ...) is development-only. The credential is stored in process memory and
  will be refused in production_mode.`
- **Plain HTTP Cloud URL:** `UserWarning: CloudTransportConfig.base_url is
  using plain HTTP (not localhost). This is insecure — use HTTPS in
  production.`

## Low-level proof verification

For advanced use cases that need direct access to the Kernel PCCB verifier:

```python
from actenon_permit.kernel_bridge import verify_pccb_at_edge
from actenon_permit.model import Action, Grant

# Verify a PCCB is bound to the exact action before releasing a credential.
verify_pccb_at_edge(intent, pccb, grant, action)
```

This is the same call the gateway makes at the edge before broker release.

## Package metadata

- **Package:** `actenon-permit`
- **Version:** 1.4.0
- **Python:** >=3.11
- **License:** Apache-2.0
- **Source:** https://github.com/Actenon/actenon-permit
- **Docs:** https://github.com/Actenon/actenon-permit/tree/main/src/actenon_permit/sdk

## Examples

See `scripts/sdk_quickstart.py` for the full hero quickstart demonstrating
all 6 security guarantees. See `tests/test_sdk.py` for comprehensive usage
examples covering every API surface.

## Migration guidance

### From v1.0-3 (Grant/Action/Decision APIs)

The low-level APIs are unchanged. The SDK is a new layer on top. You can
migrate incrementally:

1. **Keep existing grant issuance** — the SDK's `Actenon.local()` issues its
   own grant internally, but you can still use your existing grants with the
   low-level `Gateway.call_tool()` API.
2. **Adopt the SDK for new code** — new intents can use
   `client.authorised_execution_intents.create()` + `intent.execute()`.
3. **Migrate gradually** — the SDK and the low-level APIs share the same
   state store, so intents created via either API are visible to both.

### From bare action names to namespaced action names

The GitHub adapter now accepts both `issue.create` (bare) and
`github.issue.create` (namespaced). The namespaced form is canonical; the
bare form is a backward-compat alias. New code should use the namespaced
form for clarity.
