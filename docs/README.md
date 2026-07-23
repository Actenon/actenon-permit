# Actenon Documentation

> **Honesty notice**: Actenon is a design-partner-ready platform, not a
> fully production-ready product. See [§12 Security Guarantees and
> Limitations](#12-security-guarantees-and-limitations) for what's
> production-ready vs pilot-ready vs stub.

## Table of Contents

1. [What Actenon Solves](#1-what-actenon-solves)
2. [Scan in Minutes](#2-scan-in-minutes)
3. [First Brokered Protected Action](#3-first-brokered-protected-action)
4. [Local Development](#4-local-development)
5. [Cloud Deployment](#5-cloud-deployment)
6. [Permit Authority Model](#6-permit-authority-model)
7. [Kernel Boundary Verification](#7-kernel-boundary-verification)
8. [Resource-Owned Integration](#8-resource-owned-integration)
9. [Protocol Implementation](#9-protocol-implementation)
10. [Evidence Verification](#10-evidence-verification)
11. [Threat Model](#11-threat-model)
12. [Security Guarantees and Limitations](#12-security-guarantees-and-limitations)
13. [Migration](#13-migration)
14. [API and SDK Reference](#14-api-and-sdk-reference)
15. [Provider Adapter Development](#15-provider-adapter-development)
16. [Production Deployment](#16-production-deployment)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. What Actenon Solves

Most agent security incidents aren't clever exploits — they're
over-permissioned agents doing permitted-but-catastrophic things. A refund
bot that can also charge. An email helper with no spend cap. A coding agent
whose shell tool has no rate limit. The agent was *authorised* to act; it
just shouldn't have been.

Actenon is the enforcement layer between an AI agent and the real world.

**The three repos:**

| Repo | Role | Can run alone? |
|---|---|---|
| **actenon-kernel** | Open verifier + spec + conformance authority | ✅ Yes |
| **actenon-permit** | Open authority broker: issues grants, enforces at edge, runs the credential broker | ✅ Yes |
| **actenon-cloud** | Optional managed control plane (multi-tenant, hosted) | ❌ Requires Kernel + Permit |
| **actenon-scan** | Independent static-analysis scanner for the execution gap | ✅ Yes (zero deps) |
| **actenon-protocol** | Neutral wire-format spec (JSON Schemas, canonicalisation, refusal codes) | ✅ Yes |

**Key honesty points:**
- Kernel can be adopted independently.
- Permit can run without Cloud.
- Cloud is optional.
- Scan recognises equivalent controls (not just Actenon).
- Brokered execution is the default immediate product path.
- Resource-owned execution requires adoption at the protected resource.

---

## 2. Scan in Minutes

```bash
pip install actenon-scan
actenon-scan scan ./my-agent-code
```

Scan detects consequential actions (payments, data destruction, deployments,
identity changes, provider SDK calls) reachable from agent tool boundaries.
It recognises existing guards — Actenon or not.

```bash
# See adoption guidance
actenon-scan adopt ./my-agent-code

# Register custom guards
actenon-scan init  # writes actenon-scan.json
# Add your guard function names to the "guards" section
```

Scan runs without Cloud. Scan runs without Permit. Scan runs without Kernel.
It's a standalone security tool.

---

## 3. First Brokered Protected Action

```bash
pip install actenon-permit
```

```python
from actenon_permit import Actenon, GitHubAdapter

client = Actenon.local(agent_id="my-agent", scopes=["issue.create"])
client.register_credential("GITHUB_TOKEN", "ghp_YOUR_TOKEN")
client.register_adapter_tool(
    "github_issue",
    action_type="issue.create",
    adapter=GitHubAdapter(test_mode=True),
    credential_ref="GITHUB_TOKEN",
    target="github",
)

intent = client.authorised_execution_intents.create(
    action="issue.create",
    target="github",
    parameters={"owner": "Actenon", "repo": "example", "title": "Hello"},
)
result = intent.execute()
print(f"state={result.state}  finality={result.finality}")
```

**What just happened:**
- The agent never saw the GitHub token.
- The broker resolved the credential internally and passed it only to the adapter.
- A proof was minted and verified at the edge.
- A receipt was issued.
- Replay and mutation are refused.

---

## 4. Local Development

```bash
# Install with dev deps
git clone https://github.com/Actenon/actenon-permit.git
cd actenon-permit
uv sync --extra dev

# Run the CLI demo
uv run actenon demo

# Run tests
uv run pytest

# Run the gateway demo
uv run permit demo --mode gateway --auto-approve
```

The local runtime uses:
- SQLite for grant/budget/rate state (WAL mode, `BEGIN IMMEDIATE` transactions)
- Ephemeral or SQLite intent store
- Auto-generated dev signing key (`~/.actenon-permit/dev-signing-key`, `0600` perms)
- GitHubAdapter in `test_mode=True` (no network, deterministic responses)

**Development-only warnings**: the SDK emits explicit warnings for ephemeral
keys, development-only credentials, and plain HTTP. These are NOT silenced
in production mode.

---

## 5. Cloud Deployment

Cloud is the **optional** managed control plane. It adds:
- Multi-tenant isolation (RLS + Python-level checks)
- Hosted AEI lifecycle management (create, approve, execute, evidence)
- Encrypted credential store (AES-256-GCM, per-tenant keys)
- Durable execution workers (retry, dead-letter, reconciliation)
- Evidence bundles (9 independent layers, independently verifiable)

```bash
# Cloud is NOT required for local development.
# To deploy Cloud, see PRODUCTION_INTEGRATION.md in actenon-cloud.
```

**Cloud does NOT define proof validity.** The Kernel remains the verifier
authority. Cloud issues proofs under authorised conditions and delegates
execution to the Permit gateway.

---

## 6. Permit Authority Model

Permit is the authority broker. It:
- Issues signed, scoped, expiring, revocable **Grants** (capability tokens)
- Runs the **PDP** (Policy Decision Point) — deterministic ALLOW/DENY/REQUIRE_APPROVAL
- Enforces **budget**, **rate limits**, **scope**, **expiry**, and **approval** rules
- Attenuates grants (UCAN-style delegation — child grants are strictly weaker)
- Mints **PCCBs** (Proof of Constrained Capability Bound) via the Kernel
- Runs the **broker** that resolves credentials and invokes adapters

Permit runs without Cloud. The `Actenon.local()` SDK constructor creates an
in-process Permit gateway with all of the above.

---

## 7. Kernel Boundary Verification

The Kernel is the open verifier + spec + conformance authority. It:
- Defines the PCCB data model and builder
- Defines the canonicalisation profile (`ACTENON-JCS-STRICT-1`)
- Verifies proofs at the edge (signature, action_hash, audience, expiry, replay)
- Issues nothing, enforces nothing — it only verifies

The Kernel can be adopted independently. A third-party proof that conforms
to the Kernel's conformance vectors will be accepted by the Kernel verifier.

```python
from actenon.proof import PCCBVerifier
verifier = PCCBVerifier()
verifier.verify(pccb, intent, action)  # raises ProofVerificationError on mismatch
```

---

## 8. Resource-Owned Integration

In resource-owned mode, the resource boundary independently verifies the
proof and decides whether to execute. The broker submits the request +
proof; the resource verifies and returns a signed receipt.

**Submission is NOT execution.** A submitted state is non-final. The
lifecycle stays at `submitted` until:
- The resource returns a cryptographically verified receipt → `succeeded`
- The resource refuses → `refused`
- No receipt is received → `outcome_unknown`

A forged receipt is forced to `outcome_unknown`, never `succeeded`.

Resource-owned requires adoption at the protected resource — the resource
must run its own Kernel verifier and sign receipts with its own key.

---

## 9. Protocol Implementation

The Protocol defines the wire format for proofs, receipts, refusals, and
execution results. Version 1.1.0 (Prompt 9 added the discriminated
`ExecutionResult` union).

- JSON Schemas: `schemas/*.v1.json`
- Python types: `actenon_protocol/` package
- Canonicalisation: JCS (RFC 8785 compatible, sorted keys, no whitespace)
- Refusal codes: two-layer disclosure model (public-safe + trusted-only)
- Execution modes: `brokered` and `resource_owned` (explicit on every artefact)

The Protocol is purely additive — v1.0.0 artefacts are valid under v1.1.0.

---

## 10. Evidence Verification

Evidence bundles contain 9 independent artefact layers, each with a SHA-256
hash. The bundle can be verified without trusting the Cloud UI:

```bash
# Retrieve the bundle
curl -H "Authorization: Bearer $TOKEN" \
  https://cloud.example.com/api/v1/intents/$INTENT_ID/evidence

# Verify it independently
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://cloud.example.com/api/v1/intents/$INTENT_ID/evidence/verify
```

**Receipts prove declared enforcement evidence, not the wisdom of the
authority decision.** See [INSURER_CLARITY.md](https://github.com/Actenon/actenon-cloud/blob/main/INSURER_CLARITY.md)
for the three separate questions (execution integrity, authority-process
integrity, business decision correctness).

---

## 11. Threat Model

| Threat | Mitigation |
|---|---|
| Proof forgery | HMAC-SHA256 / Ed25519 signatures; constant-time comparison |
| Signature confusion | Algorithm allow-list (EdDSA, ES256, RS256); HS256 deprecated |
| Canonicalisation ambiguity | JCS (RFC 8785); deterministic JSON serialisation |
| Replay | Single-use proofs + lifecycle state machine; idempotency keys |
| Concurrency | SQLite WAL + BEGIN IMMEDIATE; SQLAlchemy transactions |
| Idempotency | idempotency_key deduplicates; duplicate submit returns original |
| Issuer compromise | Key revocation + rotation; overlapping verification |
| Key rotation | SigningKeyReference: active/suspended/revoked/retired |
| SSRF | Adapter endpoints are configured, not user-supplied |
| Secret leakage | Credential never in logs, receipts, exceptions, or evidence |
| Credential theft | Broker resolves credential; agent never sees it |
| Cross-tenant access | RLS + Python-level checks; 404 on cross-tenant (no leak) |
| Approval bypass | Permission check (intent.approve); not just authenticated |
| Budget race | Atomic reserve+commit in SQLite transaction |
| Attenuation escalation | Child grant must be strictly weaker on every dimension |
| Cloud trust confusion | Cloud does NOT define proof validity; Kernel does |
| Resource-receipt forgery | HMAC-SHA256 verification; forged → outcome_unknown |
| Downgrade attacks | Protocol version pinned; v2.x rejected by v1.x verifier |
| Dependency compromise | Lockfiles; minimal deps (scan has zero) |
| Malicious provider responses | Redaction; outcome_unknown for partial responses |
| Log injection | Structured logging; no credential values in log fields |
| Oversized inputs | MAX_CANONICAL_OUTPUT_BYTES (1 MiB); MAX_JSON_DEPTH (100) |
| Denial of service | Rate limits; timeout handling; dead-letter queues |

---

## 12. Security Guarantees and Limitations

### Production-ready

| Component | Status |
|---|---|
| Credential encryption (AES-256-GCM) | ✅ Production-ready |
| Tenant isolation (RLS + Python checks) | ✅ Production-ready |
| Credential rotation + revocation | ✅ Production-ready |
| Execution workers (durable, retry, dead-letter) | ✅ Production-ready |
| Evidence bundles (9 layers, independent verification) | ✅ Production-ready |
| Signing key rotation + audit | ✅ Production-ready |
| Bearer token auth + permissions | ✅ Production-ready |
| Scan (independent, zero-dep) | ✅ Production-ready |
| Python SDK (sync + async) | ✅ Production-ready |
| TypeScript SDK (ESM, discriminated types) | ✅ Production-ready |
| Unified CLI | ✅ Production-ready |

### Pilot-ready (design-partner grade)

| Component | Status | Limitation |
|---|---|---|
| Ed25519 signing | ✅ Pilot-ready | Private key on disk, NOT KMS/HSM |
| Local evidence storage | ✅ Pilot-ready | Filesystem, NOT S3/GCS |
| Synchronous execution | ✅ Pilot-ready | No Celery/RQ (correct but blocking) |

### Stub (not production-ready)

| Component | Status | What's needed |
|---|---|---|
| KMS/HSM signing | ❌ Stub | Wire AWS KMS / GCP KMS / Azure Key Vault |
| OIDC authentication | ❌ Stub | Wire Auth0 / Okta / Keycloak |
| S3/GCS evidence storage | ❌ Stub | Implement S3/GCS backend |
| Multi-region | ❌ N/A | Infrastructure concern |
| Automated backups | ❌ N/A | Operations concern |

### Development-only configurations

- **Dev signing key**: auto-generated to `~/.actenon-permit/dev-signing-key`. Warning emitted. Refused in `production_mode=True`.
- **LocalDevSecretProvider**: credentials stored in process memory. Warning emitted. Refused in `production_mode=True`.
- **MOCK_*` env vars**: marked `development_only=True` by `EnvironmentSecretProvider`.

---

## 13. Migration

### From v0/v1 low-level APIs to the SDK

```python
# Before (25 lines)
grant = Grant(agent_id=..., scopes=..., budget=..., ...)
grant.sign()
store.put_grant(grant)
action = Action(grant_id=grant.id, type=..., params=..., est_cost=...)
decision, intent, pccb = pdp.decide_and_mint_pccb(grant, action, ctx={})
result = broker.execute_via_adapter(grant, action, decision, adapter, ...)

# After (10 lines)
client = Actenon.local(agent_id="my-agent", scopes=["issue.create"])
client.register_credential("GITHUB_TOKEN", "ghp_...")
client.register_adapter_tool("github_issue", ...)
intent = client.authorised_execution_intents.create(action=..., target=..., parameters=...)
result = intent.execute()
```

The low-level APIs are preserved. The SDK is the recommended surface, not
the only entry point.

### Version compatibility

| Protocol | Kernel | Permit | Cloud | Scan | SDK |
|---|---|---|---|---|---|
| 1.1.0 | 0.1.0 | 1.4.0 | 0.1.0 | 0.1.3 | 1.4.0 |

Protocol 1.1.0 is backward-compatible with 1.0.0 (purely additive).

---

## 14. API and SDK Reference

### Python SDK

```python
from actenon_permit import Actenon

# Sync
client = Actenon.local(agent_id=..., scopes=...)
intent = client.authorised_execution_intents.create(action=..., target=..., parameters=...)
result = intent.execute()  # -> BrokeredResult | ResourceOwnedResult

# Async
client = await Actenon.async_local(agent_id=..., scopes=...)
intent = await client.authorised_execution_intents.create(...)
result = await intent.execute_async()

# Cloud
client = Actenon.cloud(base_url=..., grant_token=...)
```

### TypeScript SDK

```typescript
import { Actenon } from "@actenon/sdk";

const client = Actenon.cloud({ baseUrl: "...", grantToken: "..." });
const intent = await client.authorisedExecutionIntents.create({ action: "...", target: "...", parameters: {...} });
const result = await intent.execute();
if (result.mode === "brokered" && result.state === "succeeded") { ... }
```

### CLI

```bash
actenon init           # initialise local project
actenon demo           # hero demo (8 guarantees)
actenon intent create  # create an intent
actenon intent execute # execute a brokered intent
actenon verify receipt # verify a resource receipt
actenon evidence list  # list local evidence
actenon scan           # run the execution-gap scanner
actenon doctor         # diagnose configuration
actenon version        # version info
```

### Cloud API

```
POST   /api/v1/intents                      create intent
GET    /api/v1/intents                      list intents
GET    /api/v1/intents/{id}                 retrieve intent
POST   /api/v1/intents/{id}/approve         approve (requires intent.approve)
POST   /api/v1/intents/{id}/execute         execute brokered (via PermitGatewayBridge)
POST   /api/v1/intents/{id}/submit          submit resource-owned
GET    /api/v1/intents/{id}/evidence        evidence bundle (9 layers)
POST   /api/v1/intents/{id}/evidence/verify verify bundle independently
GET    /api/v1/intents/{id}/outcome         honest outcome state
POST   /api/v1/credentials                  register credential (credential.manage)
```

---

## 15. Provider Adapter Development

```python
from actenon_permit.adapters import ProviderAdapter, ProviderResponse, ValidationResult

class MyAdapter(ProviderAdapter):
    provider_id = "my-provider"
    test_mode = False

    def supported_actions(self) -> list[str]:
        return ["my.action"]

    def validate_params(self, action: str, params: dict) -> ValidationResult:
        # Must reject unknown params — never silently drop.
        ...

    def execute(self, action, params, credential, *, idempotency_key=None, timeout_seconds=None):
        # credential.value is the secret — use it to authenticate, never log it.
        ...

    def map_response(self, action, raw) -> ProviderResponse:
        ...

    def reconcile(self, action, params, response) -> ProviderResponse:
        ...

    def redact(self, action, params, response) -> ProviderResponse:
        ...

    def health(self) -> dict:
        ...
```

See `actenon_permit/adapters/github.py` for the reference implementation.

---

## 16. Production Deployment

See [PRODUCTION_INTEGRATION.md](https://github.com/Actenon/actenon-cloud/blob/main/PRODUCTION_INTEGRATION.md)
for exactly what to wire:

1. **Signing**: KMS/HSM (interface exists, wire AWS KMS / GCP KMS / Azure)
2. **Credential master key**: Vault / Secrets Manager
3. **Evidence storage**: S3 / GCS
4. **Async execution**: Celery / RQ (optional)
5. **OIDC**: Auth0 / Okta / Keycloak
6. **Multi-region**: Managed Postgres + global LB
7. **Backups**: Managed DB automated backups

---

## 17. Troubleshooting

| Problem | Solution |
|---|---|
| "ephemeral dev signing key" warning | Run `actenon init` or set `ACTENON_SIGNING_KEY` |
| "credential missing" error | Register credential: `client.register_credential(ref, value)` |
| "lifecycle transition not allowed" | Check the state machine; terminal states cannot transition |
| "adapter does not support action" | Check `adapter.supported_actions()`; use namespaced names (`github.issue.create`) |
| Scan false positive | Register your guard: `actenon-scan init`, add to `guards` section |
| Scan false negative | Dynamic dispatch (`getattr`) is a known limitation; use static calls |
| TS SDK "registerCredential blocked in browser" | Correct — credentials must be registered server-side |
| Cross-tenant 404 | Expected — Cloud returns 404 (not 403) to avoid leaking existence |
| Resource-owned "submitted" not green | Correct — submission is not execution; wait for receipt |
