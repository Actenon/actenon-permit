# Actenon-Permit

> The open authority broker. Issues signed grants, enforces at the edge, runs the credential broker. The recommended developer entry point for the Actenon ecosystem.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.9–3.12](https://img.shields.io/badge/Python-3.9%E2%80%933.12-blue.svg)](https://www.python.org/)
[![PyPI: actenon-permit](https://img.shields.io/pypi/v/actenon-permit?label=PyPI%20%C2%B7%20Python%20SDK)](https://pypi.org/project/actenon-permit/)
[![npm: @actenon/sdk](https://img.shields.io/npm/v/@actenon/sdk?label=npm%20%C2%B7%20TypeScript%20SDK)](https://www.npmjs.com/package/@actenon/sdk)
[![Grant v1.0](https://img.shields.io/badge/Grant%20Spec-v1.0-success.svg)](SPEC.md)
[![Boundary Kit](https://img.shields.io/badge/Boundary%20Kit-auto--discovery-orange.svg)](#boundary-kit--resource-boundary-protection-in-3-commands)
[![CI](https://github.com/Actenon/actenon-permit/actions/workflows/ci.yml/badge.svg)](https://github.com/Actenon/actenon-permit/actions/workflows/ci.yml)
[![Code style: ruff](https://img.shields.io/badge/Code%20style-ruff-black.svg)](https://docs.astral.sh/ruff/)
[![No Cloud required](https://img.shields.io/badge/Cloud-not%20required-2ea44f.svg)](#independence)

---

## The Actenon ecosystem

Permit is one of five independent repositories that together close the **execution gap** — the gap between *upstream authorization* and the *execution edge* that actually performs a consequential side effect.

| Repo | Role | Depends on |
|---|---|---|
| **`actenon-protocol`** | The neutral wire contract — what every artefact looks like on the wire | *nothing* |
| **`actenon-kernel`** | The open verifier — defines what a valid proof is | `actenon-protocol` |
| **`actenon-permit`** ← you are here | The developer on-ramp + authority broker — issues grants, runs the PDP, brokers credentials | `actenon-kernel`, `actenon-protocol` |
| **`actenon-cloud`** | The optional managed control plane — multi-tenant, hosted, evidence bundles | `actenon-kernel`, `actenon-permit` |
| **`actenon-scan`** | The independent static-analysis scanner — finds the execution gap in any codebase | *nothing* |

Permit is the **on-ramp**. If you are an engineer evaluating Actenon for the first time, this is the repo to start with. It runs **without Cloud** — the `Actenon.local()` SDK constructor gives you an in-process gateway with every feature below, no login, no API key, no hosted account.

---

## What this is

Permit is the **on-ramp** for protected AI-agent execution. It:

- **Issues signed grants** — capability tokens that are scoped, bounded (currency + spend cap + rate limit), expiring, revocable, and attenuable (UCAN-style sub-grants that can never exceed the parent on any dimension). Signed with HMAC-SHA256 (v0) or Ed25519 (pilot) over canonical JSON.
- **Runs the PDP** (Policy Decision Point) — deterministic `ALLOW` / `DENY` / `REQUIRE_APPROVAL` decisions per action, with structured reason codes.
- **Enforces budget, rate, scope, expiry, and approval rules** at decision time, atomically and race-free.
- **Runs the credential broker** — resolves credentials server-side, never gives them to the agent, supports 5 pluggable credential providers (static env, file, OIDC, cloud-secret-reference, custom callable).
- **Ships provider adapters** — starting with a reference `GitHubAdapter` (issue.create, issue.comment, branch.create, pr.open) with strict parameter validation, redaction, idempotency, and reconciliation.
- **Provides the Python SDK, TypeScript SDK, unified CLI, and Boundary Kit** — four first-class surfaces, all usable without Cloud.

Permit runs **without Cloud**. The `Actenon.local()` SDK constructor creates an in-process gateway with all of the above. You can build, test, and ship a protected agent without ever signing up for anything.

## Why it exists

The execution gap is not closed by authentication, policy, approval, or audit alone — those are all upstream controls. Permit is the layer that **binds an upstream decision to a specific execution edge** by:

1. Issuing a **Grant** that is narrow (scoped action types), bounded (budget + rate), expiring (absolute `expires_at`), and revocable (instant `status=revoked`).
2. MINTING a **PCCB** (via the Kernel) bound to the *exact* Action Intent — same action name, same target, same tenant, same subject, same audience, same parameters hash, same time window, single-use nonce.
3. Verifying that PCCB at the **protected endpoint** before any side effect.
4. **Brokering the credential** only after verification passes — the agent never sees the raw secret.
5. Emitting a canonical **Receipt** or **Refusal** that is independently verifiable.

The agent walks away with a Receipt it could not forge; the protected endpoint walks away with proof it actually verified; the auditor walks away with a hash-chained evidence trail. Read the canonical problem statement in [`actenon-kernel/THE_EXECUTION_GAP.md`](https://github.com/Actenon/actenon-kernel/blob/main/THE_EXECUTION_GAP.md).

## Install

```bash
pip install actenon-permit              # Python SDK + unified CLI + Boundary Kit
npm install @actenon/sdk                # TypeScript SDK v1.4.0 — discriminated result types, receipt verification, protocol parity with Python
```

## Hero quickstart (6 lines)

```python
from actenon_permit import Actenon, GitHubAdapter

client = Actenon.local(agent_id="my-agent", scopes=["issue.create"])
client.register_credential("GITHUB_TOKEN", "ghp_YOUR_TOKEN")
client.register_adapter_tool("github_issue",
    action_type="github.issue.create",
    adapter=GitHubAdapter(test_mode=True),
    credential_ref="GITHUB_TOKEN", target="github")

intent = client.authorised_execution_intents.create(
    action="github.issue.create", target="github",
    parameters={"owner": "Actenon", "repo": "example", "title": "Hello"})
result = intent.execute()
print(f"{result.state}  {result.finality}")   # succeeded  final
```

**The agent never sees the GitHub token.** The broker resolves it internally and passes it only to the adapter, only after the Kernel verifies the proof, only for the exact action bound to that proof, only once.

### TypeScript quickstart (parity with Python)

```typescript
import { Actenon } from "@actenon/sdk";

const client = Actenon.cloud({
  baseUrl: "http://localhost:7780",
  grantToken: "v1.YOUR_GRANT_TOKEN",
});

const intent = await client.authorisedExecutionIntents.create({
  action: "github.issue.create",
  target: "github",
  parameters: { title: "Hello from TS SDK", body: "Created through authorised execution." },
});

const result = await intent.execute();

// Result is a discriminated union — the TS compiler enforces mode-aware narrowing.
if (result.mode === "brokered" && result.state === "succeeded") {
  console.log("Issue created:", result.evidence);
  console.log("Receipt verified:", result.receiptVerified);
}
```

Full TypeScript docs in [`ts-sdk/README.md`](ts-sdk/README.md).

## The signed Grant — a capability token with teeth

A Grant is the digital analogue of a physical keycard with a budget and an expiry. The full spec is in [`SPEC.md`](SPEC.md). Each Grant is:

| Property | How it's enforced |
|---|---|
| **Signed** | HMAC-SHA256 (v0) or Ed25519 (pilot) over canonical JSON (`ACTENON-JCS-STRICT-1`). Constant-time comparison on verify. |
| **Scoped** | Explicit `allow[]` and `deny[]` action-type lists with glob matching (`payment.*`, `shell.exec`). `deny` wins. Default-deny when `allow` is non-empty. |
| **Bounded** | A currency, a hard `limit`, and a mutable `remaining` spend cap. Atomic decrement under a transaction; refusal at `REQUIRE_APPROVAL` thresholds. |
| **Rate-limited** | `{max, per_seconds}` sliding-window enforcement. |
| **Expiring** | Absolute `expires_at` timestamp. PDP transitions to `expired` on first decision after expiry. |
| **Revocable** | Issuer flips `status=revoked` at any time. Next decision is `DENY`. Revocation is logged with a timestamp. |
| **Attenuable** | Holder can derive a strictly-weaker sub-grant (UCAN-style delegation). The sub-grant can never exceed the parent on any dimension — narrower scope, smaller budget, shorter TTL, stricter approval rules. |
| **Bearer-transportable** | Wire format `v1.<base64url>` for HTTP / MCP transport. The Grant is the *capability*; the real secret stays in the broker. |

### Grant lifecycle states

`active` → `revoked` (issuer kill-switch) / `expired` (TTL elapsed) / `exhausted` (budget hit zero). All transitions are logged and reflected in the next PDP decision.

## The PDP — deterministic decisions

The Policy Decision Point returns one of three decisions for every action:

| Decision | Meaning | What happens next |
|---|---|---|
| `ALLOW` | The Grant is valid, scoped, in-budget, in-rate, not expired, not revoked, and no approval rule fires. | The Kernel mints a PCCB; the broker resolves the credential; the adapter executes; a Receipt is emitted. |
| `DENY` | The Grant is invalid, out-of-scope, out-of-budget, out-of-rate, expired, revoked, or the action is on the deny list. | A Refusal is emitted with a structured reason code. No proof is minted. No credential is resolved. |
| `REQUIRE_APPROVAL` | The action matches an approval rule (e.g. `email.send` always, or `payment.refund > 20`). | The intent is parked in `pending_approval`. An approver with `intent.approve` must approve or deny. Only then does the PDP run again with the approval attached. |

Decisions are **deterministic** — the same Grant + Action + state always produces the same decision. There is no model in the loop; there is no "vibes-based" allow.

## The credential broker — five pluggable providers

The broker is the only component that ever sees the raw credential value. It resolves a credential *reference* (a logical name like `"github_pat"` or `"aws_oidc_role"`) into a materialised `Credential` at call time — the moment a brokered action is about to execute — and drops the reference immediately after the adapter call returns.

| Provider type | When to use | `development_only`? |
|---|---|---|
| **Static environment** | Local dev, CI smoke tests | Yes — broker refuses in production mode |
| **File** | Mounted secrets, sidecar-injected material | Configurable |
| **OIDC** | Short-lived workload-identity tokens (AWS STS, GCP Workload Identity, GitHub OIDC) | No — sets `ttl_seconds`, broker refreshes before expiry |
| **Cloud secret reference** | AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault (broker calls the secrets API; never persists the value) | No |
| **Custom callable** | Your existing credential plumbing — anything that returns a `(value, ttl_seconds)` tuple | No |

The base class sets `__repr__ = "<redacted>"` to prevent accidental disclosure in tracebacks. Providers MUST NOT log, persist, or echo `.value`. Design rules are enforced by tests.

## The GitHub reference adapter

[`src/actenon_permit/adapters/github.py`](src/actenon_permit/adapters/github.py) is the first reference implementation of the `ProviderAdapter` contract. It supports four low-risk, consequential actions:

| Action type | What it does | Reversible? |
|---|---|---|
| `github.issue.create` | Open a new issue on a repository | Yes (close) |
| `github.issue.comment` | Add a comment to an existing issue | Yes (delete) |
| `github.branch.create` | Create a branch from a ref (default: repo default) | Yes (delete) |
| `github.pr.open` | Open a pull request from head → base | Yes (close) |

Design choices that make it a reference:

- **No destructive production actions** — no force-pushes, no repo deletions, no member additions. The adapter exposes only reversible actions.
- **Test mode** — when `test_mode=True`, the adapter does NOT touch the network. It returns deterministic mock responses with realistic shapes. This is what the safe end-to-end demo and the security tests use.
- **Strict parameter validation** — unknown fields are rejected with `InvalidParametersError`. Adapters must not silently ignore unsupported parameters.
- **Redaction** — the GitHub token never appears in any response field. Issue/PR URLs with token query params (defensive code is cheap) are stripped.
- **Idempotency** — GitHub's REST API supports `Idempotency-Key` on a subset of endpoints. Where unsupported, the adapter simulates idempotency in-process by caching `(key, params_hash) → response`. Duplicate keys with different params raise `InvalidParametersError`.
- **Reconciliation** — after `execute()` returns, the broker calls `reconcile()` which (in non-test mode) issues a GET to confirm the resource exists. In test mode, reconcile is a no-op.

## The unified CLI

```bash
actenon demo                          # full safe brokered demo (8 guarantees)
actenon protect quickstart ./my-api   # discover + apply + test in one command
actenon protect deploy --mode observe # staging rollout
actenon protect deploy --mode enforce # production
actenon scan                          # run the execution-gap scanner
actenon doctor                        # diagnose configuration
```

The CLI is the single entry point for the whole ecosystem — including Scan (which lives in a separate repo). It is intentionally a thin orchestrator: every subcommand maps to a function you can also call from the SDK.

## Boundary Kit — resource-boundary protection in 3 commands

The Boundary Kit converts resource-boundary protection from bespoke security code into reviewable configuration. The adoption flow:

```bash
# 1. Discover consequential endpoints + auto-extract parameter mappings
actenon protect quickstart ./my-api

# 2. Deploy in observe mode (safe rollout)
actenon protect deploy --mode observe

# 3. Switch to enforce
actenon protect deploy --mode enforce
```

The manifest is **~95% auto-generated**. Parameter types, target mappings, and action names are extracted from your FastAPI route signatures. The developer only reviews — they don't write mapping code.

What the Boundary Kit generates:

- `actenon.boundary.yaml` — a `BoundaryManifest` (per the Protocol) mapping HTTP routes to canonical Actenon actions, with parameter extraction rules, audience, target, and trusted-issuer config.
- `BoundaryMiddleware` — ASGI / WSGI middleware that intercepts protected routes, extracts parameters, builds a `BoundaryVerificationRequest`, calls the Kernel's `BoundaryVerifier`, and refuses on `valid=False` before the route handler runs.
- Auto-generated tests proving enforcement works for each protected route.

The Boundary Kit is the **resource-owned mode** implementation. Use it when the resource is the protected endpoint (Placement B in the Kernel README).

## The intent lifecycle — 14 states

Every consequential action enters the system as an `AuthorisedExecutionIntent` and walks through a 14-state lifecycle that prevents both premature execution and post-hoc mutation:

```
            ┌─────────────┐
            │   created   │
            └──────┬──────┘
                   ↓
            ┌─────────────┐
            │  evaluating │  ← PDP runs here
            └──────┬──────┘
                   ↓
        ┌──────────┴──────────┐
        ↓                     ↓
 ┌─────────────┐       ┌─────────────┐
 │   denied    │       │  allowed    │
 └─────────────┘       └──────┬──────┘
                               ↓
                       ┌─────────────────┐
                       │ pending_approval│ ← if REQUIRE_APPROVAL
                       └──────┬──────────┘
                              ↓
                  ┌───────────┴───────────┐
                  ↓                       ↓
           ┌─────────────┐         ┌─────────────┐
           │  approved   │         │  rejected   │
           └──────┬──────┘         └─────────────┘
                  ↓
           ┌─────────────┐
           │  reserving  │  ← budget + replay state reserved atomically
           └──────┬──────┘
                  ↓
           ┌─────────────┐
           │  executing  │  ← PCCB minted, broker resolves cred, adapter runs
           └──────┬──────┘
                  ↓
        ┌─────────┴─────────┐
        ↓                   ↓
 ┌─────────────┐     ┌─────────────┐
 │  succeeded  │     │   failed    │
 └──────┬──────┘     └─────────────┘
        ↓
 ┌─────────────┐
 │  committed  │  ← receipt durable, state final
 └─────────────┘

Plus: refused, cancelled, outcome_unknown
```

States are persisted atomically. The lifecycle is the source of truth — not the broker, not the adapter, not the agent. See [`src/actenon_permit/intent.py`](src/actenon_permit/intent.py).

## Brokered vs resource-owned execution

Permit supports **both** execution modes defined in the Protocol:

| Mode | How Permit is involved | When to use |
|---|---|---|
| `brokered` | Permit mints the PCCB, brokers the credential, runs the adapter, issues the Receipt. | You control the agent framework; you want the agent never to hold the production credential. |
| `resource_owned` | Permit mints the PCCB and hands it to the agent; the **resource** (your FastAPI route, Express endpoint, etc.) verifies it and issues the Receipt. | You cannot fully trust the agent, or the resource is shared by multiple callers, or the resource team is a separate org. |

In `resource_owned` mode, Permit still issues the Grant and mints the PCCB — but the verification step runs at the resource boundary, not in the broker. The Boundary Kit (above) is how you wire the resource side.

## What the agent never does

- **See the raw credential.** The broker resolves it internally and passes it only to the adapter.
- **Bypass proof verification.** The Kernel verifies at the edge; the broker will not resolve the credential until verification passes.
- **Exceed budget / scope / rate.** The PDP enforces at decision time; the lifecycle state machine prevents out-of-order execution.
- **Replay a proof.** Single-use PCCB + lifecycle state machine + durable replay store (atomic claim-once, not check-then-write). Replays are refused with `REPLAY_DETECTED`.
- **Mutate parameters after approval.** The PCCB binds the action-hash (SHA-256 over `ACTENON-JCS-STRICT-1` canonical JSON of the parameters). Any mutation is detected at the edge as `ACTION_HASH_MISMATCH` / `PARAMETER_DIGEST_MISMATCH`.
- **Forward proof to a different tool.** The PCCB binds `audience`. A proof minted for tool A is refused by tool B with `AUDIENCE_MISMATCH`. See the Kernel's [Multi-Agent Execution Model](https://github.com/Actenon/actenon-kernel/blob/main/MULTI_AGENT_EXECUTION_MODEL.md).
- **Silently ignore unsupported parameters.** Adapters reject unknown fields with `InvalidParametersError`.

## Insurer-facing clarity

Every consequential action that runs under Permit produces a cryptographic Receipt that answers the questions a claims adjuster will ask. The full insurer pitch is in [`docs/INSURER_PITCH.md`](docs/INSURER_PITCH.md). The short version:

| Question the adjuster asks | What the Receipt proves |
|---|---|
| Was this exact action authorized before it executed? | The PCCB was issued and signed before the edge released the credential. |
| Was the agent authorized for precisely this amount, target, and purpose? | The PCCB is bound to those exact parameters; any deviation was refused at the edge. |
| Could the logs have been altered after the fact? | No. Receipts are hash-chained into an append-only ledger; any modification is detectable. |
| Was the action replayed or reused? | No. Each proof is single-use with a unique nonce. |
| Was the agent's authority revoked in time? | The revocation is logged with a timestamp; calls after revocation are refused. |

The Kernel's [Insurer Clarity document](https://github.com/Actenon/actenon-cloud/blob/main/INSURER_CLARITY.md) separates three distinct questions — execution integrity, authority-process integrity, and business decision correctness — and is honest about which two cryptography can prove and which one it cannot.

## What's in this repo

| Component | Location |
|---|---|
| Python SDK (sync + async) | [`src/actenon_permit/sdk/`](src/actenon_permit/sdk/) |
| TypeScript SDK (`@actenon/sdk` v1.4.0 on npm) | [`ts-sdk/`](ts-sdk/) — discriminated results, receipt verification, protocol parity |
| Unified CLI | [`src/actenon_permit/unified_cli.py`](src/actenon_permit/unified_cli.py) |
| Boundary Kit (manifest + middleware + auto-discovery) | [`src/actenon_permit/boundary/`](src/actenon_permit/boundary/) |
| Credential providers (5 types) | [`src/actenon_permit/credentials.py`](src/actenon_permit/credentials.py) |
| Provider adapters (GitHub reference) | [`src/actenon_permit/adapters/`](src/actenon_permit/adapters/) |
| Intent lifecycle (14 states) | [`src/actenon_permit/intent.py`](src/actenon_permit/intent.py) |
| Brokered + resource-owned execution | [`src/actenon_permit/execution_modes.py`](src/actenon_permit/execution_modes.py) |
| PDP (decision engine) | [`src/actenon_permit/pdp.py`](src/actenon_permit/pdp.py) |
| Credential broker | [`src/actenon_permit/broker.py`](src/actenon_permit/broker.py) |
| Kernel bridge (PCCB mint + verify) | [`src/actenon_permit/kernel_bridge.py`](src/actenon_permit/kernel_bridge.py) |
| Atomic state store (reserve / commit / release) | [`src/actenon_permit/state.py`](src/actenon_permit/state.py) |
| Ed25519 signer | [`src/actenon_permit/ed25519_signer.py`](src/actenon_permit/ed25519_signer.py) |
| Hash-chained ledger | [`src/actenon_permit/ledger.py`](src/actenon_permit/ledger.py) |
| Grant spec | [`SPEC.md`](SPEC.md) |
| Insurer pitch | [`docs/INSURER_PITCH.md`](docs/INSURER_PITCH.md) |
| Demo policy | [`examples/refund-bot-policy.yaml`](examples/refund-bot-policy.yaml) |

## PyPI / npm

```bash
pip install actenon-permit              # Python SDK + CLI + Boundary Kit
npm install @actenon/sdk                # TypeScript SDK v1.4.0
```

## Independence

Permit depends on [`actenon-kernel`](https://github.com/Actenon/actenon-kernel) (runtime) and [`actenon-protocol`](https://github.com/Actenon/actenon-protocol) (runtime). It does **not** depend on Cloud or Scan. The SDK, CLI, and Boundary Kit all work without Cloud — `Actenon.local()` gives you the full feature set in-process.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
