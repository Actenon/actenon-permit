# @actenon/sdk

The official TypeScript SDK for [Actenon](https://github.com/Actenon/actenon-permit) —
protected execution for AI agents with discriminated result types, receipt
verification, and protocol parity with the Python SDK.

## Installation

```bash
npm install @actenon/sdk
# or
bun add @actenon/sdk
# or
yarn add @actenon/sdk
```

## Quickstart

```typescript
import { Actenon } from "@actenon/sdk";

const client = Actenon.cloud({
  baseUrl: "http://localhost:7780",
  grantToken: "v1.YOUR_GRANT_TOKEN",
});

const intent = await client.authorisedExecutionIntents.create({
  action: "github.issue.create",
  target: "github",
  parameters: {
    title: "Hello from TS SDK",
    body: "Created through authorised execution.",
  },
});

const result = await intent.execute();

// Result is a discriminated union — you MUST narrow on `mode`.
if (result.mode === "brokered" && result.state === "succeeded") {
  console.log("Issue created:", result.evidence);
  console.log("Receipt verified:", result.receiptVerified);
}
```

## Type safety

Results are discriminated unions. The TypeScript compiler enforces mode-aware
interpretation — you cannot access `receiptVerified` on a `resource_owned`
result without first narrowing:

```typescript
// ✅ Correct — narrowing on mode
if (result.mode === "brokered") {
  console.log(result.receiptVerified); // OK
} else {
  console.log(result.resourceReceiptVerified); // OK
}

// ❌ Type error — no narrowing
console.log(result.receiptVerified); // Error: Property does not exist on ResourceOwnedResult
```

This prevents the unsafe pattern:

```typescript
// ❌ Not allowed — result.state is not enough; you must understand who executed it
if (result.state === "succeeded") {
  // Without checking result.mode, you don't know if this was brokered or resource-owned
}
```

## Discriminated results

### BrokeredResult

```typescript
interface BrokeredResult {
  mode: "brokered";
  intentId: string;
  state: "succeeded" | "failed" | "refused" | "outcome_unknown";
  finality: "final" | "non_final";
  providerExecutionObserved: boolean;
  receiptReceived: boolean;
  receiptVerified: boolean;
  evidence: Record<string, unknown>;
  attemptId: string | null;
}
```

### ResourceOwnedResult

```typescript
interface ResourceOwnedResult {
  mode: "resource_owned";
  intentId: string;
  state: "submitted" | "accepted" | "refused" | "succeeded" | "failed" | "outcome_unknown";
  finality: "final" | "non_final";
  providerExecutionObserved: boolean;
  resourceReceiptReceived: boolean;
  resourceReceiptVerified: boolean;
  submissionReference: string | null;
  evidence: Record<string, unknown>;
  attemptId: string | null;
}
```

## Structured exceptions

```typescript
import { ExecutionRefusedError, OutcomeUnknownError } from "@actenon/sdk";

try {
  const result = await intent.execute();
} catch (e) {
  if (e instanceof ExecutionRefusedError) {
    console.error("refused:", e.message, "rule:", e.rule);
  } else if (e instanceof OutcomeUnknownError) {
    console.error("outcome unknown (retryable):", e.message);
  }
}
```

| Exception | When | Retryable |
|---|---|---|
| `ExecutionRefusedError` | Action refused (out of scope, proof invalid) | No |
| `ExecutionFailedError` | Provider call failed | No |
| `OutcomeUnknownError` | Timeout, partial response | Yes |
| `ProviderError` | Adapter crash | Depends |
| `IntentNotFoundError` | Intent id not found | No |

## Receipt verification

```typescript
import { verifyResourceReceipt } from "@actenon/sdk";

const verified = verifyResourceReceipt(
  { charge_id: "ch_123", signing_key_id: "rk_1", signature: "abc..." },
  new Map([["rk_1", new TextEncoder().encode("the-secret")]]),
);
if (!verified) throw new Error("forged receipt!");
```

## Capabilities

```typescript
const caps = client.capabilities;
// {
//   transport: "cloud",
//   supportsBrokered: true,
//   supportsResourceOwned: true,
//   supportsAsync: true,
//   supportsPolling: true,
//   durable: true,
//   productionMode: true
// }
```

## Environment support

| Environment | Supported | Notes |
|---|---|---|
| Node.js 18+ (LTS) | ✅ | Primary target. Uses `node:crypto` for HMAC. |
| Node.js 20+ (LTS) | ✅ | Recommended. |
| Node.js 22+ (LTS) | ✅ | |
| Bun | ✅ | Tested with Bun 1.3+. |
| Deno | ⚠️ | Should work via npm: specifier; not tested. |
| Browser | ⚠️ | Receipt verification works (uses Web Crypto). **Credential registration is blocked** — secret-bearing broker code must not run in an untrusted browser. |
| ESM | ✅ | `"type": "module"` |
| CommonJS | ❌ | Not supported. ESM-only. |

### Browser safety

The SDK blocks `registerCredential()` and `registerResourceFromConfig()` in
browser environments. These methods require server-side execution because they
handle secret material. Browser clients should only use `Actenon.cloud()` to
talk to a server-side gateway that holds the credentials.

## Python parity

The TypeScript and Python SDKs agree on all protocol-level semantics:

| Feature | Python | TypeScript | Parity |
|---|---|---|---|
| Lifecycle states | 14 states | 14 states | ✅ |
| Execution modes | brokered, resource_owned | brokered, resource_owned | ✅ |
| Brokered result states | succeeded, failed, refused, outcome_unknown | same | ✅ |
| Resource-owned result states | 6 states | 6 states | ✅ |
| Finality | final, non_final | final, non_final | ✅ |
| Discriminated union | `BrokeredResult \| ResourceOwnedResult` | `BrokeredResult \| ResourceOwnedResult` | ✅ |
| Receipt verification | HMAC-SHA256, canonical JSON | HMAC-SHA256, canonical JSON | ✅ |
| Canonicalisation | JCS (sorted keys, no whitespace) | JCS (sorted keys, no whitespace) | ✅ |
| Exception hierarchy | `ActenonError` → 6 subclasses | `ActenonError` → 6 subclasses | ✅ |
| Retryability | `.retryable` property | `.retryable` property | ✅ |
| Capability info | `CapabilityInfo` dataclass | `CapabilityInfo` interface | ✅ |

### Known differences from Python

| Aspect | Python | TypeScript | Reason |
|---|---|---|---|
| Sync API | ✅ `Actenon.local()` sync | ❌ async only | TS is async-first; sync broker calls would block the event loop |
| In-process broker | ✅ `LocalActenonClient` runs broker in-process | ❌ HTTP to local gateway | Secret-bearing code must stay server-side in TS |
| Signing key auto-gen | ✅ `~/.actenon-permit/dev-signing-key` | ❌ server-side only | TS SDK doesn't run the broker in-process |
| Naming | `snake_case` (e.g. `provider_execution_observed`) | `camelCase` (e.g. `providerExecutionObserved`) | Idiomatic TS |
| Dev signing key warning | ✅ `UserWarning` | ❌ N/A (server-side) | TS SDK doesn't auto-gen keys |

## Build

```bash
bun install
bun run build        # tsc → dist/
bun run typecheck    # tsc --noEmit
bun test             # run tests
```

## License

Apache-2.0
