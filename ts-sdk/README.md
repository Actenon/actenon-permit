# @actenon/permit-sdk

TypeScript SDK for [Actenon-Permit](https://github.com/Actenon/actenon-permit) — the open authority broker for AI agents.

## Install

```bash
bun install @actenon/permit-sdk
# or
npm install @actenon/permit-sdk
```

## Quick start

```typescript
import { ControlPlaneClient, GatewayClient } from "@actenon/permit-sdk";

// 1. Issue a grant via the control plane
const cp = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:7780" });
const grant = await cp.issueGrant({
  agent: "refund-bot",
  ttl: "1h",
  budget: { currency: "USD", limit: 50 },
  scopes: {
    allow: ["payment.refund", "email.send"],
    deny: ["payment.charge", "shell.*"],
  },
  rate: { max: 20, per: "1m" },
  approval: { require_human: ["email.send"] },
});

// 2. Mint a bearer token
const { token } = await cp.mintToken(grant.id);

// 3. Call a guarded tool through the gateway
const gw = new GatewayClient({ baseUrl: "http://127.0.0.1:7780", grantToken: token });
const result = await gw.callTool("refund", { amount: 20, reason: "customer" });
console.log(result);
```

## Over-budget denial

```typescript
import { PermitDenied } from "@actenon/permit-sdk";

try {
  await gw.callTool("refund", { amount: 60 });
} catch (e) {
  if (e instanceof PermitDenied) {
    console.log(e.reason);      // "would exceed USD 50 budget"
    console.log(e.rule_matched); // "reserve"
  }
}
```

## Ledger verification

```typescript
const entries = await cp.listLedger(grant.id);
const { ok } = await cp.verifyLedger();
console.log(`ledger intact: ${ok}, entries: ${entries.length}`);
```

## Token operations

```typescript
import { encodeGrantToken, decodeGrantToken, verifyGrantToken } from "@actenon/permit-sdk";

const token = encodeGrantToken(grant);
const decoded = decodeGrantToken(token, { verify: false });
const verified = await verifyGrantToken(token, signingKey);
```

## Running the tests

```bash
cd ts-sdk
bun install
bun run typecheck
bun test
```

The tests spawn a real Python gateway server, so you need `uv` and Python 3.11+ on your PATH.

## API reference

### ControlPlaneClient

| Method | Description |
|---|---|
| issueGrant(policy) | Create a signed grant from a policy object |
| mintToken(grantId) | Mint a v1 bearer token for a grant |
| listGrants(agentId?) | List grants, optionally filtered by agent |
| getGrant(grantId) | Get a single grant by ID |
| revokeGrant(grantId) | Kill switch — revoke a grant |
| attenuateGrant(grantId, req) | Derive a strictly-weaker sub-grant |
| listApprovals() | List pending approvals |
| approve(actionId) | Approve a pending action |
| deny(actionId) | Deny a pending action |
| listLedger(grantId?, limit?) | Read the action log |
| verifyLedger() | Verify the hash chain |

### GatewayClient

| Method | Description |
|---|---|
| listTools() | List available tools |
| callTool(toolName, args) | Call a guarded tool; returns result on ALLOW, throws PermitDenied on DENY |

### Errors

- PermitDenied — thrown when the gateway denies a tool call. Has .reason, .rule_matched, .action_id, .grant_id.
- PermitError — base class for all SDK errors.
- TokenError — token encoding/decoding errors.

## License

Apache-2.0
