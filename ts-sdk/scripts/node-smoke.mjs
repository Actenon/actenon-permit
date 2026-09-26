// Import the built package in plain Node (no bundler, no Bun) and use it.
// Run after `bun run build`: node scripts/node-smoke.mjs
import assert from "node:assert/strict";

const sdk = await import("../dist/index.js");
for (const name of ["Actenon", "ExecutionRefusedError", "canonicalizeJson", "verifyResourceReceipt", "encodeGrantToken"]) {
  assert.ok(name in sdk, `missing export ${name}`);
}
const body = { receipt_id: "r1", amount: 5, signing_key_id: "k1" };
const secret = new TextEncoder().encode("s3cret");
const signature = sdk.computeReceiptSignature(body, secret);
assert.equal(sdk.verifyResourceReceipt({ ...body, signature }, new Map([["k1", secret]])), true);
await import("../dist/protocol.js");
await import("../dist/crypto.js");
console.log("node smoke: OK");
