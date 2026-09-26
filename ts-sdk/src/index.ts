/**
 * @actenon/sdk — the official Actenon TypeScript SDK.
 *
 * Provides protected execution for AI agents with discriminated result
 * types, receipt verification, and protocol parity with the Python SDK.
 *
 * @example
 * ```ts
 * import { Actenon } from "@actenon/sdk";
 *
 * const client = Actenon.cloud({
 *   baseUrl: "http://localhost:7780",
 *   grantToken: "v1.YOUR_TOKEN",
 * });
 *
 * const intent = await client.authorisedExecutionIntents.create({
 *   action: "github.issue.create",
 *   target: "github",
 *   parameters: { title: "Hello from TS SDK" },
 * });
 *
 * const result = await intent.execute();
 * if (result.mode === "brokered" && result.state === "succeeded") {
 *   console.log("succeeded:", result.evidence);
 * }
 * ```
 *
 * @module
 */

// Protocol types (parity with Python actenon_protocol + actenon_permit.sdk)
export * from "./protocol.js";

// Crypto helpers (canonicalisation + receipt verification)
export {
  CanonicalizationError,
  canonicalizeJson,
  computeReceiptSignature,
  verifyResourceReceipt,
} from "./crypto.js";

// Client (Actenon.local / Actenon.cloud)
export { Actenon, ActenonClient, CloudActenonClient, LocalActenonClient } from "./client.js";

// Legacy v1 exports (backward compat with the existing TS SDK)
export * from "./types.js";
export * from "./token.js";
export { ControlPlaneClient } from "./legacy-client.js";
export type { ControlPlaneClientOptions } from "./legacy-client.js";
export { GatewayClient } from "./gateway-client.js";
export type { GatewayClientOptions } from "./gateway-client.js";
