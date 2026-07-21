/**
 * Actenon-Permit TypeScript SDK — public entry point.
 *
 * Use this SDK to talk to an Actenon-Permit control plane + gateway from
 * TypeScript / JavaScript agents. For Python agents, use the `actenon_permit`
 * package directly.
 *
 * @example
 * ```ts
 * import { ControlPlaneClient, GatewayClient } from "@actenon/permit-sdk";
 *
 * const cp = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:7780" });
 * const grant = await cp.issueGrant({
 *   agent: "refund-bot",
 *   ttl: "1h",
 *   budget: { currency: "USD", limit: 50 },
 *   scopes: { allow: ["payment.refund"], deny: ["payment.charge"] },
 * });
 * const { token } = await cp.mintToken(grant.id);
 *
 * const gw = new GatewayClient({ baseUrl: "http://127.0.0.1:7780", grantToken: token });
 * const result = await gw.callTool("refund", { amount: 20, reason: "customer" });
 * ```
 */

export * from "./types.ts";
export * from "./token.ts";
export { ControlPlaneClient } from "./client.ts";
export type { ControlPlaneClientOptions } from "./client.ts";
export { GatewayClient } from "./gateway-client.ts";
export type { GatewayClientOptions } from "./gateway-client.ts";
