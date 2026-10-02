/**
 * Actenon TypeScript SDK — canonicalisation + receipt verification.
 *
 * Parity with Python `actenon_permit.sdk.receipt`. Receipts are signed over
 * the ASCII-escaped `json.dumps(sort_keys=True, separators=(",", ":"))`
 * encoding the kernel's `ResourceReceiptVerifier` uses (`canonicalizeJson`).
 * That is NOT ACTENON-JCS-STRICT-1 for non-ASCII strings; the strict profile
 * is `canonicalizeStrictJson`. Both live in `canonical.ts`.
 */

import { createHmac } from "node:crypto";

// ---------------------------------------------------------------------------
// Canonical JSON (see canonical.ts: the receipt encoding is the ASCII-escaped one)
// ---------------------------------------------------------------------------

import { canonicalizeJson } from "./canonical.js";

export { CanonicalizationError, canonicalizeJson, canonicalizeStrictJson } from "./canonical.js";

// ---------------------------------------------------------------------------
// HMAC-SHA256 receipt verification
// (parity: actenon_permit.sdk.receipt.verify_resource_receipt)
// ---------------------------------------------------------------------------

/**
 * Verify a resource receipt's HMAC-SHA256 signature.
 *
 * @param receipt - The receipt object. Must contain `signing_key_id` and
 *   `signature` fields.
 * @param signingKeys - A map of key id -> secret bytes.
 * @returns true iff the signature matches the canonical body computed
 *   with the key identified by `signing_key_id`.
 *
 * @example
 * ```ts
 * import { verifyResourceReceipt } from "@actenon/sdk";
 *
 * const verified = verifyResourceReceipt(
 *   { charge_id: "ch_123", signing_key_id: "rk_1", signature: "abc..." },
 *   new Map([["rk_1", new TextEncoder().encode("the-secret")]]),
 * );
 * if (!verified) throw new Error("forged receipt!");
 * ```
 */
export function verifyResourceReceipt(
  receipt: Record<string, unknown>,
  signingKeys: Map<string, Uint8Array>,
): boolean {
  const keyId = receipt["signing_key_id"] as string | undefined;
  const signature = receipt["signature"] as string | undefined;
  if (!keyId || !signature) return false;

  const secret = signingKeys.get(keyId);
  if (!secret) return false;

  // Build the body (everything except 'signature') and canonicalise.
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(receipt)) {
    if (k !== "signature") body[k] = v;
  }
  const canonical = canonicalizeJson(body);

  // Compute HMAC-SHA256 using Web Crypto (available in Node 18+ and browsers).
  // This is async in Web Crypto, but we provide a sync fallback using
  // Node's crypto module when available.
  return verifyHmacSha256Sync(canonical, secret, signature);
}

/**
 * Compute the HMAC-SHA256 signature for a receipt body.
 *
 * @param body - The receipt body (without the `signature` field).
 * @param secret - The signing key secret.
 * @returns The hex-encoded signature.
 */
export function computeReceiptSignature(
  body: Record<string, unknown>,
  secret: Uint8Array,
): string {
  const canonical = canonicalizeJson(body);
  return hmacSha256HexSync(canonical, secret);
}

// ---------------------------------------------------------------------------
// Sync HMAC-SHA256 (uses Node's crypto module)
// ---------------------------------------------------------------------------

function verifyHmacSha256Sync(
  message: string,
  secret: Uint8Array,
  expectedHex: string,
): boolean {
  const actualHex = hmacSha256HexSync(message, secret);
  return timingSafeEqual(actualHex, expectedHex);
}

function hmacSha256HexSync(message: string, secret: Uint8Array): string {
  // Node's crypto module (Node 18+), imported statically: `require` does
  // not exist in an ES module under Node.
  const hmac = createHmac("sha256", Buffer.from(secret));
  hmac.update(message, "utf-8");
  return hmac.digest("hex");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
