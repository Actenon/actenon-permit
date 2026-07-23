/**
 * Actenon TypeScript SDK — canonicalisation + receipt verification.
 *
 * Parity with Python `actenon_permit.sdk.receipt` and
 * `actenon_protocol.canonicalisation`.
 *
 * The canonicalisation is JCS (JSON Canonicalization Scheme, RFC 8785)
 * compatible — sorted keys, no insignificant whitespace, UTF-8 encoded.
 * This is the same canonicalisation used by the Kernel's
 * `actenon-jcs-sha256-v1` profile and by the `ResourceReceiptVerifier`.
 */

// ---------------------------------------------------------------------------
// Canonical JSON (parity: actenon_protocol.canonicalisation.canonicalize_json)
// ---------------------------------------------------------------------------

/**
 * Canonicalise a JSON-serialisable value using JCS-compatible rules:
 *   - sorted object keys (lexicographic byte order)
 *   - no insignificant whitespace
 *   - UTF-8 encoded
 *
 * This matches Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
 */
export function canonicalizeJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  const obj = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortKeys(obj[key]);
  }
  return sorted;
}

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
  // Use Node's crypto module (available in Node 18+).
  // In a browser, this would need a polyfill or Web Crypto (async).
  const { createHmac } = require("node:crypto") as typeof import("node:crypto");
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
