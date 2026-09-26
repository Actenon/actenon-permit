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

import { createHmac } from "node:crypto";

// ---------------------------------------------------------------------------
// Canonical JSON (parity: actenon_protocol.canonicalisation.canonicalize_json)
// ---------------------------------------------------------------------------

/** Thrown when a value has no single canonical encoding shared with Python. */
export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

/**
 * Canonicalise a JSON value exactly as the Python reference does
 * (`json.dumps(obj, sort_keys=True, separators=(",", ":"))`, used by the
 * kernel's ResourceReceiptVerifier):
 *   - object keys sorted by Unicode code point (not UTF-16 code unit)
 *   - no insignificant whitespace
 *   - every non-ASCII character escaped as lowercase `\uXXXX`
 *     (surrogate pairs as two escapes), control characters as Python does
 *
 * Fails closed (throws `CanonicalizationError`) on values whose encoding
 * would differ between languages or silently lose information: numbers
 * that are not safe integers (floats, -0, NaN, Infinity, |n| > 2^53-1),
 * unpaired surrogates, and anything that is not a plain JSON value
 * (undefined, functions, symbols, bigint, Date, Map, Set, class instances).
 */
export function canonicalizeJson(value: unknown): string {
  return canon(value, "$");
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function quote(s: string, path: string): string {
  if (LONE_SURROGATE.test(s)) {
    throw new CanonicalizationError(`${path}: unpaired surrogate has no UTF-8 encoding`);
  }
  return JSON.stringify(s).replace(
    /[\u0080-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

function compareCodePoints(a: string, b: string): number {
  const ca = Array.from(a, (c) => c.codePointAt(0) as number);
  const cb = Array.from(b, (c) => c.codePointAt(0) as number);
  for (let i = 0; i < Math.min(ca.length, cb.length); i++) {
    if (ca[i] !== cb[i]) return ca[i] - cb[i];
  }
  return ca.length - cb.length;
}

function canon(value: unknown, path: string): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new CanonicalizationError(`${path}: ${value} is not a safe integer`);
      }
      return String(value);
    case "string":
      return quote(value, path);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v, i) => canon(v, `${path}[${i}]`)).join(",") + "]";
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new CanonicalizationError(`${path}: not a plain JSON object`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort(compareCodePoints);
      return (
        "{" +
        keys.map((k) => quote(k, path) + ":" + canon(obj[k], `${path}.${k}`)).join(",") +
        "}"
      );
    }
    default:
      throw new CanonicalizationError(`${path}: ${typeof value} is not a JSON value`);
  }
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
