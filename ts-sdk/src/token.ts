/**
 * Grant token wire format — TS mirror of Python `actenon_permit.token`.
 *
 * Formats:
 *   `v2.<base64url(ACTENON-JCS-STRICT-1(signed_grant_object))>` — minted from 2.0.0
 *   `v1.<base64url(json(signed_grant_object))>`                — pre-2.0.0, verify-only
 *
 * The HMAC-SHA256 signature covers the grant minus `signature`, encoded with
 * the canonicaliser of the token's version: ACTENON-JCS-STRICT-1 for `v2.`
 * (literal UTF-8), Python's ASCII-escaping `json.dumps(sort_keys=True)` for
 * `v1.`. `v1.` tokens are accepted until actenon-permit 3.0.0.
 *
 * The signing key MUST match the `ACTENON_SIGNING_KEY` the server uses. In
 * the browser / agent process, the key is typically NOT present — the agent
 * receives a token issued by the control plane and only needs to *present*
 * it, not verify it. Verification is for tooling (CLI, dashboards).
 */

import { canonicalizeJson, canonicalizeStrictJson } from "./canonical.js";
import type { Grant } from "./types.js";
import { TokenError } from "./types.js";

const PREFIX_V1 = "v1.";
const PREFIX_V2 = "v2.";

type TokenVersion = "v1" | "v2";

// --- base64url helpers (browser + node compatible) ---

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = typeof btoa === "function"
    ? btoa(bin)
    : Buffer.from(bin, "binary").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// --- HMAC-SHA256 via Web Crypto (browser + node >= 15) ---

async function hmacSha256Hex(key: Uint8Array, message: Uint8Array): Promise<string> {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj?.subtle) {
    throw new TokenError("Web Crypto API not available — cannot compute HMAC");
  }
  const keyObj = await cryptoObj.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const sig = await cryptoObj.subtle.sign("HMAC", keyObj, message as BufferSource);
  const bytes = new Uint8Array(sig);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function strToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// --- public API ---

/** Encode a signed grant as a `v2.` token (ACTENON-JCS-STRICT-1 body). */
export function encodeGrantToken(grant: Grant): string {
  if (!grant.signature) {
    throw new TokenError("grant is not signed — cannot encode token");
  }
  return `${PREFIX_V2}${bytesToBase64Url(strToBytes(canonicalizeStrictJson(grant)))}`;
}

function splitToken(token: unknown): { version: TokenVersion; encoded: string } {
  if (typeof token !== "string") throw new TokenError("token must be a string");
  if (token.startsWith(PREFIX_V2)) return { version: "v2", encoded: token.slice(PREFIX_V2.length) };
  if (token.startsWith(PREFIX_V1)) return { version: "v1", encoded: token.slice(PREFIX_V1.length) };
  throw new TokenError(`unsupported token version (expected '${PREFIX_V1}' or '${PREFIX_V2}')`);
}

function parsePayload(encoded: string): Grant {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(encoded);
  } catch (e) {
    throw new TokenError(`invalid base64 payload: ${(e as Error).message}`);
  }
  let payload: unknown;
  try {
    // fatal: invalid UTF-8 is an error (as in Python), not a silent U+FFFD.
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (e) {
    throw new TokenError(`invalid JSON payload: ${(e as Error).message}`);
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new TokenError("invalid grant payload: not an object");
  }
  const grant = payload as Grant;
  if (!grant.id || typeof grant.signature !== "string" || !grant.signature) {
    throw new TokenError("invalid grant payload: missing id or signature");
  }
  return grant;
}

export function decodeGrantToken(token: string, opts: { verify?: boolean; signingKey?: string } = {}): Grant {
  const verify = opts.verify ?? true;
  const { encoded } = splitToken(token);
  const grant = parsePayload(encoded);
  // Structural signature check; cryptographic verification is async (below).
  if (verify && !opts.signingKey) {
    // Without a key we can only do the structural check. Throw to surface
    // the requirement — silent skip would be a security footgun.
    throw new TokenError("cryptographic verification requires opts.signingKey; pass { verify: false } to skip");
  }
  return grant;
}

export async function verifyGrantToken(token: string, signingKey: string): Promise<Grant> {
  const { version, encoded } = splitToken(token);
  const grant = parsePayload(encoded);
  const { signature, ...rest } = grant;
  let signed: string;
  try {
    signed = version === "v2" ? canonicalizeStrictJson(rest) : canonicalizeJson(rest);
  } catch (e) {
    throw new TokenError(`grant payload has no canonical encoding: ${(e as Error).message}`);
  }
  const expected = await hmacSha256Hex(strToBytes(signingKey), strToBytes(signed));
  if (!timingSafeEqual(expected, signature)) {
    throw new TokenError("signature verification failed — token is forged or was signed with a different key");
  }
  return grant;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
