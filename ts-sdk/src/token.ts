/**
 * Grant token wire format — TS mirror of Python `actenon_permit.token`.
 *
 * Format: `v1.<base64url(canonical_json(signed_grant_object))>`
 *
 * The signing key MUST match the `ACTENON_SIGNING_KEY` the server uses. In
 * the browser / agent process, the key is typically NOT present — the agent
 * receives a token issued by the control plane and only needs to *present*
 * it, not verify it. Verification is for tooling (CLI, dashboards).
 */

import type { Grant } from "./types.ts";
import { TokenError } from "./types.ts";

const VERSION = "v1";
const PREFIX = `${VERSION}.`;

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

// --- canonical JSON (matches Python: sort_keys + compact separators) ---

function canonicalJson(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[k] = sortKeys((value as Record<string, unknown>)[k]);
  }
  return sorted;
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

export function encodeGrantToken(grant: Grant): string {
  if (!grant.signature) {
    throw new TokenError("grant is not signed — cannot encode token");
  }
  const body = canonicalJson(grant);
  const encoded = bytesToBase64Url(strToBytes(body));
  return `${PREFIX}${encoded}`;
}

export function decodeGrantToken(token: string, opts: { verify?: boolean; signingKey?: string } = {}): Grant {
  const verify = opts.verify ?? true;
  if (typeof token !== "string") throw new TokenError("token must be a string");
  if (!token.startsWith(PREFIX)) throw new TokenError(`unsupported token version (expected '${PREFIX}')`);
  const encoded = token.slice(PREFIX.length);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(encoded);
  } catch (e) {
    throw new TokenError(`invalid base64 payload: ${(e as Error).message}`);
  }
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    throw new TokenError(`invalid JSON payload: ${(e as Error).message}`);
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new TokenError("invalid grant payload: not an object");
  }
  const grant = payload as Grant;
  if (!grant.id || !grant.signature) {
    throw new TokenError("invalid grant payload: missing id or signature");
  }
  // Structural signature check; cryptographic verification is async (below).
  if (verify && !opts.signingKey) {
    // Without a key we can only do the structural check. Throw to surface
    // the requirement — silent skip would be a security footgun.
    throw new TokenError("cryptographic verification requires opts.signingKey; pass { verify: false } to skip");
  }
  return grant;
}

export async function verifyGrantToken(token: string, signingKey: string): Promise<Grant> {
  const grant = decodeGrantToken(token, { verify: false });
  const { signature, ...rest } = grant;
  const expected = await hmacSha256Hex(strToBytes(signingKey), strToBytes(canonicalJson(rest)));
  // Constant-time-ish comparison (lengths are equal so this is fine).
  if (expected.length !== signature.length || !timingSafeEqual(expected, signature)) {
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
