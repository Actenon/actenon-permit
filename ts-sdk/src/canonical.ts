/**
 * Canonical JSON for the Actenon TypeScript SDK. No Node-only imports, so the
 * grant-token module stays usable in browsers.
 *
 * Two encodings, both fail-closed on values with no single cross-language
 * encoding (non-safe-integer numbers, -0, unpaired surrogates, anything that
 * is not a plain JSON value):
 *
 * - `canonicalizeJson` (ASCII-escaped): Python's
 *   `json.dumps(obj, sort_keys=True, separators=(",", ":"))`. Every non-ASCII
 *   character is written as lowercase `\uXXXX` (surrogate pairs as two
 *   escapes). The kernel's ResourceReceiptVerifier and pre-2.0.0 (`v1.`)
 *   grant-token signatures use it.
 * - `canonicalizeStrictJson`: ACTENON-JCS-STRICT-1
 *   (`actenon_protocol.canonicalize_json`). Non-ASCII characters are literal
 *   UTF-8, and nesting deeper than 32 levels is refused. `v2.` grant tokens
 *   use it.
 *
 * Both sort object keys by Unicode code point, which equals UTF-8 byte order
 * (not RFC 8785's UTF-16 code-unit order).
 */

/** Thrown when a value has no single canonical encoding shared with Python. */
export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

/** ACTENON-JCS-STRICT-1 `MAX_JSON_DEPTH` (actenon_protocol.canonicalisation). */
export const STRICT_MAX_JSON_DEPTH = 32;

/**
 * Canonicalise a JSON value as Python's ASCII-escaping
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))` does.
 */
export function canonicalizeJson(value: unknown): string {
  return canon(value, "$", true, 0, Number.POSITIVE_INFINITY);
}

/** Canonicalise a JSON value under ACTENON-JCS-STRICT-1 (literal UTF-8, depth <= 32). */
export function canonicalizeStrictJson(value: unknown): string {
  return canon(value, "$", false, 0, STRICT_MAX_JSON_DEPTH);
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function quote(s: string, path: string, asciiEscape: boolean): string {
  if (LONE_SURROGATE.test(s)) {
    throw new CanonicalizationError(`${path}: unpaired surrogate has no UTF-8 encoding`);
  }
  const json = JSON.stringify(s);
  if (!asciiEscape) return json;
  return json.replace(/[\u0080-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

function compareCodePoints(a: string, b: string): number {
  const ca = Array.from(a, (c) => c.codePointAt(0) as number);
  const cb = Array.from(b, (c) => c.codePointAt(0) as number);
  for (let i = 0; i < Math.min(ca.length, cb.length); i++) {
    if (ca[i] !== cb[i]) return ca[i] - cb[i];
  }
  return ca.length - cb.length;
}

function canon(value: unknown, path: string, asciiEscape: boolean, depth: number, maxDepth: number): string {
  if (depth > maxDepth) {
    throw new CanonicalizationError(`${path}: JSON depth exceeds maximum ${maxDepth}`);
  }
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
      return quote(value, path, asciiEscape);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v, i) => canon(v, `${path}[${i}]`, asciiEscape, depth + 1, maxDepth)).join(",") + "]";
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new CanonicalizationError(`${path}: not a plain JSON object`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort(compareCodePoints);
      return (
        "{" +
        keys
          .map((k) => quote(k, path, asciiEscape) + ":" + canon(obj[k], `${path}.${k}`, asciiEscape, depth + 1, maxDepth))
          .join(",") +
        "}"
      );
    }
    default:
      throw new CanonicalizationError(`${path}: ${typeof value} is not a JSON value`);
  }
}
