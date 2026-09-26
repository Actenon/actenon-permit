import { describe, expect, it } from "bun:test";
import { CanonicalizationError, canonicalizeJson } from "../src/index.ts";

// Expected strings are Python's json.dumps(obj, sort_keys=True,
// separators=(",", ":")), which the kernel's ResourceReceiptVerifier signs.
describe("canonicalizeJson parity with Python", () => {
  it("escapes non-ASCII and sorts keys by code point", () => {
    expect(
      canonicalizeJson({ b: 1, a: "café", "é": ["😀", -5, true, null], ctl: 'a\nb\u001f"' }),
    ).toBe('{"a":"caf\\u00e9","b":1,"ctl":"a\\nb\\u001f\\"","\\u00e9":["\\ud83d\\ude00",-5,true,null]}');
    expect(canonicalizeJson({ "￿": 1, "😀": 2 })).toBe('{"\\uffff":1,"\\ud83d\\ude00":2}');
  });

  const rejected: Array<[string, () => unknown]> = [
    ["lone high surrogate", () => "\uD800"],
    ["lone low surrogate", () => "x\uDC00y"],
    ["reversed surrogate pair", () => "\uDE00\uD83D"],
    ["lone surrogate key", () => ({ "\uD800": 1 })],
    ["float", () => ({ amount: 1.5 })],
    ["negative zero", () => -0],
    ["unsafe integer 2^53", () => 2 ** 53],
    ["unsafe number 1e21", () => ({ amount: 1e21 })],
    ["unsafe integer via JSON.parse", () => JSON.parse("123456789012345678901234567890")],
    ["NaN", () => NaN],
    ["Date", () => ({ when: new Date(0) })],
    ["Map", () => ({ m: new Map([["a", 1]]) })],
    ["Set", () => new Set([1])],
    ["undefined value", () => ({ a: undefined })],
    ["bigint", () => ({ a: 1n })],
  ];
  for (const [name, make] of rejected) {
    it(`rejects ${name}`, () => {
      expect(() => canonicalizeJson(make())).toThrow(CanonicalizationError);
    });
  }
});
