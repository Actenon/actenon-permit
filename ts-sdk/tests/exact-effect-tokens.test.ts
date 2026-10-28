import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { encodeGrantToken, verifyGrantToken } from "../src/token";

const vectors = JSON.parse(readFileSync(path.join(import.meta.dir, "vectors", "exact_effect_tokens.json"), "utf8"));
describe("signed exact effect authority interop", () => {
  for (const v of vectors.valid) {
    test(v.name, async () => {
      const grant = await verifyGrantToken(v.token, vectors.signing_key);
      expect(grant.approved_effect_ids ?? null).toEqual(v.approved_effect_ids);
      expect(encodeGrantToken(grant)).toBe(v.token);
    });
  }
  for (const v of vectors.invalid) {
    test(`refuses ${v.name}`, async () => {
      await expect(verifyGrantToken(v.token, vectors.signing_key)).rejects.toThrow();
    });
  }
});
