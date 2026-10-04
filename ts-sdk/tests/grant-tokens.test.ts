import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import path from "node:path";

import { encodeGrantToken, verifyGrantToken } from "../src/token";

// Same vectors the Python tests verify: v1 from released actenon-permit
// 1.4.0, v2 from the 2.0.0 candidate (ACTENON-JCS-STRICT-1).
const vectors = JSON.parse(readFileSync(path.join(import.meta.dir, "vectors", "grant_tokens.json"), "utf8"));

describe("grant token interop vectors", () => {
  for (const v of vectors.valid) {
    test(`verifies ${v.name}`, async () => {
      const grant = await verifyGrantToken(v.token, vectors.signing_key);
      expect(grant.id).toBe(v.grant_id);
      expect(grant.agent_id).toBe(v.agent_id);
    });
  }
  for (const v of vectors.tampered) {
    test(`refuses ${v.name}`, async () => {
      await expect(verifyGrantToken(v.token, vectors.signing_key)).rejects.toThrow();
    });
  }
  test("re-encoding a verified v2 grant yields the same v2 token", async () => {
    for (const v of vectors.valid.filter((x: { version: string }) => x.version === "v2")) {
      const grant = await verifyGrantToken(v.token, vectors.signing_key);
      expect(encodeGrantToken(grant)).toBe(v.token);
    }
  });
});
