/**
 * TypeScript SDK tests (Prompt 12).
 *
 * Covers:
 *   - Protocol types: discriminated unions, lifecycle states, modes
 *   - Crypto: canonicalisation, receipt verification (valid + forged)
 *   - Client: Actenon.cloud capabilities, error mapping
 *   - Type safety: mode-aware result interpretation is enforced
 *   - Package smoke: all public exports are importable
 */

import { describe, expect, it } from "bun:test";
import {
  Actenon,
  ActenonError,
  BrokeredResult,
  type CapabilityInfo,
  CloudActenonClient,
  type ExecutionResult,
  ExecutionRefusedError,
  type IntentCreateRequest,
  type IntentHandle,
  type IntentLifecycle,
  LocalActenonClient,
  OutcomeUnknownError,
  ResourceOwnedResult,
  canonicalizeJson,
  computeReceiptSignature,
  verifyResourceReceipt,
} from "../src/index";

// ---------------------------------------------------------------------------
// 1. Protocol types
// ---------------------------------------------------------------------------

describe("protocol types", () => {
  it("BrokeredResult has mode='brokered'", () => {
    const result: BrokeredResult = {
      mode: "brokered",
      intentId: "intent_test",
      state: "succeeded",
      finality: "final",
      providerExecutionObserved: true,
      receiptReceived: true,
      receiptVerified: true,
      evidence: {},
      attemptId: "exec_1",
    };
    expect(result.mode).toBe("brokered");
    expect(result.state).toBe("succeeded");
  });

  it("ResourceOwnedResult has mode='resource_owned'", () => {
    const result: ResourceOwnedResult = {
      mode: "resource_owned",
      intentId: "intent_test",
      state: "submitted",
      finality: "non_final",
      providerExecutionObserved: false,
      resourceReceiptReceived: false,
      resourceReceiptVerified: false,
      submissionReference: "sub_1",
      evidence: {},
      attemptId: null,
    };
    expect(result.mode).toBe("resource_owned");
    expect(result.state).toBe("submitted");
  });

  it("ExecutionResult is a discriminated union", () => {
    const brokered: ExecutionResult = {
      mode: "brokered",
      intentId: "i",
      state: "succeeded",
      finality: "final",
      providerExecutionObserved: true,
      receiptReceived: true,
      receiptVerified: true,
      evidence: {},
      attemptId: null,
    };
    const resource: ExecutionResult = {
      mode: "resource_owned",
      intentId: "i",
      state: "submitted",
      finality: "non_final",
      providerExecutionObserved: false,
      resourceReceiptReceived: false,
      resourceReceiptVerified: false,
      submissionReference: null,
      evidence: {},
      attemptId: null,
    };
    expect(brokered.mode).not.toBe(resource.mode);
  });

  it("IntentLifecycle includes all 14 states", () => {
    const states: IntentLifecycle[] = [
      "created", "evaluating", "requires_approval", "authorised",
      "denied", "proof_issued", "executing", "submitted",
      "succeeded", "failed", "refused", "outcome_unknown",
      "cancelled", "expired",
    ];
    expect(states.length).toBe(14);
  });
});

// ---------------------------------------------------------------------------
// 2. Type safety — mode-aware interpretation is enforced
// ---------------------------------------------------------------------------

describe("type safety", () => {
  it("callers must narrow on mode before accessing mode-specific fields", () => {
    // This is a compile-time test. If the type system is correct,
    // accessing receiptVerified on a resource_owned result would be
    // a type error. We verify the narrowing works at runtime.
    function processResult(result: ExecutionResult): string {
      if (result.mode === "brokered") {
        // result.receiptVerified is accessible here
        return `brokered: ${result.receiptVerified}`;
      } else {
        // result.resourceReceiptVerified is accessible here
        return `resource_owned: ${result.resourceReceiptVerified}`;
      }
    }
    const brokered: ExecutionResult = {
      mode: "brokered", intentId: "i", state: "succeeded",
      finality: "final", providerExecutionObserved: true,
      receiptReceived: true, receiptVerified: true,
      evidence: {}, attemptId: null,
    };
    expect(processResult(brokered)).toBe("brokered: true");

    const resource: ExecutionResult = {
      mode: "resource_owned", intentId: "i", state: "submitted",
      finality: "non_final", providerExecutionObserved: false,
      resourceReceiptReceived: false, resourceReceiptVerified: false,
      submissionReference: null, evidence: {}, attemptId: null,
    };
    expect(processResult(resource)).toBe("resource_owned: false");
  });
});

// ---------------------------------------------------------------------------
// 3. Crypto: canonicalisation + receipt verification
// ---------------------------------------------------------------------------

describe("crypto", () => {
  it("canonicalizeJson sorts keys + removes whitespace", () => {
    const result = canonicalizeJson({ b: 2, a: 1, c: { z: 3, y: 2 } });
    expect(result).toBe('{"a":1,"b":2,"c":{"y":2,"z":3}}');
  });

  it("verifyResourceReceipt accepts a valid signature", () => {
    const secret = new TextEncoder().encode("test-secret");
    const body = { resource_id: "test", result: "ok", signing_key_id: "k1" };
    const signature = computeReceiptSignature(body, secret);
    const receipt = { ...body, signature };
    const keys = new Map([["k1", secret]]);
    expect(verifyResourceReceipt(receipt, keys)).toBe(true);
  });

  it("verifyResourceReceipt rejects a forged signature", () => {
    const realSecret = new TextEncoder().encode("real-secret");
    const wrongSecret = new TextEncoder().encode("wrong-secret");
    const body = { resource_id: "test", result: "ok", signing_key_id: "k1" };
    const signature = computeReceiptSignature(body, wrongSecret);
    const receipt = { ...body, signature };
    const keys = new Map([["k1", realSecret]]);
    expect(verifyResourceReceipt(receipt, keys)).toBe(false);
  });

  it("verifyResourceReceipt rejects unknown key id", () => {
    const body = { resource_id: "test", signing_key_id: "unknown" };
    const receipt = { ...body, signature: "deadbeef" };
    const keys = new Map([["k1", new TextEncoder().encode("secret")]]);
    expect(verifyResourceReceipt(receipt, keys)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 4. Client: capabilities + error mapping
// ---------------------------------------------------------------------------

describe("client", () => {
  it("Actenon.cloud() returns CloudActenonClient with correct capabilities", () => {
    const client = Actenon.cloud({
      baseUrl: "https://cloud.example.com",
      grantToken: "tok",
    });
    expect(client).toBeInstanceOf(CloudActenonClient);
    const caps = client.capabilities;
    expect(caps.transport).toBe("cloud");
    expect(caps.supportsBrokered).toBe(true);
    expect(caps.supportsResourceOwned).toBe(true);
    expect(caps.supportsAsync).toBe(true);
    expect(caps.durable).toBe(true);
  });

  it("Actenon.cloud() without grantToken reports supportsBrokered=false", () => {
    const client = Actenon.cloud({ baseUrl: "https://cloud.example.com" });
    expect(client.capabilities.supportsBrokered).toBe(false);
  });

  it("Actenon.local() returns LocalActenonClient", () => {
    const client = Actenon.local({ agentId: "test" });
    expect(client).toBeInstanceOf(LocalActenonClient);
    expect(client.capabilities.transport).toBe("local");
  });

  it("LocalActenonClient.registerCredential throws in browser env", async () => {
    const client = Actenon.local();
    // Simulate browser env
    const originalWindow = globalThis.window;
    (globalThis as Record<string, unknown>).window = {};
    try {
      await expect(client.registerCredential("TOKEN", "val")).rejects.toThrow(ActenonError);
    } finally {
      if (originalWindow === undefined) {
        delete (globalThis as Record<string, unknown>).window;
      } else {
        (globalThis as Record<string, unknown>).window = originalWindow;
      }
    }
  });

  it("mapResponseToResult raises ExecutionRefusedError on DENY without state", () => {
    const client = Actenon.cloud({ baseUrl: "https://example.com" });
    expect(() => {
      (client as CloudActenonClient as unknown as {
        mapResponseToResult: (id: string, resp: Record<string, unknown>) => ExecutionResult;
      }).mapResponseToResult("intent_1", {
        outcome: "DENY",
        reason: "out of scope",
        rule_matched: "allow:default-deny",
      });
    }).toThrow(ExecutionRefusedError);
  });

  it("mapResponseToResult raises OutcomeUnknownError", () => {
    const client = Actenon.cloud({ baseUrl: "https://example.com" });
    expect(() => {
      (client as CloudActenonClient as unknown as {
        mapResponseToResult: (id: string, resp: Record<string, unknown>) => ExecutionResult;
      }).mapResponseToResult("intent_1", {
        execution_mode: "brokered",
        execution_state: "outcome_unknown",
        finality: "non_final",
        provider_execution_observed: false,
        reason: "timeout",
      });
    }).toThrow(OutcomeUnknownError);
  });
});

// ---------------------------------------------------------------------------
// 5. Exception hierarchy
// ---------------------------------------------------------------------------

describe("exceptions", () => {
  it("OutcomeUnknownError is retryable", () => {
    const e = new OutcomeUnknownError("timeout");
    expect(e.retryable).toBe(true);
  });

  it("ExecutionRefusedError is not retryable", () => {
    const e = new ExecutionRefusedError("out of scope", { reason: "out of scope" });
    expect(e.retryable).toBe(false);
  });

  it("all exceptions inherit from ActenonError", () => {
    expect(new OutcomeUnknownError("x")).toBeInstanceOf(ActenonError);
    expect(new ExecutionRefusedError("x")).toBeInstanceOf(ActenonError);
  });
});

// ---------------------------------------------------------------------------
// 6. Package smoke — all exports importable
// ---------------------------------------------------------------------------

describe("package smoke", () => {
  it("all public names are exported", () => {
    expect(Actenon).toBeDefined();
    expect(CloudActenonClient).toBeDefined();
    expect(LocalActenonClient).toBeDefined();
    expect(canonicalizeJson).toBeDefined();
    expect(verifyResourceReceipt).toBeDefined();
    expect(computeReceiptSignature).toBeDefined();
    expect(ActenonError).toBeDefined();
    expect(ExecutionRefusedError).toBeDefined();
    expect(OutcomeUnknownError).toBeDefined();
  });
});
