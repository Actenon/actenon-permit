import { describe, expect, it } from "bun:test";
import {
  ControlPlaneClient,
  GatewayClient,
  PermitDenied,
  decodeGrantToken,
  encodeGrantToken,
  verifyGrantToken,
} from "../src/index.ts";

const SIGNING_KEY = "test-signing-key-not-secret";
const BASE_URL = "http://127.0.0.1:7781";

const REFUND_POLICY = {
  agent: "ts-test-refund-bot",
  ttl: "1h",
  budget: { currency: "USD", limit: 50 },
  scopes: {
    allow: ["payment.refund", "email.send"],
    deny: ["payment.charge", "shell.*"],
  },
  rate: { max: 20, per: "1m" },
  approval: { require_human: ["email.send"] },
};

async function withServer<T>(fn: (port: number) => Promise<T>): Promise<T> {
  // Spawn the python gateway server on a free port, run the test, then kill.
  const proc = Bun.spawn({
    cmd: [
      "uv",
      "run",
      "python",
      "-c",
      `
import os, sys
os.environ["ACTENON_SIGNING_KEY"] = "${SIGNING_KEY}"
os.environ["ACTENON_DB_PATH"] = "/tmp/actenon-ts-test.db"
os.environ["MOCK_STRIPE_KEY"] = "sk_mock_123"
sys.path.insert(0, "src")
sys.path.insert(0, "examples")

# Wipe DB
for p in ["/tmp/actenon-ts-test.db", "/tmp/actenon-ts-test.db-wal", "/tmp/actenon-ts-test.db-shm"]:
    try: os.unlink(p)
    except: pass

import uvicorn
from actenon_permit import SQLiteStore, Ledger, PDP, Broker, Gateway, ToolRegistry, AutoApproveGate
from actenon_permit.control import create_app
from actenon_permit._mock_providers import mock_stripe_refund, mock_stripe_charge, mock_send_email

state = SQLiteStore("/tmp/actenon-ts-test.db")
ledger = Ledger(state)
pdp = PDP(state, ledger)
broker = Broker(pdp)
tools = ToolRegistry()
tools.register("refund", action_type="payment.refund", target="stripe",
               cost_from="amount", credential_name="MOCK_STRIPE_KEY",
               real_call=lambda secret, amount, reason="customer_request": mock_stripe_refund(secret, amount, reason))
tools.register("charge", action_type="payment.charge", target="stripe",
               cost_from="amount", credential_name="MOCK_STRIPE_KEY",
               real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description))
tools.register("send_email", action_type="email.send", target="smtp",
               credential_name="MOCK_STRIPE_KEY",
               real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body))
gw = Gateway(state=state, ledger=ledger, pdp=pdp, broker=broker, tools=tools, approval_gate=AutoApproveGate())
app = create_app(state=state, ledger=ledger, pdp=pdp, gateway=gw)
uvicorn.run(app, host="127.0.0.1", port=7781, log_level="warning")
`,
    ],
    stdout: "pipe",
    stderr: "pipe",
    cwd: "/home/z/my-project/Actenon-Permit",
    env: {
      ...process.env,
      UV_CACHE_DIR: "/home/z/.cache/uv",
      PATH: "/home/z/.local/bin:/usr/local/bin:/usr/bin:/bin",
    },
  });

  // Wait for server to be ready
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${BASE_URL}/health`);
      if (r.ok) {
        ready = true;
        break;
      }
    } catch {
      // not ready yet
    }
    await new Promise((res) => setTimeout(res, 100));
  }
  if (!ready) {
    const err = await new Response(proc.stderr).text();
    throw new Error(`server did not become ready: ${err.slice(0, 500)}`);
  }

  try {
    return await fn(7781);
  } finally {
    proc.kill();
    await proc.exited;
  }
}

describe("token encode/decode", () => {
  it("round-trips a grant through the wire format", async () => {
    const grant = {
      id: "grant_test123",
      agent_id: "ts-agent",
      issued_at: "2026-07-08T14:30:00+00:00",
      expires_at: "2026-07-08T15:30:00+00:00",
      scopes: { allow: ["payment.refund"], deny: ["shell.*"] },
      budget: { currency: "USD", limit: 50, remaining: 50 },
      rate: { max: 20, per_seconds: 60 },
      approval_rules: ["email.send"],
      status: "active" as const,
      signature: "deadbeef".repeat(16),
    };
    const token = encodeGrantToken(grant);
    expect(token.startsWith("v1.")).toBe(true);
    const decoded = decodeGrantToken(token, { verify: false });
    expect(decoded.id).toBe(grant.id);
    expect(decoded.agent_id).toBe(grant.agent_id);
  });

  it("cryptographic verification passes for a correctly-signed token", async () => {
    // Build a grant with a real signature
    const grantWithoutSig = {
      id: "grant_test456",
      agent_id: "ts-agent",
      issued_at: "2026-07-08T14:30:00+00:00",
      expires_at: "2026-07-08T15:30:00+00:00",
      scopes: { allow: ["payment.refund"], deny: [] },
      budget: { currency: "USD", limit: 50, remaining: 50 },
      rate: { max: 0, per_seconds: 60 },
      approval_rules: [],
      status: "active" as const,
    };
    // Compute HMAC-SHA256 hex over canonical JSON
    const cryptoObj = globalThis.crypto;
    const keyObj = await cryptoObj.subtle.importKey(
      "raw",
      new TextEncoder().encode(SIGNING_KEY),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const canonical = JSON.stringify(
      Object.keys(grantWithoutSig).sort().reduce(
        (acc, k) => ({ ...acc, [k]: (grantWithoutSig as Record<string, unknown>)[k] }),
        {},
      ),
    );
    const sig = await cryptoObj.subtle.sign("HMAC", keyObj, new TextEncoder().encode(canonical));
    const sigHex = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const grant = { ...grantWithoutSig, signature: sigHex };
    const token = encodeGrantToken(grant);
    const verified = await verifyGrantToken(token, SIGNING_KEY);
    expect(verified.id).toBe(grant.id);
  });

  it("rejects a token with the wrong signature", async () => {
    const grant = {
      id: "grant_test789",
      agent_id: "ts-agent",
      issued_at: "2026-07-08T14:30:00+00:00",
      expires_at: "2026-07-08T15:30:00+00:00",
      scopes: { allow: ["payment.refund"], deny: [] },
      budget: { currency: "USD", limit: 50, remaining: 50 },
      rate: { max: 0, per_seconds: 60 },
      approval_rules: [],
      status: "active" as const,
      signature: "00".repeat(64),
    };
    const token = encodeGrantToken(grant);
    await expect(verifyGrantToken(token, SIGNING_KEY)).rejects.toThrow(
      /signature verification failed/,
    );
  });
});

describe("control plane + gateway end-to-end", () => {
  it(
    "issues a grant, mints a token, calls refund (ALLOW), then over-budget (DENY)",
    async () => {
      await withServer(async () => {
        const cp = new ControlPlaneClient({ baseUrl: BASE_URL });
        const grant = await cp.issueGrant(REFUND_POLICY);
        expect(grant.status).toBe("active");
        expect(grant.budget.limit).toBe(50);

        const { token } = await cp.mintToken(grant.id);
        expect(token.startsWith("v1.")).toBe(true);

        const gw = new GatewayClient({ baseUrl: BASE_URL, grantToken: token });

        // step 1: refund $20 -> ALLOW
        const r1 = (await gw.callTool("refund", { amount: 20, reason: "customer" })) as {
          id: string;
          amount: number;
        };
        expect(r1.amount).toBe(20);

        // step 2: refund $25 -> ALLOW
        const r2 = (await gw.callTool("refund", { amount: 25, reason: "fraud" })) as {
          amount: number;
        };
        expect(r2.amount).toBe(25);

        // step 3: refund $20 -> DENY (only $5 left)
        await expect(gw.callTool("refund", { amount: 20 })).rejects.toBeInstanceOf(PermitDenied);

        // step 4: send_email -> REQUIRE_APPROVAL -> (auto-approve) -> ALLOW
        const r4 = (await gw.callTool("send_email", {
          to: "ops@example.com",
          subject: "refund",
          body: "hi",
        })) as { status: string };
        expect(r4.status).toBe("sent");

        // step 5: charge $100 -> DENY (scope)
        await expect(gw.callTool("charge", { amount: 100 })).rejects.toBeInstanceOf(PermitDenied);

        // step 6: revoke -> step 7: refund $1 -> DENY (revoked)
        await cp.revokeGrant(grant.id);
        await expect(gw.callTool("refund", { amount: 1 })).rejects.toBeInstanceOf(PermitDenied);
      });
    },
    { timeout: 30_000 },
  );

  it(
    "attenuates a parent grant to a weaker child",
    async () => {
      await withServer(async () => {
        const cp = new ControlPlaneClient({ baseUrl: BASE_URL });
        const parent = await cp.issueGrant(REFUND_POLICY);
        const child = await cp.attenuateGrant(parent.id, {
          budget_limit: 10,
          scopes_allow: ["payment.refund"],
        });
        expect(child.budget.limit).toBeLessThanOrEqual(10);
        expect(child.scopes.allow).toEqual(["payment.refund"]);

        // Attempting to widen must fail
        await expect(
          cp.attenuateGrant(parent.id, { budget_limit: 9999 }),
        ).rejects.toThrow();
      });
    },
    { timeout: 30_000 },
  );

  it(
    "ledger verifies as intact after a series of calls",
    async () => {
      await withServer(async () => {
        const cp = new ControlPlaneClient({ baseUrl: BASE_URL });
        const grant = await cp.issueGrant(REFUND_POLICY);
        const { token } = await cp.mintToken(grant.id);
        const gw = new GatewayClient({ baseUrl: BASE_URL, grantToken: token });
        await gw.callTool("refund", { amount: 10 });
        await gw.callTool("refund", { amount: 5 });
        const verify = await cp.verifyLedger();
        expect(verify.ok).toBe(true);
      });
    },
    { timeout: 30_000 },
  );
});
