/**
 * Gateway client — talks to the v1 out-of-process PEP.
 *
 * Agents use this to call guarded tools. The grant token is presented in
 * the `X-Actenon-Grant` header. The gateway runs `decide()` server-side,
 * swaps the grant for the real credential, and executes the real call.
 * The agent only ever sees the tool signature and the outcome.
 */

import type { GatewayCallResult } from "./types.ts";
import { PermitDenied, PermitError } from "./types.ts";

export interface GatewayClientOptions {
  baseUrl: string; // e.g. "http://127.0.0.1:7780"
  grantToken: string; // bearer token issued by the control plane
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class GatewayClient {
  private baseUrl: string;
  private grantToken: string;
  private fetchFn: typeof fetch;
  private timeoutMs: number;

  constructor(opts: GatewayClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.grantToken = opts.grantToken;
    this.fetchFn = opts.fetch ?? globalThis.fetch;
    if (!this.fetchFn) {
      throw new PermitError("global fetch is not available; pass opts.fetch");
    }
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  /** Update the grant token (e.g. after attenuation or re-issuance). */
  setGrantToken(token: string): void {
    this.grantToken = token;
  }

  /** List the tool names the gateway exposes. */
  async listTools(): Promise<string[]> {
    const resp = await this.fetchFn(`${this.baseUrl}/proxy/tools`, {
      headers: { "X-Actenon-Grant": this.grantToken },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) {
      throw new PermitError(`list tools failed: ${resp.status} ${resp.statusText}`);
    }
    const payload = (await resp.json()) as { tools: string[] };
    return payload.tools;
  }

  /**
   * Call a guarded tool. Returns the tool's result on ALLOW, throws
   * `PermitDenied` on DENY, throws `PermitError` on transport errors.
   */
  async callTool(toolName: string, args: Record<string, unknown> = {}): Promise<unknown> {
    const url = `${this.baseUrl}/proxy/${encodeURIComponent(toolName)}`;
    let resp: Response;
    try {
      resp = await this.fetchFn(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Actenon-Grant": this.grantToken,
        },
        body: JSON.stringify(args),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new PermitError(`request to ${url} failed: ${(e as Error).message}`, e);
    }
    const text = await resp.text();
    let payload: GatewayCallResult | null;
    try {
      payload = text ? (JSON.parse(text) as GatewayCallResult) : null;
    } catch {
      throw new PermitError(`non-JSON response from ${url} (status ${resp.status}): ${text.slice(0, 200)}`);
    }
    if (!payload) {
      throw new PermitError(`empty response from ${url} (status ${resp.status})`);
    }
    if (payload.outcome === "ALLOW") {
      // Coerce remaining_budget from Decimal-string to number if needed.
      if (payload.remaining_budget != null && typeof payload.remaining_budget !== "number") {
        const n = Number(payload.remaining_budget);
        payload.remaining_budget = isNaN(n) ? null : n;
      }
      return payload.result;
    }
    throw new PermitDenied(payload.reason, {
      rule_matched: payload.rule_matched,
      action_id: payload.action_id,
      grant_id: payload.grant_id,
    });
  }
}
