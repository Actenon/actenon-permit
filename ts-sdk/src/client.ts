/**
 * Control plane client — talks to the Actenon-Permit FastAPI app
 * (POST /grants, GET /grants, POST /grants/:id/revoke, etc.).
 */

import type {
  AttenuateRequest,
  Grant,
  LedgerEntry,
  Policy,
} from "./types.ts";
import { PermitError } from "./types.ts";

export interface ControlPlaneClientOptions {
  baseUrl: string; // e.g. "http://127.0.0.1:7780"
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Coerce a value that may arrive as a Decimal-serialised string (e.g. "50.0")
 * into a number. The Python backend uses Decimal for exact monetary arithmetic
 * and serialises it as a JSON string; the TS SDK presents it as a number.
 */
function coerceNumber(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    const n = Number(v);
    if (!isNaN(n)) return n;
  }
  return 0;
}

/** Normalise a Grant's budget fields from wire format (strings) to numbers. */
function coerceGrant(g: Grant): Grant {
  if (g?.budget) {
    g.budget.limit = coerceNumber(g.budget.limit);
    g.budget.remaining = coerceNumber(g.budget.remaining);
  }
  if (g?.rate) {
    g.rate.max = coerceNumber(g.rate.max);
  }
  return g;
}

export class ControlPlaneClient {
  private baseUrl: string;
  private fetchFn: typeof fetch;
  private timeoutMs: number;

  constructor(opts: ControlPlaneClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.fetchFn = opts.fetch ?? globalThis.fetch;
    if (!this.fetchFn) {
      throw new PermitError("global fetch is not available; pass opts.fetch");
    }
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  async health(): Promise<{ status: string }> {
    return this.getJson("/health");
  }

  async issueGrant(policy: Policy): Promise<Grant> {
    return coerceGrant(await this.postJson<Grant>("/grants", { policy }));
  }

  async listGrants(agentId?: string): Promise<Grant[]> {
    const qs = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : "";
    const grants = await this.getJson<Grant[]>(`/grants${qs}`);
    return grants.map(coerceGrant);
  }

  async getGrant(grantId: string): Promise<Grant> {
    return coerceGrant(await this.getJson<Grant>(`/grants/${encodeURIComponent(grantId)}`));
  }

  async revokeGrant(grantId: string): Promise<{ grant_id: string; status: string }> {
    return this.postJson(`/grants/${encodeURIComponent(grantId)}/revoke`, {});
  }

  async attenuateGrant(grantId: string, req: AttenuateRequest): Promise<Grant> {
    return coerceGrant(await this.postJson<Grant>(`/grants/${encodeURIComponent(grantId)}/attenuate`, req));
  }

  async mintToken(grantId: string): Promise<{ grant_id: string; token: string }> {
    return this.postJson(`/grants/${encodeURIComponent(grantId)}/token`, {});
  }

  async listApprovals(): Promise<unknown[]> {
    return this.getJson("/approvals");
  }

  async approve(actionId: string): Promise<{ action_id: string; decision: string }> {
    return this.postJson(`/approvals/${encodeURIComponent(actionId)}/approve`, {});
  }

  async deny(actionId: string): Promise<{ action_id: string; decision: string }> {
    return this.postJson(`/approvals/${encodeURIComponent(actionId)}/deny`, {});
  }

  async listLedger(grantId?: string, limit = 1000): Promise<LedgerEntry[]> {
    const params = new URLSearchParams();
    if (grantId) params.set("grant_id", grantId);
    params.set("limit", String(limit));
    return this.getJson(`/ledger?${params.toString()}`);
  }

  async verifyLedger(): Promise<{ ok: boolean }> {
    return this.getJson("/ledger/verify");
  }

  // --- internals ---

  private async getJson<T>(path: string): Promise<T> {
    return this.request<T>("GET", path, undefined);
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private async request<T>(method: string, path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const init: RequestInit = {
      method,
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(this.timeoutMs),
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    let resp: Response;
    try {
      resp = await this.fetchFn(url, init);
    } catch (e) {
      throw new PermitError(`request to ${url} failed: ${(e as Error).message}`, e);
    }
    const text = await resp.text();
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      throw new PermitError(`non-JSON response from ${url} (status ${resp.status}): ${text.slice(0, 200)}`);
    }
    if (!resp.ok) {
      const detail = (payload as { detail?: string } | null)?.detail ?? resp.statusText;
      throw new PermitError(`${url} returned ${resp.status}: ${detail}`);
    }
    return payload as T;
  }
}
