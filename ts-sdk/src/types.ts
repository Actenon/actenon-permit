/**
 * Actenon-Permit TypeScript SDK — shared types.
 *
 * Mirrors the Python `actenon_permit.model` module. These types are the
 * wire contract between the TS SDK and the Actenon-Permit control plane /
 * gateway.
 */

export type GrantStatus = "active" | "revoked" | "expired" | "exhausted";

export type DecisionOutcome = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

export interface Scopes {
  allow: string[];
  deny: string[];
}

export interface Budget {
  currency: string;
  limit: number;
  remaining: number;
}

export interface Rate {
  max: number;
  per_seconds: number;
}

export interface Grant {
  id: string;
  agent_id: string;
  issued_at: string; // ISO-8601
  expires_at: string; // ISO-8601
  scopes: Scopes;
  budget: Budget;
  rate: Rate;
  approval_rules: string[];
  status: GrantStatus;
  signature: string;
}

export interface Action {
  action_id: string;
  grant_id: string;
  ts: string;
  type: string;
  target: string;
  params: Record<string, unknown>;
  est_cost: number | null;
}

export interface Decision {
  outcome: DecisionOutcome;
  reason: string;
  rule_matched: string | null;
  state_delta: Record<string, unknown>;
}

export interface LedgerEntry {
  seq: number;
  action_id: string;
  grant_id: string;
  ts: string;
  action_type: string;
  target: string;
  params: Record<string, unknown>;
  est_cost: number | null;
  outcome: DecisionOutcome;
  reason: string;
  rule_matched: string | null;
  state_delta: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

// ---------------------------------------------------------------------------
// Policy (request body for POST /grants)
// ---------------------------------------------------------------------------

export interface Policy {
  agent?: string;
  agent_id?: string;
  ttl?: string | number;
  expires_at?: string;
  budget?: { currency?: string; limit: number; remaining?: number };
  scopes?: { allow?: string[]; deny?: string[] };
  rate?: { max?: number; per?: string | number };
  approval?: { require_human?: string[] };
}

// ---------------------------------------------------------------------------
// Attenuation request (POST /grants/:id/attenuate)
// ---------------------------------------------------------------------------

export interface AttenuateRequest {
  agent_id?: string;
  expires_at?: string;
  scopes_allow?: string[];
  scopes_deny?: string[];
  budget_limit?: number;
  rate_max?: number;
  rate_per_seconds?: number;
  extra_approval_rules?: string[];
}

// ---------------------------------------------------------------------------
// Gateway tool-call result
// ---------------------------------------------------------------------------

export interface GatewayCallResult {
  outcome: DecisionOutcome;
  reason: string;
  rule_matched: string | null;
  result?: unknown;
  action_id: string | null;
  grant_id: string | null;
  remaining_budget: number | null;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class PermitError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message);
    this.name = "PermitError";
  }
}

export class PermitDenied extends PermitError {
  public rule_matched: string | null;
  public action_id: string | null;
  public grant_id: string | null;

  constructor(
    message: string,
    opts: { rule_matched?: string | null; action_id?: string | null; grant_id?: string | null } = {},
  ) {
    super(message);
    this.name = "PermitDenied";
    this.rule_matched = opts.rule_matched ?? null;
    this.action_id = opts.action_id ?? null;
    this.grant_id = opts.grant_id ?? null;
  }
}

export class TokenError extends PermitError {
  constructor(message: string) {
    super(message);
    this.name = "TokenError";
  }
}
