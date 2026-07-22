/**
 * Actenon TypeScript SDK — protocol types with Python parity.
 *
 * These types mirror the Python `actenon_protocol.execution_results` and
 * `actenon_permit.intent` modules. The Python and TypeScript SDKs MUST
 * agree on:
 *   - protocol fields
 *   - lifecycle states
 *   - execution modes
 *   - refusal codes
 *   - result meanings
 *   - receipt verification
 *   - canonicalisation
 *   - idempotency semantics
 *   - capability reporting
 */

// ---------------------------------------------------------------------------
// Execution modes (parity: actenon_protocol.execution_modes.ExecutionMode)
// ---------------------------------------------------------------------------

export type ExecutionMode = "brokered" | "resource_owned";

// ---------------------------------------------------------------------------
// Lifecycle states (parity: actenon_permit.intent.IntentLifecycle)
// ---------------------------------------------------------------------------

export type IntentLifecycle =
  | "created"
  | "evaluating"
  | "requires_approval"
  | "authorised"
  | "denied"
  | "proof_issued"
  | "executing"
  | "submitted"
  | "succeeded"
  | "failed"
  | "refused"
  | "outcome_unknown"
  | "cancelled"
  | "expired";

// ---------------------------------------------------------------------------
// Finality (parity: actenon_protocol.execution_results.FinalityStatus)
// ---------------------------------------------------------------------------

export type Finality = "final" | "non_final";

// ---------------------------------------------------------------------------
// Brokered execution states
// (parity: actenon_protocol.execution_results.BrokeredExecutionState)
// ---------------------------------------------------------------------------

export type BrokeredExecutionState =
  | "succeeded"
  | "failed"
  | "refused"
  | "outcome_unknown";

// ---------------------------------------------------------------------------
// Resource-owned execution states
// (parity: actenon_protocol.execution_results.ResourceOwnedExecutionState)
// ---------------------------------------------------------------------------

export type ResourceOwnedExecutionState =
  | "submitted"
  | "accepted"
  | "refused"
  | "succeeded"
  | "failed"
  | "outcome_unknown";

// ---------------------------------------------------------------------------
// Discriminated result models
// (parity: actenon_permit.sdk.models.BrokeredResult / ResourceOwnedResult)
//
// The two result types are NOT interchangeable. Callers MUST branch on
// the `mode` discriminant before reading mode-specific fields.
// ---------------------------------------------------------------------------

export interface BrokeredResult {
  readonly mode: "brokered";
  readonly intentId: string;
  readonly state: BrokeredExecutionState;
  readonly finality: Finality;
  readonly providerExecutionObserved: boolean;
  readonly receiptReceived: boolean;
  readonly receiptVerified: boolean;
  readonly evidence: Record<string, unknown>;
  readonly attemptId: string | null;
}

export interface ResourceOwnedResult {
  readonly mode: "resource_owned";
  readonly intentId: string;
  readonly state: ResourceOwnedExecutionState;
  readonly finality: Finality;
  readonly providerExecutionObserved: boolean;
  readonly resourceReceiptReceived: boolean;
  readonly resourceReceiptVerified: boolean;
  readonly submissionReference: string | null;
  readonly evidence: Record<string, unknown>;
  readonly attemptId: string | null;
}

/**
 * Discriminated union of brokered and resource-owned results.
 * Callers MUST narrow on `result.mode` before accessing mode-specific
 * fields.
 *
 * @example
 * ```ts
 * if (result.mode === "brokered") {
 *   // result.receiptVerified is accessible
 * } else {
 *   // result.resourceReceiptVerified is accessible
 * }
 * ```
 */
export type ExecutionResult = BrokeredResult | ResourceOwnedResult;

// ---------------------------------------------------------------------------
// Intent create request (parity: actenon_permit.sdk.models.IntentCreateRequest)
// ---------------------------------------------------------------------------

export interface IntentCreateRequest {
  action: string;
  target: string;
  parameters?: Record<string, unknown>;
  requestedExecutionMode?: ExecutionMode;
  idempotencyKey?: string;
  expirySeconds?: number;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Intent handle (the object returned by create())
// ---------------------------------------------------------------------------

export interface IntentHandle {
  readonly intentId: string;
  readonly lifecycleState: IntentLifecycle;
  execute(): Promise<ExecutionResult>;
  submitToResource(proof: Record<string, unknown>): Promise<ExecutionResult>;
}

// ---------------------------------------------------------------------------
// Capability info (parity: actenon_permit.sdk.config.CapabilityInfo)
// ---------------------------------------------------------------------------

export interface CapabilityInfo {
  transport: "local" | "cloud";
  supportsBrokered: boolean;
  supportsResourceOwned: boolean;
  supportsAsync: boolean;
  supportsPolling: boolean;
  durable: boolean;
  productionMode: boolean;
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

export interface LocalRuntimeConfig {
  agentId?: string;
  scopes?: string[];
  budgetLimit?: number;
  budgetCurrency?: string;
  signingKey?: string;
  intentStorePath?: string;
  productionMode?: boolean;
}

export interface CloudTransportConfig {
  baseUrl: string;
  grantToken?: string;
  timeoutSeconds?: number;
  verifyTls?: boolean;
  extraHeaders?: Record<string, string>;
}

export interface ResourceClientConfig {
  resourceId: string;
  endpointUrl: string;
  signingKeyId: string;
  signingKeySecret: Uint8Array;
  timeoutSeconds?: number;
}

// ---------------------------------------------------------------------------
// Structured exceptions (parity: actenon_permit.sdk.exceptions)
// ---------------------------------------------------------------------------

export class ActenonError extends Error {
  readonly rule: string | null;
  readonly retryable: boolean;

  constructor(message: string, opts: { rule?: string | null; retryable?: boolean } = {}) {
    super(message);
    this.name = "ActenonError";
    this.rule = opts.rule ?? null;
    this.retryable = opts.retryable ?? false;
  }
}

export class IntentNotFoundError extends ActenonError {
  constructor(message: string) {
    super(message);
    this.name = "IntentNotFoundError";
  }
}

export class ProofMissingError extends ActenonError {
  constructor(message: string) {
    super(message);
    this.name = "ProofMissingError";
  }
}

export class ExecutionRefusedError extends ActenonError {
  readonly reason: string;

  constructor(
    message: string,
    opts: { rule?: string | null; reason?: string } = {},
  ) {
    super(message, { rule: opts.rule });
    this.name = "ExecutionRefusedError";
    this.reason = opts.reason ?? "";
  }
}

export class ExecutionFailedError extends ActenonError {
  constructor(message: string, opts: { rule?: string | null } = {}) {
    super(message, { rule: opts.rule });
    this.name = "ExecutionFailedError";
  }
}

export class OutcomeUnknownError extends ActenonError {
  constructor(message: string, opts: { rule?: string | null } = {}) {
    super(message, { rule: opts.rule, retryable: true });
    this.name = "OutcomeUnknownError";
  }
}

export class ProviderError extends ActenonError {
  constructor(
    message: string,
    opts: { rule?: string | null; retryable?: boolean } = {},
  ) {
    super(message, { rule: opts.rule, retryable: opts.retryable });
    this.name = "ProviderError";
  }
}
