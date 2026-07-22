/**
 * Actenon TypeScript SDK — the main client.
 *
 * Provides `Actenon.local()` for in-process execution (via HTTP to a
 * local gateway) and `Actenon.cloud()` for Cloud-managed deployments.
 *
 * The TS SDK is async-only (unlike Python which has both sync + async).
 * All methods return Promises.
 *
 * @example
 * ```ts
 * import { Actenon } from "@actenon/sdk";
 *
 * const client = Actenon.cloud({
 *   baseUrl: "http://localhost:7780",
 *   grantToken: "v1.YOUR_GRANT_TOKEN",
 * });
 *
 * const intent = await client.authorisedExecutionIntents.create({
 *   action: "github.issue.create",
 *   target: "github",
 *   parameters: { title: "Hello from TS SDK" },
 * });
 *
 * const result = await intent.execute();
 * if (result.mode === "brokered" && result.state === "succeeded") {
 *   console.log("Issue created:", result.evidence);
 * }
 * ```
 */

import type {
  CapabilityInfo,
  CloudTransportConfig,
  ExecutionResult,
  IntentCreateRequest,
  IntentHandle,
  IntentLifecycle,
  LocalRuntimeConfig,
  ResourceClientConfig,
} from "./protocol";
import {
  ActenonError,
  ExecutionFailedError,
  ExecutionRefusedError,
  OutcomeUnknownError,
} from "./protocol";

// ---------------------------------------------------------------------------
// AuthorisedExecutionIntents API
// ---------------------------------------------------------------------------

class AuthorisedExecutionIntentsAPI {
  constructor(private client: ActenonClient) {}

  async create(req: IntentCreateRequest): Promise<IntentHandle> {
    return this.client.createIntent(req);
  }
}

// ---------------------------------------------------------------------------
// Abstract client
// ---------------------------------------------------------------------------

export abstract class ActenonClient {
  readonly authorisedExecutionIntents: AuthorisedExecutionIntentsAPI;

  constructor() {
    this.authorisedExecutionIntents = new AuthorisedExecutionIntentsAPI(this);
  }

  abstract createIntent(req: IntentCreateRequest): Promise<IntentHandle>;
  abstract readonly capabilities: CapabilityInfo;

  protected mapResponseToResult(
    intentId: string,
    response: Record<string, unknown>,
  ): ExecutionResult {
    const state = response["execution_state"] as string | undefined;

    // If the gateway returned a plain DENY without execution_state
    // (e.g. PDP denial, unknown intent, token error), raise.
    if (!state) {
      throw new ExecutionRefusedError(
        (response["reason"] as string) ?? "execution refused",
        {
          rule: (response["rule_matched"] as string) ?? null,
          reason: (response["reason"] as string) ?? "",
        },
      );
    }

    const mode = (response["execution_mode"] as string) ?? "brokered";
    const finality = (response["finality"] as string) ?? "non_final";
    const evidence = (response["result"] as Record<string, unknown>) ?? {};
    const intent = response["intent"] as Record<string, unknown> | undefined;
    const attemptIds = (intent?.["linked_attempt_ids"] as string[]) ?? [];
    const attemptId = attemptIds[0] ?? null;

    let result: ExecutionResult;
    if (mode === "brokered") {
      result = {
        mode: "brokered",
        intentId,
        state: state as ExecutionResult extends { mode: "brokered" }
          ? ExecutionResult["state"]
          : never,
        finality: finality as "final" | "non_final",
        providerExecutionObserved:
          (response["provider_execution_observed"] as boolean) ?? false,
        receiptReceived: (response["receipt_received"] as boolean) ?? false,
        receiptVerified: (response["receipt_verified"] as boolean) ?? false,
        evidence,
        attemptId,
      };
    } else {
      result = {
        mode: "resource_owned",
        intentId,
        state: state as never,
        finality: finality as "final" | "non_final",
        providerExecutionObserved:
          (response["provider_execution_observed"] as boolean) ?? false,
        resourceReceiptReceived:
          (response["resource_receipt_received"] as boolean) ?? false,
        resourceReceiptVerified:
          (response["resource_receipt_verified"] as boolean) ?? false,
        submissionReference:
          (response["submission_reference"] as string | null) ?? null,
        evidence,
        attemptId,
      };
    }

    // Raise structured exceptions for non-succeeded terminal states.
    if (state === "succeeded") return result;
    if (state === "refused") {
      throw new ExecutionRefusedError(
        (response["reason"] as string) ?? "execution refused",
        {
          rule: (response["rule_matched"] as string) ?? null,
          reason: (response["reason"] as string) ?? "",
        },
      );
    }
    if (state === "failed") {
      throw new ExecutionFailedError(
        (response["reason"] as string) ?? "execution failed",
        { rule: (response["rule_matched"] as string) ?? null },
      );
    }
    if (state === "outcome_unknown") {
      throw new OutcomeUnknownError(
        (response["reason"] as string) ?? "outcome unknown",
        { rule: (response["rule_matched"] as string) ?? null },
      );
    }
    // submitted / accepted — non-final, return the result.
    return result;
  }
}

// ---------------------------------------------------------------------------
// Cloud client (HTTP transport)
// ---------------------------------------------------------------------------

export class CloudActenonClient extends ActenonClient {
  private config: CloudTransportConfig;

  constructor(config: CloudTransportConfig) {
    super();
    this.config = config;
  }

  get capabilities(): CapabilityInfo {
    return {
      transport: "cloud",
      supportsBrokered: this.config.grantToken != null,
      supportsResourceOwned: true,
      supportsAsync: true,
      supportsPolling: true,
      durable: true,
      productionMode: true,
    };
  }

  async createIntent(req: IntentCreateRequest): Promise<IntentHandle> {
    const body = {
      action_type: req.action,
      action_params: req.parameters ?? {},
      target_type: "unknown",
      target_id: req.target,
      requested_execution_mode: req.requestedExecutionMode ?? "brokered",
      requester_subject: this.config.grantToken ? "sdk-cloud" : "sdk-anon",
      requester_agent_id: "sdk-cloud",
      idempotency_key: req.idempotencyKey,
      expiry_seconds: req.expirySeconds ?? 3600,
      metadata: req.metadata ?? {},
    };
    const resp = await this.httpPost("/intents", body);
    const intentId = resp["intent_id"] as string;
    const lifecycleState = resp["lifecycle_state"] as IntentLifecycle;
    return new IntentHandleImpl(this, intentId, lifecycleState);
  }

  async executeIntent(intentId: string): Promise<ExecutionResult> {
    if (!this.config.grantToken) {
      throw new ActenonError("CloudActenonClient.execute() requires a grantToken");
    }
    const resp = await this.httpPost(
      `/intents/${intentId}/execute`,
      {},
      { "X-Actenon-Grant": this.config.grantToken },
    );
    return this.mapResponseToResult(intentId, resp);
  }

  async submitIntent(
    intentId: string,
    proof: Record<string, unknown>,
  ): Promise<ExecutionResult> {
    const resp = await this.httpPost(`/intents/${intentId}/submit`, { proof });
    return this.mapResponseToResult(intentId, resp);
  }

  private async httpPost(
    path: string,
    body: Record<string, unknown>,
    extraHeaders?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const url = this.config.baseUrl.replace(/\/+$/, "") + path;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "@actenon/sdk-ts/1.4.0",
      ...(extraHeaders ?? {}),
    };
    if (this.config.grantToken && !headers["X-Actenon-Grant"]) {
      headers["X-Actenon-Grant"] = this.config.grantToken;
    }

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      (this.config.timeoutSeconds ?? 30) * 1000,
    );
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await resp.text();
      try {
        return JSON.parse(text) as Record<string, unknown>;
      } catch {
        throw new ActenonError(`HTTP ${resp.status}: ${text.slice(0, 200)}`);
      }
    } catch (e) {
      if (e instanceof ActenonError) throw e;
      throw new ActenonError(`HTTP request failed: ${(e as Error).message}`);
    } finally {
      clearTimeout(timeout);
    }
  }
}

// ---------------------------------------------------------------------------
// Local client (HTTP to a local gateway, same as cloud but with dev defaults)
// ---------------------------------------------------------------------------

export class LocalActenonClient extends CloudActenonClient {
  constructor(config: LocalRuntimeConfig) {
    // The local client is an HTTP client to a local gateway.
    // The grant token is obtained from the local gateway's control plane.
    // For now, we use the same HTTP transport as cloud; the difference is
    // in the config defaults and capability reporting.
    super({
      baseUrl: "http://127.0.0.1:7780",
      grantToken: undefined, // Set by the caller via registerCredential
      timeoutSeconds: 30,
    });
    this.localConfig = config;
  }

  private localConfig: LocalRuntimeConfig;

  get capabilities(): CapabilityInfo {
    return {
      transport: "local",
      supportsBrokered: true,
      supportsResourceOwned: false,
      supportsAsync: true,
      supportsPolling: false,
      durable: this.localConfig.intentStorePath != null,
      productionMode: this.localConfig.productionMode ?? false,
    };
  }

  /**
   * Register a credential for brokered execution.
   * In the TS SDK, this sends the credential to the local gateway's
   * control plane (NOT stored in the browser/client).
   */
  async registerCredential(ref: string, _value: string): Promise<void> {
    // The TS SDK does NOT store credentials client-side. It sends a
    // registration request to the local gateway, which stores the
    // credential in its CredentialProviderRegistry.
    //
    // For security: this method is a no-op in browser environments.
    // In Node.js, it makes an HTTP call to the local gateway.
    if (typeof window !== "undefined") {
      throw new ActenonError(
        "registerCredential() must not be called from a browser environment. " +
          "Credentials must be registered server-side.",
      );
    }
    // In a real implementation, this would POST to /credentials on the
    // local gateway. For now, we log a warning.
    console.warn(
      `[actenon] registerCredential('${ref}') called. ` +
        "In production, register credentials server-side via the gateway's " +
        "control plane, not from the SDK client.",
    );
  }

  /**
   * Register a resource client from config.
   * In the TS SDK, this is a server-side operation.
   */
  async registerResourceFromConfig(_config: ResourceClientConfig): Promise<void> {
    if (typeof window !== "undefined") {
      throw new ActenonError(
        "registerResourceFromConfig() must not be called from a browser environment.",
      );
    }
    console.warn(
      "[actenon] registerResourceFromConfig() called. " +
        "In production, register resource clients server-side.",
    );
  }
}

// ---------------------------------------------------------------------------
// IntentHandle implementation
// ---------------------------------------------------------------------------

class IntentHandleImpl implements IntentHandle {
  constructor(
    private client: ActenonClient,
    public readonly intentId: string,
    public readonly lifecycleState: IntentLifecycle,
  ) {}

  async execute(): Promise<ExecutionResult> {
    if (this.client instanceof CloudActenonClient) {
      return this.client.executeIntent(this.intentId);
    }
    throw new ActenonError("IntentHandle.execute() requires a CloudActenonClient");
  }

  async submitToResource(proof: Record<string, unknown>): Promise<ExecutionResult> {
    if (this.client instanceof CloudActenonClient) {
      return this.client.submitIntent(this.intentId, proof);
    }
    throw new ActenonError(
      "IntentHandle.submitToResource() requires a CloudActenonClient",
    );
  }
}

// ---------------------------------------------------------------------------
// Public constructor class
// ---------------------------------------------------------------------------

export class Actenon {
  /**
   * Create a local client (HTTP to a local gateway).
   *
   * The TS SDK does NOT run the broker in-process (unlike Python).
   * The local client talks to a local Actenon-Permit gateway over HTTP.
   * This keeps secret-bearing code server-side.
   */
  static local(config?: LocalRuntimeConfig): LocalActenonClient {
    return new LocalActenonClient(config ?? {});
  }

  /**
   * Create a Cloud client (HTTP to a Cloud-managed gateway).
   */
  static cloud(config: CloudTransportConfig): CloudActenonClient {
    return new CloudActenonClient(config);
  }
}
