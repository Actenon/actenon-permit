# Actenon-Permit Grant / Capability-Token Format (v1.0)

This document is the standalone specification of the **Grant** — the signed,
scoped, expiring, revocable capability token that an agent presents to
Actenon-Permit's Policy Decision Point (PDP) when it wants to act. It is
written so that an independent implementation in another language can
interoperate with the Python reference. The format is intentionally small
and declarative; future versions may add fields, but the v1.0 field set will
remain a strict subset.

**Changes in v1.0** (from v0.1):
- Added §11: Grant Bearer Token wire format (`v1.<base64url>`) for HTTP/MCP transport.
- Added §12: Out-of-process PEP gateway protocol (HTTP proxy + MCP stdio).
- Added §13: Attenuated multi-agent delegation wire endpoint.
- The Grant object format (§§2–10) is unchanged from v0.1.

## 1. Overview

A Grant is the digital analogue of a physical keycard with a budget and an
expiry. It is:

- **Signed** — HMAC-SHA256 over canonical JSON, so tampering is detectable.
- **Scoped** — explicit `allow[]` and `deny[]` action-type lists (glob match).
- **Bounded** — a currency, a hard spend cap, and a rate limit.
- **Expiring** — an absolute `expires_at` timestamp.
- **Revocable** — the issuer can flip `status` to `revoked` at any time; the
  next decision the agent makes is DENY.
- **Attenuable** — the holder can derive a strictly-weaker sub-grant (UCAN-style
  delegation). The sub-grant can never exceed the parent on any dimension.

The agent never holds the real credential. The Grant is the *capability*; the
real secret lives inside the broker and is only swapped in for a single call
after the PDP returns ALLOW.

## 2. Wire format

A Grant is a JSON object with the following fields. Field order is irrelevant
on the wire; for signing, fields MUST be serialized in canonical JSON (sorted
keys, no insignificant whitespace).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique grant identifier. Convention: `grant_<16 hex>`. |
| `agent_id` | string | yes | The principal this grant is issued to. |
| `issued_at` | ISO-8601 string (UTC) | yes | When the grant was created. |
| `expires_at` | ISO-8601 string (UTC) | yes | When the grant expires. The PDP transitions the grant to `expired` on first decision after this time. |
| `scopes` | object | yes | `{allow: [string], deny: [string]}`. Glob-style (`shell.*`). |
| `budget` | object | yes | `{currency: string, limit: decimal string, remaining: decimal string}`. `limit` is the signed cap; `remaining` is mutable exact state. See fixed-point accounting below. |
| `rate` | object | yes | `{max: int, per_seconds: int}`. `max=0` disables rate limiting. |
| `approval_rules` | array of string | yes (may be empty) | Rules that force REQUIRE_APPROVAL. |
| `status` | string | yes | One of `active`, `revoked`, `expired`, `exhausted`. |
| `signature` | string | yes | HMAC-SHA256 over immutable authority (excluding live status and remaining). |

### 2.1 Canonical JSON

For signing and for hash-chaining, JSON MUST be serialized as:

- Sorted object keys (lexicographic byte order).
- No insignificant whitespace (`separators=(",", ":")`).
- UTF-8 encoded.
- `null`, `true`, `false`, numbers, and strings per RFC 8259.
- Datetimes serialized as ISO-8601 strings with explicit `+00:00` offset.

### 2.2 Example Grant

```json
{
  "agent_id": "refund-bot",
  "approval_rules": ["email.send"],
  "budget": {"currency": "USD", "limit": 50.0, "remaining": 50.0},
  "expires_at": "2026-07-08T15:30:00+00:00",
  "id": "grant_a1b2c3d4e5f60718",
  "issued_at": "2026-07-08T14:30:00+00:00",
  "rate": {"max": 20, "per_seconds": 60},
  "scopes": {"allow": ["payment.refund", "email.send"], "deny": ["payment.charge", "shell.*"]},
  "status": "active",
  "signature": "9f3c1a...<64 hex chars>"
}
```

## 3. Signing

The signature is computed as:

```
signature = HMAC-SHA256(
    key = ACTENON_SIGNING_KEY (UTF-8 bytes),
    message = canonical_json(authority_payload)
).hex()
```

`authority_payload` is the grant object with these live/signature fields removed:

- `signature` (the field being computed)
- `status` (the store flips this on revoke, expiry, and exhaustion)
- `budget.remaining` (the store decrements this on every reservation)

An absent or null `approved_effect_ids` is omitted from the signing projection
to preserve existing scope-grant signatures. A finite list, including `[]`, is
retained. Removing or changing that list invalidates its signature.

`budget.limit`, `budget.currency`, scopes, expiry, rate, and identity stay
in the payload. Reservation and revocation therefore leave `verify()` true.
Widening the limit or the allow list leaves `verify()` false. A Grant with
an empty or mismatched `signature` field fails verification. The PDP denies
before it reserves when verification fails.

Verification recomputes the HMAC and uses constant-time comparison
(`hmac.compare_digest`). Live `status` and `budget.remaining` are enforced
by the state store, not by the HMAC. A bearer token's copy of those two
fields is not authoritative; the gateway reloads them from the store.

The signing key is read from the `ACTENON_SIGNING_KEY` environment variable.
If unset, the reference implementation generates an ephemeral dev key and
prints a warning. Grants signed with a dev key do not survive a process
restart. Production deployments MUST set `ACTENON_SIGNING_KEY` to a stable,
high-entropy value.

## 4. Scope matching

`scopes.allow` and `scopes.deny` are lists of glob patterns matched against
the action's `type` field (e.g. `"payment.refund"`, `"shell.exec"`).

- A pattern matches if it equals the type exactly, OR if `fnmatch(pattern, type)`
  succeeds. Example: `shell.*` matches `shell.exec`, `shell.rm`, etc.
- `deny` is checked BEFORE `allow`. A type in both lists is denied.
- If `allow` is non-empty, any type not matched by `allow` is DENY
  (default-deny). If `allow` is empty, the allow-list is permissive and only
  `deny` is enforced.

## 5. Approval rules

Each entry in `approval_rules` is a string in one of two forms:

- **Bare type** — `email.send`. Matches if `action.type == "email.send"`.
- **Type + threshold** — `payment.refund > 20`. Matches if
  `action.type == "payment.refund"` AND `float(action.params['amount'] or action.est_cost) > 20`.
  If that amount is not a finite number (a non-numeric string, NaN, a list),
  the rule matches: an amount that cannot be compared is not under the
  threshold.

If any rule matches, the PDP returns `REQUIRE_APPROVAL` and blocks until the
control plane returns `approve` or `deny`. On approval, the PDP re-runs the
decision from step 1 (state and clock have moved).

## 6. Attenuation

A grant holder MAY derive a sub-grant for a sub-agent. The sub-grant MUST be
strictly weaker on every dimension:

| Dimension | Parent value | Allowed child value |
|-----------|--------------|---------------------|
| `expires_at` | T_parent | T_child <= T_parent |
| `scopes.allow` | A_parent | A_child ⊆ A_parent, and A_child non-empty if A_parent is (an empty list permits every non-denied action, §4) |
| `scopes.deny` | D_parent | D_child ⊇ D_parent (deny may only grow) |
| `budget.limit` | L_parent | L_child <= parent.remaining |
| `rate.max` | M_parent | M_child <= M_parent, and M_child > 0 if M_parent > 0 (`max=0` disables rate limiting) |
| `rate.per_seconds` | P_parent | P_child >= P_parent |
| `approval_rules` | R_parent | R_child ⊇ R_parent (rules may only grow) |

Any attempt to widen MUST be rejected with a `ValueError` at the API layer.
The child grant is freshly signed (with the same signing key) and gets a new
`id` and `issued_at`. The parent grant is unaffected.

This is the UCAN-style capability-delegation invariant: a sub-agent can never
hold more power than its parent.

## 7. Status transitions

```
                  issue
                    │
                    ▼
                 ┌──────┐
       ┌─────────│active│─────────┐
       │         └──────┘         │
       │ revoke        now >      │ remaining hits 0
       │               expires_at │ after a reserve
       │                   │      │
       ▼                   ▼      ▼
   ┌────────┐         ┌────────┐ ┌──────────┐
   │revoked │         │expired │ │exhausted │
   └────────┘         └────────┘ └──────────┘
       │                   │      │
       └───────────────────┴──────┴── all three are terminal for v0
```

A `revoked` grant is the kill switch — every subsequent decision is DENY with
reason `"grant status is revoked"`. Revoke is idempotent.

## 8. Decision algorithm (reference)

```
decide(grant, action):
    try:
        if grant.status != active:           return DENY("grant status is <status>")
        if now > grant.expires_at:           set status=expired; return DENY("expired")
        if action.type matches scopes.deny:  return DENY("scope denied: <rule>")
        if scopes.allow and not match:       return DENY("out of scope")
        if rate.exceeded(grant.id):          return DENY("rate limit")
        if budget.remaining - est_cost < 0:  return DENY("would exceed <currency> <limit> budget")
        if any approval_rule matches:        return REQUIRE_APPROVAL(rule)
        # atomic reserve-then-record
        reserve(est_cost); record_rate_hit()
        return ALLOW
    except Exception:
        return DENY("engine error, failing closed")
```

The atomic reserve-then-record step is the part an amateur build gets wrong:
without it, two concurrent $30 charges against a $50 budget both pass. In the
reference implementation, reservation and rate-counter increment happen in a
single SQLite `BEGIN IMMEDIATE` transaction.

## 9. Versioning

This is **v0.1** of the format. Future versions:

- MAY add new fields. Implementations MUST ignore unknown fields when verifying
  (forward compatibility).
- MUST NOT change the meaning of existing fields.
- MUST NOT remove the `signature` field or change the canonical-JSON rule.

A future `version` field will be added when the format diverges
non-additively. Until then, v0.1 grants are self-describing by the absence of
a `version` field.

## 10. Security considerations

- The signing key is the root of trust. Compromise of `ACTENON_SIGNING_KEY`
  permits forging arbitrary grants. Protect it accordingly.
- Grants are bearer tokens: anyone holding one can present it at the
  gateway. The control plane (`/grants`, `/approvals`, `/ledger`: issuing,
  listing, revoking, attenuating, minting tokens, approving) requires
  `Authorization: Bearer <admin token>` (constant-time compare; 401 without
  it, 403 when wrong or when none is configured). `permit serve` takes the
  token from `--admin-token-file` / `ACTENON_ADMIN_TOKEN_FILE`, then
  `ACTENON_ADMIN_TOKEN`, else writes a fresh one to
  `~/.actenon-permit/admin-token` (0600) and prints only that path. Agents
  never hold it. The control plane still shares the gateway's port and
  binds 127.0.0.1 by default; serving it on a separate interface/port is a
  recommended hardening step not yet built in. Use TLS before any of it
  leaves the host.
- Revocation stops new decisions immediately, but cannot recall a PCCB
  already minted. PCCBs therefore live at most `PCCB_TTL_SECONDS` (120 s,
  `actenon_permit.kernel_bridge`) from the action's timestamp, bounded by
  the grant's expiry: that is the residual window in which a revoked
  grant's last proof can still verify at an edge that does not also check
  grant status.
- The grant object travels in the agent's context, but the real credential
  never does. The broker is the only component that sees the secret, and only
  for the duration of a single guarded call.
- The ledger is append-only and hash-chained, but it is NOT a blockchain —
  there is no consensus. It is a tamper-evident local audit log. A
  sophisticated attacker with filesystem access can still forge a consistent
  history by rewriting the whole file. The defence against that is operational
  (append-only storage, log shipping), not cryptographic.

---

## 11. Grant Bearer Token (v1.0)

For transport in HTTP headers (`X-Actenon-Grant`) and MCP `_meta` fields, a
Grant is encoded as a compact bearer token:

```
v1.<base64url(canonical_json(signed_grant_object))>
```

### 11.1 Encoding

1. Serialize the Grant object as canonical JSON (sorted keys, compact
   separators, UTF-8) — identical to the signing canonical form from §3.
2. Base64url-encode the bytes (no padding).
3. Prepend `v1.`.

The Grant MUST already be signed (the `signature` field MUST be present and
non-empty). Encoding an unsigned Grant raises `TokenError`.

### 11.2 Decoding & verification

```
grant = decode(token, verify=True)
```

1. Strip the `v1.` prefix. Reject if absent (`TokenError: unsupported token version`).
2. Base64url-decode the payload. Reject on invalid base64 (`TokenError: invalid base64 payload`).
3. Parse the payload as JSON. Reject on invalid JSON or non-object (`TokenError: invalid JSON payload` / `invalid grant payload`).
4. Validate the payload as a Grant (all required fields present and well-typed).
5. If `verify=True`: recompute the HMAC-SHA256 over `{every field except signature}` using the verifier's `ACTENON_SIGNING_KEY`, and constant-time-compare to the `signature` field. Reject on mismatch (`TokenError: signature verification failed`).

`verify=False` skips step 5 — use only for inspection tooling. Production
verifiers MUST verify.

### 11.3 Security notes

- Tokens are bearer tokens. Anyone holding one can present it to the gateway.
  Transport security (TLS, localhost-only, unix socket) is the deployment's
  responsibility. The v1 gateway binds to 127.0.0.1 by default.
- A token's signature proves the grant was issued by someone holding the
  signing key. It does NOT prove the grant is still active — the gateway
  loads live status from the state store on every call. A revoked grant's
  token is still decodable but the next decision is DENY.
- Tokens do not expire independently of their grant. When the grant expires,
  the next call is DENY regardless of the token's structural validity.

---

## 12. Out-of-process PEP gateway protocol (v1.0)

The v1 gateway runs in a separate process from the agent, holds the real
credentials, and enforces every decision server-side. Two transports are
supported.

### 12.1 HTTP proxy

| Method | Path | Headers | Body | Returns |
|--------|------|---------|------|---------|
| GET | `/proxy/tools` | (none) | — | `{"tools": ["refund", "charge", ...]}` |
| POST | `/proxy/{tool_name}` | `X-Actenon-Grant: <token>` (required), `Content-Type: application/json` | `{"arg": "value", ...}` | see below |

**Response body** (always JSON, status code reflects outcome):

```json
{
  "outcome": "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
  "reason": "string",
  "rule_matched": "string | null",
  "result": <any, only on ALLOW>,
  "action_id": "string | null",
  "grant_id": "string | null",
  "remaining_budget": "number | null"
}
```

| Outcome | HTTP status |
|---------|-------------|
| ALLOW | 200 |
| DENY | 403 |
| REQUIRE_APPROVAL | 202 (after auto-approve resolves to ALLOW or DENY, the final status is 200 or 403) |
| Missing `X-Actenon-Grant` header | 401 |
| Unknown tool | 403 (outcome=DENY, reason="unknown tool") |
| Invalid grant token | 403 (outcome=DENY, reason="invalid grant token: ...") |

### 12.2 MCP stdio (JSON-RPC 2.0 over stdin/stdout)

The gateway is also an MCP server. Messages are newline-delimited JSON-RPC 2.0.

**`initialize`** → returns server capabilities:
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
→ {"jsonrpc":"2.0","id":1,"result":{
    "protocolVersion":"2024-11-05",
    "capabilities":{"tools":{"listChanged":false}},
    "serverInfo":{"name":"actenon-permit-gateway","version":"1.0.0"}
}}
```

**`tools/list`** → returns registered tools as MCP tool specs:
```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
→ {"jsonrpc":"2.0","id":2,"result":{"tools":[
    {"name":"refund","description":"...","inputSchema":{...}},
    ...
]}}
```

**`tools/call`** → enforces decision and executes. The grant token MUST be
passed in `params._meta.actenon_grant`:
```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
    "name":"refund",
    "arguments":{"amount":20,"reason":"customer"},
    "_meta":{"actenon_grant":"v1.eyJ..."}
}}
```

The result is an MCP content block. On ALLOW:
```json
{"jsonrpc":"2.0","id":3,"result":{
    "content":[{"type":"text","text":"{\"id\":\"re_mock_...\",\"amount\":20,...}"}],
    "isError":false
}}
```

On DENY (or REQUIRE_APPROVAL that resolves to DENY):
```json
{"jsonrpc":"2.0","id":3,"result":{
    "content":[{"type":"text","text":"DENY: would exceed USD 50 budget"}],
    "isError":true
}}
```

The grant can instead be fixed at launch (`permit mcp-serve --grant-token`
or `ACTENON_GRANT_TOKEN`), so standard MCP clients need no `_meta`; a
per-call `_meta.actenon_grant` overrides it. Notifications (no `id`, e.g.
`notifications/initialized`) never receive a response.

With neither a launch grant nor `_meta.actenon_grant`, `tools/call` returns a JSON-RPC error:
```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"missing _meta.actenon_grant"}}
```

### 12.3 Enforcement path (both transports)

```
1. Decode + verify grant token  →  on failure: DENY("invalid grant token")
2. Load live grant from state    →  if missing: DENY("grant not found, treating as revoked")
3. Lookup tool in registry       →  if missing: DENY("unknown tool")
4. Build Action from args (cost_from rule for est_cost: the `cost_from` argument,
   else `amount`, else `cost`)  →  if that argument is not a finite number
   (e.g. the string "40"): DENY (`rule_matched: "cost:invalid"`)
5. PDP.decide(grant, action)
6. On DENY: return DENY
7. On REQUIRE_APPROVAL:
   a. ApprovalGate.request(grant, action, decision)  →  blocks
   b. If denied/timeout: return DENY("approval denied or timed out")
   c. If approved: re-run PDP.decide() with ctx={approved_action_id}
   d. If still not ALLOW: return DENY
8. On ALLOW: broker.execute(grant, action, decision, real_call, credential_name)
   → on CredentialMissing: release reservation, return DENY("credential missing")
   → on real_call exception: release reservation, return DENY("tool execution error")
   → on success: commit actual cost, return ALLOW with result + remaining_budget
```

---

## 13. Attenuated multi-agent delegation (v1.0)

A grant holder MAY derive a strictly-weaker sub-grant for a sub-agent. This
is the UCAN-style capability-delegation invariant: a sub-agent can never
hold more power than its parent.

### 13.1 Wire endpoint

```
POST /grants/{grant_id}/attenuate
Authorization: Bearer <admin token>
Content-Type: application/json

{
  "agent_id":             "child-agent",         // optional, new agent id
  "expires_at":           "2026-07-08T15:00Z",   // optional, must be <= parent
  "scopes_allow":         ["payment.refund"],    // optional, must be subset
  "scopes_deny":          ["shell.*"],           // optional, union with parent
  "budget_limit":         20,                    // optional, must be <= parent.remaining
  "rate_max":             10,                    // optional, must be <= parent
  "rate_per_seconds":     120,                   // optional, must be >= parent
  "extra_approval_rules": ["email.send"]         // optional, union with parent
}
```

The endpoint is operator-only (admin token). Holders delegate by asking the
operator; creating children does not grant control-plane authority. Child
spending shares the ancestors' live ceilings (§13.3).

Returns the freshly-signed child Grant (HTTP 200), or:
- 401 / 403 without a valid admin token
- 404 if the parent grant doesn't exist
- 409 if the parent grant is not active
- 400 if any attenuation rule is violated (e.g. widening budget)

### 13.2 Attenuation rules (enforced server-side)

| Dimension | Parent value | Allowed child value |
|-----------|--------------|---------------------|
| `expires_at` | T_parent | T_child <= T_parent |
| `scopes.allow` | A_parent | A_child ⊆ A_parent, and A_child non-empty if A_parent is (an empty list permits every non-denied action, §4) |
| `scopes.deny` | D_parent | D_child ⊇ D_parent (deny may only grow) |
| `budget.limit` | L_parent | L_child <= parent.remaining |
| `rate.max` | M_parent | M_child <= M_parent, and M_child > 0 if M_parent > 0 (`max=0` disables rate limiting) |
| `rate.per_seconds` | P_parent | P_child >= P_parent |
| `approval_rules` | R_parent | R_child ⊇ R_parent (rules may only grow) |

### 13.3 Budget semantics

**2.0 candidate contract change:** a child ceiling now shares the parent's
authority. Earlier versions created independent child budgets and required
operator orchestration to prevent aggregate amplification. That behavior is
preserved in historical evidence but is not the 2.0 spending contract.

Creating a child does not debit any balance. Every subsequent reservation
atomically debits the leaf and every authenticated ancestor in the same SQLite
write transaction, including their aggregate rate limits. Two children cannot
each spend 30 against a parent ceiling of 50. Missing, cyclic, invalid, expired,
revoked or widened lineage fails closed. The depth bound for store traversal is
64 grants; the PDP's configured delegation limit still applies independently.

The reservation freezes its charged owners. Actual-cost settlement and
NOT_EXECUTED refunds update those same owners atomically and at most once;
overruns create durable debt. AMBIGUOUS retains every hold. Refunding a revoked
owner does not revive its authority. Legacy reserve/commit/release and the
effect-aware path use the same accounting, rather than separate budget rules.

On migration, retained legacy held/committed costs are charged to ancestors once.
Historical parent debits cannot always be inferred; the migration deliberately
narrows authority and can overcount old manually allocated spending. It never
forgives retained cost or debt. Invalid/missing retained lineage refuses setup
for operator repair. Back up the store before migrating; review narrowed
balances. This is a SQLite shared-store guarantee, not a cross-host guarantee.

### 13.4 Wire format for handing the sub-grant to a child process

The child grant is returned as a full Grant JSON object. The child process
can:

1. Receive the Grant object (over stdout, a file, an env var, etc.)
2. Encode it as a bearer token: `v1.<base64url(canonical_json(grant))>`
3. Present the token to the gateway in the `X-Actenon-Grant` header

The gateway verifies the token's signature against the shared signing key
and loads live state. The child process never needs to call back to the
parent — the token is self-contained.

## Fixed-point budget accounting (2.0 candidate)

The store accounts in integer units of 10^-9 of the named currency/metric,
with a maximum absolute magnitude below 10^39. SQLite stores these units as
decimal integer TEXT, independently of SQLite REAL, 64-bit integer limits,
and Python Decimal context. Unrepresentable precision/range is refused,
never rounded. Grant fields serialize as decimal strings. YAML policy parsing
and the administrator attenuation CLI retain exact declared decimals; use
quoted decimal strings for JSON fractional budget values. Floats whose ULP
exceeds one budget unit are refused before authority construction or spending.

Reserve, settlement, overrun debt, effect ownership and refunds use exact
columns in the existing transactions. REAL columns and numeric `remaining`
responses are compatibility/display approximations; they never authorize
spending. `remaining_exact` is the exact decimal response. An ambiguous effect
continues to hold its reservation. New grant imports cannot reset live state.

Precision migration serializes inspection, ALTERs and backfill in one write
transaction. Legacy balances are conservatively narrowed by float uncertainty
and retained charge history against their signed cap. This cannot reconstruct
lost historical evidence; tiny uncertainty margins remain withheld after old
settlements. Unsupported precision, missing committed-cost evidence and failed
DDL refuse startup, roll back changes and close the failed connection.

New audit entries use `chain_version=3`, `entry_format=v3`, exact cost TEXT and
context-independent audit normalization. Their persisted view is frozen before
hashing. Null-version legacy and v2 candidate entries retain their own verifier;
unknown versions are refused. This is audit formatting, not a new action-hash
profile: execution proof hashing remains the Protocol implementation.

This section does not claim rolling monetary windows or cross-host budget
accounting. Aggregate ancestor consumption is defined in §13.3. Public registry
release and Airlock product budget configuration are still pending.


## Exact effect grants (2.0 candidate addition)

`approved_effect_ids` is an optional immutable finite list of Protocol effect
identifiers. Protocol `ACTENON-EFFECT-1` defines their descriptor hashing; Permit
does not invent a second effect identity or classify actions. A trusted resource
adapter derives the descriptor from the actual target and consequential bytes.
The issuer reviews that descriptor before signing its ID into the grant.

- Absent/null retains legacy scope authority. It does not mean exact-payload approval.
- `[]` approves no effects.
- A finite list approves only those exact effects, still subject to scope, expiry,
  live revocation, budget, ancestor constraints and atomic effect ownership.
- IDs must be unique lowercase `effect_` plus 64 hex digits; at most 256 per grant.
- Finite grants require the effect-aware decision/reservation path for **every**
  action. Plain decisions, legacy reservation, caller `approved_action_id`, or
  omitting the descriptor cannot bypass the restriction.

This is an explicit contract addition. New scope-only grants retain prior signing
bytes and omit the absent field in serialized form. Old grant signatures and
frozen token vectors remain valid. Older implementations that do not preserve a
finite field cannot authenticate its signature; they are not supported finite-grant
verifiers. Python and the TypeScript token verifier share new frozen vectors.

An explicit finite signed grant supplies the issuer's exact approval for matching
human-approval rules. A scope-only grant still returns REQUIRE_APPROVAL for those
rules on the protected effect path. The agent cannot turn a claimed action ID
into a finite approval. Operator issuance endpoints remain admin-authenticated.

Attenuation inherits the finite set by default. An unrestricted parent may issue
a finite child. A finite parent permits only a subset, including an empty subset;
no child can restore unrestricted authority. Store lineage validation also rejects
hand-constructed signed children that widen an ancestor.

The PDP computes the effect ID before reserving. The store validates it against
all authenticated charged ancestors in the same transaction as the reservation.
At the execution edge, Kernel independently derives the same descriptor and ID
from the exact request; the store then rechecks the live signed grant and ancestry
before its atomic dispatch claim. Merely trusting that the PDP returned ALLOW
is insufficient. A changed body, target, operation or owner namespace requires a
new approval. The existing effect ledger blocks duplicates across grants within
its resource-owner namespace; proof replay protection remains required as well.

Reconciliation does not broaden authority or approve a different effect. Unknown
outcomes retain ownership and budget. Confirmed non-execution may allow a fresh
attempt at the **same** approved effect; the old attempt/proof stays spent.
This does not claim unlimited multi-host or universal exactly-once execution.


## 16. Typed execution parameters (2.0 candidate correction, 2026-10-05)

A proof-bearing request MUST retain JSON value types from policy evaluation
through verification and dispatch. Accepted execution parameter values are
null, boolean, integer, Unicode string, JSON array and string-keyed object.
Nested values obey the same rule and Protocol's canonicalization limits.
Floats (including negative zero/NaN/infinity), tuples and custom Python value
classes MUST be rejected before the PDP reserves budget or ownership. No
float-to-string or tuple-to-list coercion is permitted. Applications needing
decimals must choose an explicit string or integer minor-unit representation
**before** review and policy evaluation; dispatch receives that same type.

This narrows the unreleased 2.0 candidate's prior convenience conversion.
The original legacy regression source and initial full-suite failures are
preserved in `docs/evidence/typed-request/legacy-contract-tests/`. The v1
remote seven-step authority/budget arc remains tested with integer request
values and gains a float-refusal/no-debit assertion. Plain `PDP.decide` budget
accounting retains Decimal precision tests; it is not an independently
verified protected executor. Historical released versions are not rewritten.

The gateway MUST snapshot all typed parameters, including nested arrays and
objects, before policy evaluation. The proof and real callback receive that
snapshot, not a scalar-only projection or subsequently changed caller map.
The GitHub adapter additionally validates its action schema, including optional
body/labels and integer issue numbers (boolean is not integer). Unsupported
fields are refused. Capture-only serializer tests prove request construction,
not a GitHub provider accepting the request or a live side effect.

The Boundary Kit compares mapped parameters by Protocol canonical bytes,
never Python structural equality (`true` and `1` differ). Proof/intent tokens
and nonempty JSON request bodies use Protocol's strict parser; duplicate
decoded members, malformed UTF-8, floats and oversized/deep JSON are refused.
Observe/warn mode remains observational for in-bounds requests. The 1 MiB
framing limit returns HTTP 413 in every mode; an oversized body is not fully
cached and a truncated body must never be forwarded to a handler. The ASGI
server remains responsible for allocation of individual received chunks.
Enforce mode requires the JSON body's keys to equal the complete set of body
fields declared by target/parameter mappings. Unknown and case-variant fields
are denied; a missing field cannot substitute for an explicitly signed null.
A mapped target must already be a nonempty string, never a coerced integer
or boolean. Whole mapped object/array values remain supported and are bound
recursively. This explicitly narrows the candidate's prior open-body behavior.
Header/query/path mappings remain the operator's responsibility and are not
a claim of complete handler-effect discovery.

Parameter mappings enforce exact declared types: `string`, `integer`,
`boolean`, `array`, `object` and `null`. Integer excludes boolean. Unsupported
mapping types (including `float` and `number`) are refused; generated manifests
for float-accepting handlers require an explicit application migration to
integer minor units or reviewed string values, not automatic coercion. The
mapping must match the handler's schema. Resource owners remain responsible
for transformations performed by application code, including nested schema
coercions; middleware does not attest arbitrary downstream handler behavior.
Target mapping `type` names the semantic resource kind, not a JSON value type.

HTTP proxy, intent creation/submission and MCP ingress require bounded strict
JSON objects before any gateway call. Malformed input never becomes `{}`.
Known transport wrapper fields reject unknown/case-variant names. An absent
intent-execute body or explicit `{}` is allowed; supplied overrides are not
implemented and are refused. Application member names remain case-sensitive.
Grant-token and control-plane wire parsing are separate compatibility surfaces
and are not covered by this ingress correction.
