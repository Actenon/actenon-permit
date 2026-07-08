# Actenon-Permit Grant / Capability-Token Format (v0.1)

This document is the standalone specification of the **Grant** — the signed,
scoped, expiring, revocable capability token that an agent presents to
Actenon-Permit's Policy Decision Point (PDP) when it wants to act. It is
written so that an independent implementation in another language can
interoperate with the v0 Python reference. The format is intentionally small
and declarative; future versions may add fields, but the v0.1 field set will
remain a strict subset.

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
| `budget` | object | yes | `{currency: string, limit: float, remaining: float}`. `limit` is the original cap; `remaining` is mutable state. |
| `rate` | object | yes | `{max: int, per_seconds: int}`. `max=0` disables rate limiting. |
| `approval_rules` | array of string | yes (may be empty) | Rules that force REQUIRE_APPROVAL. |
| `status` | string | yes | One of `active`, `revoked`, `expired`, `exhausted`. |
| `signature` | string | yes | HMAC-SHA256 hex digest over canonical JSON of every other field. |

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
    message = canonical_json(grant_without_signature_field)
).hex()
```

Verification recomputes the HMAC and uses constant-time comparison
(`hmac.compare_digest`). A Grant with an empty or mismatched `signature` field
fails verification.

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

If any rule matches, the PDP returns `REQUIRE_APPROVAL` and blocks until the
control plane returns `approve` or `deny`. On approval, the PDP re-runs the
decision from step 1 (state and clock have moved).

## 6. Attenuation

A grant holder MAY derive a sub-grant for a sub-agent. The sub-grant MUST be
strictly weaker on every dimension:

| Dimension | Parent value | Allowed child value |
|-----------|--------------|---------------------|
| `expires_at` | T_parent | T_child <= T_parent |
| `scopes.allow` | A_parent | A_child ⊆ A_parent |
| `scopes.deny` | D_parent | D_child ⊇ D_parent (deny may only grow) |
| `budget.limit` | L_parent | L_child <= parent.remaining |
| `rate.max` | M_parent | M_child <= M_parent |
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
- Grants are bearer tokens. Anyone holding a grant id and the agent_id can
  present it. The v0 control plane is localhost-only; v1 must add transport
  authentication before grants traverse a network.
- The grant object travels in the agent's context, but the real credential
  never does. The broker is the only component that sees the secret, and only
  for the duration of a single guarded call.
- The ledger is append-only and hash-chained, but it is NOT a blockchain —
  there is no consensus. It is a tamper-evident local audit log. A
  sophisticated attacker with filesystem access can still forge a consistent
  history by rewriting the whole file. The defence against that is operational
  (append-only storage, log shipping), not cryptographic.
