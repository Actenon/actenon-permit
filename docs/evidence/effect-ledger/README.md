# Durable consequential effect ownership

The effect ledger is part of SQLiteStore, the existing authoritative grant
state. `reserve_effect` uses one BEGIN IMMEDIATE transaction to claim the
Protocol effect ID and debit the grant/rate reservation. Effect identity comes
from an owner-configured namespace and trusted exact/semantic descriptor;
proof/action nonces and a different grant cannot escape prior ownership.
A partial unique index prevents another owner for RESERVED, DISPATCHING,
COMMITTED or AMBIGUOUS. Confirmed NOT_EXECUTED retains history and permits a
fresh attempt, never reuse of the prior attempt ID.

`PDP.decide_and_mint_pccb(..., effect_namespace=...)` applies the existing
policy before atomic reservation and signs the portable reference into a real
Kernel proof. The independent Kernel EffectProtector recomputes the actual
effect and invokes `claim_effect_at_edge` before acquiring credentials. That
hook atomically checks authority/principal/attempt/action hash and moves
RESERVED to DISPATCHING once. Existing gateway verification refuses an
effect-bearing proof if ownership verification is not configured.

`settle_effect` is trusted boundary/operator API. It requires consistent
COMMITTED / NOT_EXECUTED / AMBIGUOUS evidence, observer and digest. A digest
alone is not authentication: callers must authenticate the observer, keep this
store out of agent control, and sign resulting receipts. Ambiguity holds the
entire budget. A transition out of AMBIGUOUS requires explicit reconciliation;
original ambiguity and reconciliation evidence remain in append-only events.
Identical final settlement is read-only; conflict is refused. Legacy budget
commit/release cannot bypass effect state. Actual-cost overruns are debited;
excess beyond remaining budget is durable debt, and refunds pay debt before
restoring authority. Only EXHAUSTED can reactivate after a real refund; revoked
or expired authority cannot. This retains existing SQLite REAL precision; it
does not claim fixed-point, rolling, parent/child aggregate-budget parity.

Validation: full suite 634 passed, one existing documented external-CLI skip,
zero unexpected skips. `ownership.xml` contains 36 focused attacks/integrations:
thread/client/process races, crash after reserve, rollback after a forced insert
failure, lost-response holds, owner/reference mutation, replayed settlement,
old API bypass attempts, overrun debt across reopen, explicit semantic keys,
and policy/approval refusal. Real integrated Permit proof -> verify-only
Ed25519 Kernel -> ledger -> provider tests include two spawned processes with
independent replay stores observing exactly one actual provider-file mutation.
The prior settlement regression suite remains intact and passes.

Not yet claimed: PostgreSQL multi-host effect ledger, single-use signed human
approval, an authenticated reconciliation service/CLI, Airlock adapter
integration, an OS containment boundary, or finished product acceptance.
Protected-effect policy rules remain REQUIRE_APPROVAL even if a caller passes
the legacy approved_action_id shortcut: a new exact approval contract is needed.
Protocol 1.6 and merged Kernel 5cbe8f5 are immutable source candidates. Existing
release guards still refuse registry publication with candidate overrides.
