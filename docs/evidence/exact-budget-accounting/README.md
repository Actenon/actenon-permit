# Exact budget accounting

Before: the five precision tests failed against merged Permit 3cb91d18.
Three one-unit charges left a 1e16 balance unchanged; the store allowed an
above-cap debit after rounding a cap upward; policy compilation rounded an
exact declared cap; altered Decimal context changed spending; sub-unit costs
were not refused. The second before log shows the real PDP refused a Decimal
cost after SQLite could not bind it in the audit ledger. The migration case in
that log already passes the later conservative migration and is not a before
attack. No successful remote/provider action is inferred from that refusal.

After: 678 tests passed, one documented live-agent skip, zero unexpected skips.
Ruff passed. The suite includes real PDP/audit and Broker settlement, large
balances across reopen, exact YAML/JSON/CLI/control parsing, approval threshold
precision, unsupported quantum/range refusal, cost tampering, unknown audit
version, mixed historical/null/v2 evidence, independent SQLite migration
clients, injected DDL rollback and twelve existing spawned cold-start owners.

Integer TEXT units (10^-9, magnitude below 10^39) authorize accounting. REAL
columns are compatibility mirrors. Responses retain numeric `remaining` and
add authoritative `remaining_exact`. New audit v3 stores exact cost text and
freezes the persisted view, with context-independent normalization. Historical
null/v2 verification remains; no Protocol action hash profile was invented.

Legacy migration narrows balances conservatively using float bounds and
retained charges against the cap. Lost evidence is not reconstructed. Small
uncertainty margins remain withheld; unsupported old data refuses construction
with rollback rather than guessing. It does not make old binaries safe to run
concurrently with new authority-store owners. Upgrade all trusted store clients.

The separate sibling overspend in existing-falsification.json is still OPEN.
Aggregate parent budgets, rolling windows, cross-host ownership, Airlock budget
configuration and public artifact validation are not claimed. No releases.
