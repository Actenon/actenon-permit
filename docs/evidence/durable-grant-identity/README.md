# Durable grant import identity

Before: twelve regression attacks failed against merged Permit 2074cde4.
Re-import restored spent funds, reactivated revoked/expired/exhausted grants,
let two importing SQLite clients each reserve 30 against one cap of 50,
replaced even resigned authority under the same identity, and admitted a
remaining balance above the signed cap. The before XML records actual balance
restoration and two successful reservations, not missing-interface failures.

After: 664 tests passed, one existing documented live-agent skip; no unexpected
skips. Ruff passed. Import snapshots are owned before use and BEGIN IMMEDIATE
serializes existence, authority comparison and insertion across clients.
Identical authority is a no-op retaining balance, status, timestamps and all
reservation/history. Changes to authority or an existing signature require a
new grant identity. Initial remaining cannot exceed the signed cap.

The existing administrator token command can attach a verified signature to
an unsigned legacy authority. It updates only the current body's signature;
its regression holds a reservation and revocation throughout and rejects a
forged signature. It cannot restore the bearer's stale mutable state.

Two existing fixtures now respect immutable grant identity: the scope attack
first asserts public import refusal, then retains direct storage-tamper/PDP
signature denial; an approval-rule fixture issues a new grant rather than
rewriting an existing policy. Original provider/effect/budget denial assertions
remain intact.

This closes import-state reset, not the complete budget acceptance gate.
Current SQLite REAL precision, aggregate parent budgets, rolling metric
windows, cross-host state and product budget configuration remain open.
New grant issuance is a trusted control action; agents must never have grant
signing credentials or a writable state database. No package/tag/release.
