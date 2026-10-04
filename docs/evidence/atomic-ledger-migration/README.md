# Atomic audit-ledger migration

Airlock’s unchanged two-process effect test failed on Linux Python 3.11:
Ledger inspected columns in autocommit mode while another client added the
same failure_code column. One owner crashed with duplicate-column error.
The CI log is preserved here; it is not treated as a flaky test to rerun.

BEGIN IMMEDIATE now covers table/index creation, column inspection and all
ALTER statements. Individual execute calls retain the transaction, avoiding
executescript’s implicit commit. A failed migration rolls back every added
column and closes the failed connection. New tables contain current columns;
legacy tables retain their rows and hash-version interpretation.

The existing bounded contention-only initialization retry is shared with
SQLiteStore, with busy timeout set before WAL setup. The audit connection
uses WAL/FULL rather than NORMAL. No exception is ignored to proceed without
a migrated durable ledger.

Before: four real independent clients inspecting a legacy table reproduced
the same duplicate-column error; injected second-ALTER failure left a partial
migration. After: complete suite 651 passed, one documented live-agent skip,
no unexpected skips; Ruff passed. Existing twelve spawned cold-start clients
now also initialize/verify the actual audit Ledger at FULL durability. The old
and new ledger hash-chain/tamper regression tests remain unchanged.

No PostgreSQL cross-host claim, package, tag or release is introduced. Airlock
will consume the immutable merged repair and rerun its existing concurrency
attack rather than serializing or weakening it.
