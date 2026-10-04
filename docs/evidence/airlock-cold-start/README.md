# Real Airlock cold-start race

The first two-process Airlock HTTP effect test exposed an OperationalError:
database is locked while independent Permit stores enabled WAL mode. One
process dispatched; the other crashed before completing startup. The complete
failure is preserved in before-airlock.xml. Existing reservation-race tests
used initialized stores and therefore did not cover this path.

SQLite now establishes its busy timeout before schema/WAL work and retries
idempotent initialization only for SQLITE_BUSY/SQLITE_LOCKED, bounded to ten
seconds. Other errors remain fatal, timeout remains fatal, failed connections
close, WAL and FULL synchronous durability remain required. No process lock or
in-memory ownership fallback replaces the shared database.

Three fresh-database rounds start four spawned processes concurrently. All
twelve initialize one WAL effect schema. An unusable database path still
raises. The full Permit suite passes 638 tests with one existing documented
external-agent CLI skip and no unexpected skips. Airlock's actual HTTP race is
rerun against this merged pin in the Airlock product PR; this component evidence
alone does not assert that product test or any cross-host gate passed.

Permit consumes merged Kernel #47 at 9dd6af8 and preserves Protocol 3442bf3.
This is the single canonical source stack; no packages or tags are published.
