# Reconciliation state binding

An operator observation prepared before dispatch must not subsequently release
an in-flight effect. `expected_event_sequence` is validated and compared to the
reservation’s latest event inside the same BEGIN IMMEDIATE transaction as
settlement and budget refund. The application authenticates its observer;
this trusted store API does not authenticate signatures itself.

`get_effect` exposes the frozen descriptor and the latest event sequence in
one SQLite query, so clients can sign the exact review snapshot. A stale
review is refused before mutation. Identical already-terminal evidence remains
read-only/idempotent and cannot refund twice. Conflicting evidence is refused.

Before: the new contract tests failed because the sequence precondition and
descriptor snapshot were unavailable. After: full suite 646 passed, one
previously documented live-real-agent skip; no unexpected skips. Tests also
refuse boolean, string, float, zero and negative review sequences.

Existing trusted synchronous callers remain compatible without the optional
precondition. Detached/signed operator integrations must supply it. No
PostgreSQL cross-host reconciliation or authenticated product route is claimed
by this engine change.
