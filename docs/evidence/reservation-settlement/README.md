# Reservation settlement regression

Before this change, a caller could settle a nonexistent action, claim a larger reserved amount, settle another grant's action, or repeat a settlement to inflate the available budget. Two independent SQLite processes committing the same $20 reservation at $10 each returned $90 and $100: the refund happened twice.

Settlement now reads the reservation in the same `BEGIN IMMEDIATE` transaction as the budget update. Its grant and stored amount must match. An identical committed-cost replay returns the current balance without another refund; a conflicting cost or release of a committed action is refused. Release deletes only the matching uncommitted reservation, preserving the existing approval-then-reserve-again path. Non-finite numbers and booleans are refused before mutation. SQLite uses `synchronous=FULL` so an acknowledged reservation is flushed before the caller can release a consequence.

The new attack suite produced **22 failures and one pass before the fix**, then **23 passes**. The full Python suite produced **598 passes and one documented external-CLI skip**, with zero unexpected skips. Ruff and the required-check manifest validation passed.

Reproduce from this repository:

```sh
uv sync --locked --extra dev
uv run pytest tests/test_reservation_settlement.py
uv run pytest -rs --junitxml=junit.xml
python scripts/assert_no_unexpected_skips.py junit.xml
uv run ruff check .
```

[Before-fix JUnit](before.xml) and [after-fix JUnit](after.xml) preserve the counterexamples, including two threads, two connections, two processes and reopening the database. Existing broker/intent tests now obtain the actual PDP decision and pass its reserved Action instead of constructing an ALLOW with no reservation. Their credential, idempotency, failure, lifecycle and mode assertions remain intact.

This change makes **budget settlement** atomic and repeat-safe. It does not establish logical-effect identity, execution ownership, PostgreSQL cross-host reservations, fixed-point monetary storage, aggregate delegated budgets or provider reconciliation. `rate_events.action_id` remains an action reservation, not a semantic effect identity. An uncertain dispatch must retain its reservation; the next execution-contract work must enforce that across all callers. SQLite REAL storage precision remains explicit.
