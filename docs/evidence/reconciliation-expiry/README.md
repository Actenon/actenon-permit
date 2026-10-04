# Reconciliation expiry at settlement

Detached review may expire while waiting for another SQLite client to release
the write lock. The optional timezone-aware `review_expires_at` is checked after
BEGIN IMMEDIATE admits the settlement transaction, before ownership or budget
changes. Application signature checks alone cannot cover this wait.

The durable settlement time is returned, including the original time for an
identical terminal replay. Receipt verification can validate a historical
short-lived signature at that actual settlement time.

Before: the deadline/audit-time contract tests failed against merged main because
the deadline was unsupported. After: 648 Python tests passed, one documented
live-real-agent skip; no unexpected skips. A real independent SQLite client
holds the write lock through expiry; settlement then refuses, ambiguity and
budget remain held. Ruff passed.

Observer signature authentication remains the trusted caller’s responsibility.
No new package/tag/release is published.
