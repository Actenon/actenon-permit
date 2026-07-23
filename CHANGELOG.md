# Changelog

All notable changes to actenon-permit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-07-24

### BREAKING CHANGES

- **Canonicalisation now delegates to ACTENON-JCS-STRICT-1.** `canonical_json`
  (in `actenon_permit/model.py`, exported via `actenon_permit.canonical_json`)
  now delegates to `actenon_protocol.canonicalize_json` instead of Permit's
  home-grown `json.dumps(sort_keys=True, default=str)`. This fixes three
  defects:

  - **(a) Cross-language byte parity.** Python was escaping non-ASCII to
    `\uXXXX`; the TypeScript SDK's `JSON.stringify` emits raw UTF-8. Same
    grant, different bytes, different HMAC. Any grant with a non-ASCII
    agent name, reason, or target failed cross-language verification. Now
    both emit raw UTF-8.

  - **(b) Decimal type confusion.** The previous `_json_default` coerced
    unknown types via `str()`, so `Decimal("50.0")` and the string `"50.0"`
    produced identical signing bytes. `Decimal("50.0")` and
    `Decimal("50.00")` produced different bytes despite being numerically
    equal. The new `_coerce_decimals` helper normalises `Decimal` via
    `Decimal.normalize()` so numerically equal Decimals canonicalise
    identically.

  - **(c) Float rejection.** The protocol canonicaliser rejects floats
    outright (with a message naming ACTENON-JCS-STRICT-1). The previous
    `canonical_json` silently accepted floats via `default=str`. Floats in
    signing payloads are a defect — they're non-deterministic across
    language runtimes. The public `canonical_json` now lets floats raise.

- **Ledger chain version bump.** Every ledger entry hash changes because
  the canonicaliser changed. Existing ledgers would fail their integrity
  check under the new canonicaliser alone. Each entry now carries a
  `chain_version` field:

  - `chain_version` absent (NULL) — entry written by `<2.0.0`; verified
    with the legacy canonicaliser (`_legacy_canonical_json`, kept private
    in `model.py`).
  - `chain_version = 2` — entry written by `>=2.0.0`; verified with
    `canonical_json` (ACTENON-JCS-STRICT-1).

  `Ledger.verify()` dispatches per-entry, so a mixed-version ledger
  (some legacy, some new) verifies intact as long as each entry's hash
  matches its own canonicaliser and the `prev_hash` chain is unbroken.

- **Grant token wire format bump.** `grant_to_token` now mints `v2.`
  tokens (signed with ACTENON-JCS-STRICT-1). Pre-2.0.0 `v1.` tokens are
  still accepted by `token_to_grant` during a deprecation window ending
  with actenon-permit 3.0.0, at which point `v1.` tokens will be rejected.
  Callers holding long-lived `v1.` tokens should re-mint them with
  `grant_to_token` before upgrading to 3.0.0.

### Migration notes

- **Ledger migration**: automatic. The `chain_version` column is added via
  `ALTER TABLE` on first open. Existing rows have `chain_version = NULL`
  (legacy) and continue to verify with the legacy canonicaliser. New rows
  get `chain_version = 2`.

- **Token migration**: re-mint `v1.` tokens by calling `grant_to_token`
  on the underlying `Grant`. The grant's signature is also recomputed
  with the new canonicaliser, so the new `v2.` token will verify with
  the new `verify_signature`.

- **Public `canonical_json` callers**: the function signature is
  unchanged (`canonical_json(obj: Any) -> str`). Callers that passed
  `Decimal` continue to work (coerced via `Decimal.normalize()`). Callers
  that passed `float` will now get `CanonicalisationError` — convert to
  `Decimal` or `int` first.

### Internal changes

- Added `_coerce_decimals` (private) in `model.py` — recursively converts
  `Decimal` to a canonical string form before delegating to the protocol
  canonicaliser.
- Added `_legacy_canonical_json`, `_legacy_default`, `_legacy_sign`,
  `_legacy_verify_signature` (all private) in `model.py` — for verifying
  legacy ledger entries and `v1.` tokens.
- Added `_json_normalize_legacy`, `_coerce_decimals_for_new_chain`,
  `_hash_entry_v2`, `_hash_entry_legacy` (private) in `ledger.py` —
  chain-version-aware hashing.
- Added `chain_version` column to the `ledger` SQLite table (auto-migrated).
- `grant_to_token` now uses `canonicalize_json` for the wire encoding too
  (not just the signature), giving cross-language byte-parity with the
  TypeScript SDK.
- `token_to_grant` dispatches on `v1.` / `v2.` prefix and verifies with
  the appropriate canonicaliser.
- Deleted `_json_default` (the pre-2.0.0 `str()`-as-catch-all default).

## [1.4.0] — pre-2.0.0

(No formal changelog was maintained before 2.0.0. See git history.)
