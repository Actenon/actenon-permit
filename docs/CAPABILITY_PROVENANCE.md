# Capability provenance

Scan names a power. Permit signs that name into a grant, decides the call,
and asks the Kernel to mint a proof. The edge writes a receipt only after
the Kernel verifies that proof. Airlock is the runtime that binds a Python
agent's calls into this path. This document is the Permit contract Airlock
[PR #3](https://github.com/Actenon/actenon-airlock/pull/3) calls, including
the Scan authority vocabulary from
[actenon-scan PR #101](https://github.com/Actenon/actenon-scan/pull/101).

## What Airlock sends

Airlock builds one `Grant` per launch:

- `scopes.allow` is the set of Scan-named powers the operator approved.
  Each entry is an exact capability id (`airlock.` plus a digest of the
  Scan action, resource, and transport). Airlock does not put `*` in that
  list.
- An agent with no approved power gets `allow=[]` and `deny=["*"]`. An empty
  allow list is permissive at `PDP.decide` (SPEC §4). The deny entry closes
  it. `decide_and_mint_pccb` also refuses to mint from an empty allow list,
  so the attempted action is not copied into a proof.
- A call Scan cannot resolve becomes `airlock.unresolved.<digest>`. That id
  is outside the allow list, and the PDP denies it with `out of scope`.
- Airlock reloads the grant from `SQLiteStore` before every decision and
  compares it to the signed launch grant, ignoring `status` and `budget`.
  It then calls `PDP.decide_and_mint_pccb` and `ActenonGate.protect` with
  `StoreRevocationChecker`.

Scan PR #101 is the vocabulary patch that names tiktoken encoding downloads,
fixes `https://host?query` host naming, and exports `normalise_path`. Permit
does not parse call text. It authorises the capability strings Scan and
Airlock already agreed on.

## Signed grants

`Grant.sign` HMACs the authority payload: every field except `signature`,
`status`, and `budget.remaining`. `budget.limit` and `budget.currency` stay
signed.

`reserve`, `commit`, `release`, and `set_status` rewrite `status` and
`budget.remaining` in the stored body. Those updates used to invalidate the
HMAC, so every decision after the first ALLOW failed with "grant signature
could not be verified" when the caller reloaded the row. The signature is
now stable across those updates. `Grant.verify` is false when the signature
is missing or when scopes, the budget cap, expiry, rate, or identity change.

The PDP checks `verify()` before it reserves. A tampered grant is `DENY`
with reason `grant signature could not be verified`. Live status is still
enforced after that: a revoked grant verifies and is then denied with
`grant status is revoked`.

## Proofs

On ALLOW, the PCCB scope is exactly `(action.type,)`.

- The allow list is not copied onto the proof. A grant of `payment.*` plus
  `email.send` mints a proof whose capability is `payment.refund`, which is
  the action the PDP matched.
- `*`, `?`, and `[` are scope patterns. They are rejected as a proof
  capability.
- An empty `scope_capabilities` tuple is not passed to the kernel. The
  kernel minter would otherwise substitute the attempted action.

Where the installed kernel's `PCCBMinter.mint` accepts `extensions`, the
proof carries:

```json
{"authority": {"issuer": "service:actenon-permit", "grant_id": "<id>", "revocable": true}}
```

`StoreRevocationChecker` (`actenon_permit.revocation`) returns true only when
that grant and every ancestor are known, active, and unexpired. An unknown
grant, a missing authority reference, or a store error raises
`RevocationLookupError`. The kernel treats that as revocation status unknown
and refuses the call. PyPI `actenon-kernel` 1.2.1 cannot sign extensions;
Airlock's kernel pin can. On 1.2.1 the checker fails closed, which is the
safe outcome.

## Pin Airlock should use

Do not pin PyPI `actenon-permit` 1.4.0 for this contract. That release signs
`status` and `budget.remaining`, so the second ALLOW in a session does not
verify, and it does not ship `StoreRevocationChecker`.

Pin the git commit that added this file (the head SHA is in the Permit PR),
together with the kernel Airlock already pins
(`533c029d63b5ce070a1eb8d8513e8e57a75ec703`), whose `PCCBMinter.mint` accepts
`extensions`:

```text
actenon-permit @ git+https://github.com/Actenon/actenon-permit.git@<PR_HEAD_SHA>
```

Package version stays `1.4.0`. PyPI `actenon-permit` 1.4.0 does not include
this contract, and nothing here publishes a new release.
