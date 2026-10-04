# Capability provenance — unified Permit candidate

Scan names a power; Airlock presents the approved capability and exact intent. Permit verifies the grant, decides the call and asks Kernel to sign the proof. Kernel verifies the proof, edge and live authority before invoking the protected executor. Receipt evidence must distinguish releasing an operation from observing its execution.

## Signed authority and live state

The consolidated 2.0 candidate retains #22's strict canonicalisation and v2 grant format, and #23's immutable authority signature. `Grant.sign` covers identity, scopes, limits, currency, expiry, rate and delegation. It excludes `signature`, `status` and `budget.remaining`. Ordinary reservations no longer invalidate the next decision's HMAC.

Unsigned mutable fields are not caller-controlled authority. Execution uses the authoritative store: revoked or expired authority, unavailable status, and exhausted budgets still refuse. The PDP verifies immutable authority before reserving a budget. Widening a signed limit or scope invalidates the signature.

Python and TypeScript use the same v2 signing boundary and shared token vectors. Previously released v1 token bytes retain their full-body legacy verification. The unreleased v2 candidate deliberately rejects the former full-state v2 HMAC; it has no permissive signature fallback. Fixtures cover both authority tampering and repeated execution-state updates.

## Exact proof and revocation

An allowed request mints exactly one concrete capability. The grant may use patterns, but a proof may not contain `*`, `?`, `[` or `]`. An empty allow declaration cannot mint authority by substituting the attempted action. These checks consume Protocol's named-capability helpers, not an Airlock-specific classifier.

The unified Kernel's minter always signs this object in `extensions.authority`:

```json
{"authority":{"issuer":"service:actenon-permit","grant_id":"<id>","revocable":true}}
```

There is no signature-introspection fallback that silently drops the authority reference. `StoreRevocationChecker` checks the grant and all ancestors against the authoritative store. Unknown grant, revoked or expired authority, incomplete reference, and an unreadable store fail closed. Kernel replay protection and exact action/resource/parameter binding remain separate mandatory checks.

## Coordinated dependency freeze

The candidate requires Protocol **>=1.5.0,<2** and Kernel **>=1.3.0,<2**. During source integration, `tool.uv.sources`, `uv.lock` and the pip candidate constraint file select exact immutable coordinated inputs. This is one Kernel containing both #41 and #43, with signed extensions and production defaults, rather than a choice between two histories.

Version is **2.0.0rc1** (Python) / **2.0.0-rc.1** (TypeScript). No publication follows from these source tests. Publish and independently verify the canonical dependencies first; then remove source overrides and regenerate the lock from public registries. The release gate refuses publication while source overrides remain. Airlock's historical PR #3 pins are preserved until its explicit update to the unified line.
