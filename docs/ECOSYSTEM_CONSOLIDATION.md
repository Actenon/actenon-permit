# Permit consolidation evidence

Both candidate histories remain merge parents: production #22 at `34c10e6fb9f25678633766b295eece3f8a97611c` and provenance #23 at `e368dca24af6f316590ce5fd1a0e83a9aebee924`.

The 2.0 candidate retains strict canonicalisation, v2 grants, secure defaults, exact proof generation, signed authority references, revocation, installed-kernel conformance, TypeScript integration, and release/CI hardening. Immutable authority signatures from #23 now apply in both Python and TypeScript. Released v1 token fixture bytes are unchanged; unreleased v2 signatures are regenerated for the corrected immutable authority contract, with new negative widening and old-HMAC counterexamples.

All existing required CI checks remain. Plain-install, dependency-audit and ecosystem-claims checks use immutable coordinated source constraints while the new dependency versions await publication. Registry-install commands still check live registries. These source checks do not establish public-artifact readiness: release_gate refuses any remaining source overrides.

The original release evidence remains associated with its original commits. The unified candidate requires a new exact-source freeze, complete CI, artifact rehearsal and public consumer verification in dependency order. No historical tarball or wheel checksum is claimed for changed source.

Kernel #45 repaired the tracked dependency lock after #44 merged. This candidate now uses that reviewed main commit (`8f5ab060874057e60253edd801b905e95b75d84e`), including the cryptography 50 minimum. The regenerated Permit lock is tested and audited as installed, rather than relying only on a fresh resolver. The immutable authority and fixture contracts are unchanged.
