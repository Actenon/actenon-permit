# Shared delegated budget counterexamples and candidate repair

Canonical baseline: Permit `6bbf731125cdde97c1f7b48697c438356a2ccca4`.
Two sibling grants each spent 30 against their parent ceiling of 50, including
through independent SQLite clients. Both original failing tests are frozen here.
The initial repair also allowed a paid sibling to dispatch after another effect
created known parent overrun debt; that counterexample is preserved separately.

This is an explicit **2.0 candidate contract change** from independent child
spending. SPEC §13.3 defines shared ancestor consumption and migration. Earlier
independent semantics are retained in prior evidence, not relabeled as passing.
The old wire assertion that the parent stays at 100 after a child's spend of 15
now checks the shared balance of 85. Issuance still leaves 100 unchanged. A
hand-built edge-test child widened expiry and changed a literal allow pattern;
its fixture now uses the existing attenuation API and retains the parent scope.
The protected edge still verifies the same exact action and revocation behavior.

Every reservation checks authenticated bounded lineage, available balances and
aggregate rate hits, then debits all owners in one SQLite write transaction.
Settlement/refund uses its frozen owners, once. Ambiguity holds all balances;
provider overruns remain durable debt and stop later dispatch. Refunds do not
revive revoked grants. Existing legacy and effect-aware APIs share this path.

Migration charges retained legacy held/committed cost to ancestors once across
independent clients. Missing/invalid retained lineage refuses setup and rolls
back. Old manual parent allocations cannot always be distinguished, so balances
may narrow conservatively. Back up and review before migration. No historical
cost/debt is forgiven and no cross-host or rolling-money guarantee is claimed.

Full Python suite: 697 passed, one documented preexisting live-provider skip.
Additional final targeted suite: 21 passed, covering settlement rollback and
independent-client settlement. Kernel conformance: 53 passed, zero skips from
outside the source tree. One earlier invocation hit the documented local
examples/ shadow; that invocation is not called a kernel defect or PASS.
CI on the exact candidate remains required before merge or Airlock adoption.
No package/tag/release has been published by this repair.

Candidate wheel payload imported from an isolated extracted wheel path, outside
the source package. Shared ceiling refusal and ancestor refund passed. Metadata
records its hash. Engine dependencies were already installed; this is a payload
check, not the North-Star clean-install or independent-reproduction gate.
