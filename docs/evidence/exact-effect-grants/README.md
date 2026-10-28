# Exact effect authority candidate

Baseline: Permit main `5290b1304eead3e638c5a4aa1600fa63ba3137e8`.
Before this addition, the requested finite effect field was ignored: changed
body/method/target/owner/action, the plain PDP and the legacy reservation path
were allowed. The frozen first run records 12 failures and one pass.

The signed finite set now narrows Permit authority, with Protocol effect IDs as
the sole identity. Store reservation and edge dispatch check every live ancestor.
A finite grant cannot use the legacy path; matching exact issuer approval can
satisfy human rules for only that effect. SPEC documents absent/null compatibility,
empty-set denial, attenuation, signing and the supported shared-store topology.
No frozen legacy token vector was edited. New Python/TypeScript vectors include
finite/empty/legacy grants and removed/replaced/malformed constraints.

Validation: full Python suite 723 passed, one preexisting live-provider skip;
focused integration 75 passed; TypeScript token interop 26 passed, typecheck
passed. Real signed Permit proofs and the independent Kernel allow the exact
request once and reject mutation/replay. Dispatch rechecks a narrowed live grant.
The initial child-widening test expected a false return, but the existing store
contract raises StateError for malformed ancestry; the test now requires that
refusal and verifies no budget changed. It was not changed to permit the effect.

Full exact-candidate CI remains required. No packages, tags or releases are
published. This is one prerequisite for Airlock's exact publication workflow,
not a claim that the complete protected useful-agent harness has passed.
