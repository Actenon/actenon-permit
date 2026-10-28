# Permit integrated request review

This review covers the combined typed-request candidate in
`work/actenon-permit-typed-request` before its final signed commit. It is a
local source review with executable counterexamples. It is not a release,
clean-wheel result, live GitHub test or complete amended-goal PASS.

## Findings resolved in the candidate

1. **Typed snapshot and complete parameters.** The candidate copies exact
   JSON-native values before Protocol validation and policy evaluation.
   Floats, tuples, unsupported Python objects and invalid canonical values
   are refused. Nested parameters reach proof and callback together. An
   additional review probe mutated the caller's nested list from 1 to 999
   during policy evaluation: the actual callback retained the approved 1.
   Direct callers must still verify their attempted Action at the edge;
   a proof does not make mutable caller memory authoritative.

2. **Boundary request projection.** Genuine proofs originally allowed
   unbound `Amount` and `transfer_all` body members into the handler.
   The integrated candidate requires the complete declared body field set,
   distinguishes missing from null, compares typed canonical bytes and
   requires a string target. The original review harness now passes all
   five cases, including a simulated validation/copy interleaving.

3. **Raw ingress.** Proxy parsing previously converted invalid UTF-8 to
   `{}` and dispatched it; duplicate members selected the last value.
   HTTP proxy, intent wrappers and MCP now use bounded strict parsing.
   Known wrappers reject unknown/case-variant fields and wrong container
   types. Application data remains case-sensitive and is not globally
   folded or reclassified. The expanded 83-case corpus failed 53 cases on
   untouched `b820b128`; the repaired relevant integration suite passed
   229 tests, including real localhost resource-boundary tests.

4. **Declared handler types.** A valid proof for JSON `true` under an
   `integer` mapping originally reached an ordinary Pydantic handler as
   integer 1; signed string `"100"` became integer 100. Ten of the new
   fifteen handler tests failed before repair. The candidate now enforces
   declared primitive/container types and refuses float/number/unknown
   declarations; the fifteen focused cases pass. This is not a promise
   about custom application transformations or nested schemas absent from
   the manifest. The handler owner must keep those semantics consistent.

5. **Bounded Boundary Kit reads.** Previously `request.body()` buffered
   the entire body before its size check. The new stream wrapper checks
   retained bytes before yielding each chunk into Starlette's normal body
   cache. Real ASGI tests preserve valid request bytes across chunk and
   UTF-8 boundaries. A 2 MiB request now stops after the first chunk beyond
   1 MiB and returns 413 without calling the handler. This framing limit
   applies in enforce, observe and warn modes; forwarding an incompletely
   cached oversized body would silently remove its prefix. In-bounds
   observe/warn behavior is separately retained. Per-chunk allocation by
   the ASGI server is outside this middleware retention bound.

## Preserved evidence

- [Five-case review before](typed-request-review-before.xml)
  and [after](permit-review-regressions-after.xml). The before run occurred
  after the root had already repaired three review cases: two proxy cases
  still failed, three passed. It must not be described as five new failures.
- [Raw ingress initial before](../raw-request-ingress/raw-request-ingress-before.xml):
  35 failed / 30 passed; [expanded final corpus before](../raw-request-ingress/raw-request-ingress-final-corpus-before.xml):
  53 failed / 30 passed.
- [Pinned dependency integration after](../raw-request-ingress/raw-request-ingress-after-pinned.xml):
  229 passed with installed Kernel `66052b20941f908634c9fbac24f1ae7cead78e46`
  and Protocol `8e5bc9e342f694767508bae9a392749c6a8df2cc`.
- [Declared types before](boundary-declared-types-before.xml):
  10 failed / 5 passed.
- [Bounded body before](boundary-bounded-body-before.xml):
  3 failed / 3 passed; [focused integrated after](boundary-bounded-body-after.xml):
  151 passed plus one old test asserting 403 for oversized JSON. The root
  subsequently corrected that expected framing status to 413. The final
  complete suite is owned and recorded by the root, not inferred here.

The original failed assertions and raw logs remain available. Development
signer warnings and the review harness's pytest cache warning are not
provider failures. No live token was printed or provider account used.

## Scope resolution and remaining risk

The existing Airlock protected broker calls Permit PDP and the Kernel
edge in process. It does not parse Permit bearer tokens or expose Permit's
HTTP control plane in that path. Its grant comes from trusted host state;
the initial GitHub adapter must keep that topology and the agent must not
receive signing/admin credentials or another network path.

Grant-token parsing is deliberately outside this patch. A malformed
non-ASCII grant signature still raises `TypeError` from signature
comparison instead of a structured denial. A duplicate-member token can
also be accepted when its decoded object is exactly the originally signed
grant; the review probe retained the same signed grant ID and did not widen
authority. These are availability/raw-contract risks for deployments that
expose Permit token ingress, not a demonstrated bypass of the current
Airlock in-process protected path. They must remain disclosed/excluded and
be repaired before claiming complete hostile-token hardening of that
surface. A deep-token probe returned DENY, so this review does not assert
that every malformed token crashes the gateway.

Control-plane source requires its separate admin bearer credential for
grant issuance, attenuation, token minting and approval actions, and refuses
when no admin token is configured. This was a read-only check, not a full
control-plane fuzz audit. Keeping that administrative surface and key out
of the contained agent remains a deployment invariant.

No additional executable authority bypass of the reviewed initial
in-process protected path was established. This does not clear the wider
programme gates: the final clean candidate installation, useful real-agent
baseline, explicitly authorized real GitHub consequence/reconciliation,
complete containment attacks, public artifact gate and external operator
reproductions still require their own evidence. No merge, push or release
was performed by this review.
