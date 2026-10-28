# Typed request and bounded ingress — integrated candidate evidence

The candidate keeps the same typed request through policy, proof and dispatch.
Unsupported floats/tuples/custom values are refused before policy/debit. The
real GitHub adapter validates its schema; the gateway snapshots all nested
parameters. Boundary Kit binds the closed body, exact target and declared JSON
types and bounds input while retaining valid bytes for the downstream handler.
Protocol owns strict JSON semantics. See SPEC section 16 for the explicit
unreleased-candidate compatibility correction and exclusions.

## Actual validation

With Kernel `66052b2` and Protocol `8e5bc9e` installed, the final full Python suite
passed **876 tests**, with one existing live-provider skip and no unexpected
skips. TypeScript passed 68, Kernel conformance passed 53 with no skips; lint,
locked dependency resolution, release-check manifest and both shipped demos
passed. These are local candidate results, not clean public installation,
provider truth, complete gate B, or independent reproduction.

## Preserved counterexamples and historical failures

- Corrected first 23-case harness:16 failures / 7 passes; a genuine string-body
  proof accepted a float-body Action and the real adapter serialized the float.
  HTTP was captured, not sent to live GitHub. The earlier harness also had two
  setup defects (missing node_id and reused action ID); those are not exploits.
- Gateway: 4 failures: dropped nested parameters or unsupported values reached a
  callback. Boundary: 5 failures: bool/int comparison and duplicate JSON members.
- Raw boundary: 9 failures / 1 pass, closed body: 4 failures, snapshot: 1 failure.
- Raw proxy/intent/MCP final 83-case baseline:53 failures / 30 passes; malformed
  input became empty parameters and wrappers could discard unknown fields.
  Separate raw-request-ingress evidence retains its full 229-case integration.
- Independent review found10 declared-type failures / 5 passes through actual
  FastAPI/Pydantic handlers, and 3 oversized-stream failures / 3 passes. Repaired
  declared types refuse coercion; streaming stops after the first excess
  chunk. Over-limit HTTP 413 applies even in observe/warn, never forwarding a
  truncated request. Individual ASGI chunk allocation remains server-owned.
- The first full repair run was 744 passes / 1 skip / 2 old float-contract failures;
  original test files remain in legacy-contract-tests. The seven-step
  budget/scope/revocation arc remains required with integer parameters.
- The first combined ingress run was 853 passes / 1 skip / 2 assertion failures:
  float refusal moved earlier to raw parsing; the unknown-tool test now uses
  valid typed input to retain its original scope expectation. Raw logs remain.
- A local demo initially completed with the wrong arc due to float inputs;
  the input migration and a real HTTP demo assertion repair that evidence.
  Sandbox listener setup errors are retained separately from application bugs.

The manifest records exact source file hashes and installation scope. All raw
logs are retained byte-for-byte. SHA256SUMS covers the evidence files except
itself. Prior partial manifests remain historical rather than current claims.
No merge, tag, release, live account mutation or AIRLOCK-001 run was performed.
