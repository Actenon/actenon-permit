# Raw request ingress correction

This is a narrow continuation of the amended goal B typed-request repair.
Base source is Permit `b820b128c1166993c416c8c4e61d41c78bf90809`. No provider
account, paid service, public mutation, merge or release was used.

## Reproduction and repair

The existing HTTP proxy converted malformed JSON/UTF-8 to `{}` and could
dispatch a real registered callback with those empty parameters. Duplicate
JSON members were parsed with last-value-wins behavior. The intent routes
and MCP framing had comparable raw parsing gaps; unused wrapper fields
could disappear before policy. These are locally reproduced request
handling defects, not evidence of a live provider accepting an exploit.

`_request_json.py` delegates value and duplicate-member semantics to
Protocol's `parse_strict`. It bounds raw requests to 1 MiB, requires strict
UTF-8 and an object, and uses streaming HTTP reads. MCP stdin is binary by
default; bounded line reads drain an oversized frame without interpreting
its suffix as a new command. Malformed input never becomes `{}`.

Known intent, submission and MCP wrappers reject unknown fields and wrong
field types. Application JSON keys remain case-sensitive and preserved;
they are not globally case-folded. Consequential parameter validation and
authority remain the existing adapter/PDP/Kernel responsibilities. This
does not introduce a separate capability classifier or new proof encoding.

An absent `/intents/{id}/execute` body and explicit `{}` remain supported.
No execution overrides are implemented, so nonempty execute bodies are
now refused. Proxy calls require an explicit JSON object, including `{}`
for zero-argument tools. Float/exponent/non-finite representations are
refused under the Protocol strict profile before gateway entry.

## Evidence

- Initial 65-case corpus on the old source: **35 failed, 30 passed**.
- Expanded final 83-case corpus on untouched old source: **53 failed,
  30 passed**. All before results and original test assertions are retained.
- Repaired corpus plus existing gateway, intent, real localhost resource
  boundary, execution-mode and adversarial tests: **229 passed**.
- First sandbox-limited after run: 196 passed, 15 setup errors because
  local listening sockets were prohibited. It is retained separately;
  the explicit local-server rerun passed.
- Lint and whitespace validation passed.

The initial after run uses explicit Permit and Protocol source paths;
the separate `after-pinned` run uses the consolidated candidate's installed
Kernel/Protocol environment. `manifest.json` identifies paths, installed
metadata, hashes and outcomes. Source paths are not evidence of public
registry installation. The final combined candidate must rerun its full
suite after integrating this patch with the other typed-request changes.

The new corpus exercises actual FastAPI and MCP entrypoints, rejects
before gateway methods or callbacks, and retains valid Unicode/large
integer requests. Existing tests cover successful full intent lifecycles
and localhost resource-boundary execution. No tests claim live GitHub
state, provider reconciliation, complete containment or external operators.

Grant-token parsing and control-plane routes are outside this patch's
owned scope. They must not be described as covered by this ingress result.
