# Actenon-Permit

> The open authority broker. Issues grants, enforces at the edge, runs the credential broker. The recommended developer entry point for the Actenon ecosystem.

## What this is

Permit is the **on-ramp** for protected AI-agent execution. It:

- Issues **signed, scoped, expiring, revocable** grants (capability tokens)
- Runs the **PDP** (Policy Decision Point) — deterministic ALLOW / DENY / REQUIRE_APPROVAL
- Enforces **budget, rate limits, scope, expiry, and approval** rules at runtime
- Runs the **credential broker** — resolves credentials server-side, never gives them to the agent
- Provides the **Python SDK**, **TypeScript SDK**, **unified CLI**, and **Boundary Kit**

Permit runs **without Cloud**. The `Actenon.local()` SDK constructor creates an in-process gateway with all of the above.

## Install

```bash
pip install actenon-permit
```

## Hero quickstart (6 lines)

```python
from actenon_permit import Actenon, GitHubAdapter

client = Actenon.local(agent_id="my-agent", scopes=["issue.create"])
client.register_credential("GITHUB_TOKEN", "ghp_YOUR_TOKEN")
client.register_adapter_tool("github_issue",
    action_type="github.issue.create",
    adapter=GitHubAdapter(test_mode=True),
    credential_ref="GITHUB_TOKEN", target="github")

intent = client.authorised_execution_intents.create(
    action="github.issue.create", target="github",
    parameters={"owner": "Actenon", "repo": "example", "title": "Hello"})
result = intent.execute()
print(f"{result.state}  {result.finality}")  # succeeded  final
```

**The agent never sees the GitHub token.** The broker resolves it internally and passes it only to the adapter.

## The unified CLI

```bash
actenon demo              # full safe brokered demo (8 guarantees)
actenon protect quickstart ./my-api   # discover + apply + test in one command
actenon protect deploy --mode observe # staging rollout
actenon protect deploy --mode enforce # production
actenon scan              # run the execution-gap scanner
actenon doctor            # diagnose configuration
```

## Boundary Kit — resource-boundary protection in 3 commands

```bash
# 1. Discover consequential endpoints + auto-extract parameter mappings
actenon protect quickstart ./my-api

# 2. Deploy in observe mode (safe rollout)
actenon protect deploy --mode observe

# 3. Switch to enforce
actenon protect deploy --mode enforce
```

The manifest is **~95% auto-generated**. Parameter types, target mappings, and action names are extracted from your FastAPI route signatures. The developer only reviews — they don't write mapping code.

## What the agent never does

- See the raw credential (broker resolves it internally)
- Bypass proof verification (Kernel verifies at the edge)
- Exceed budget/scope/rate (PDP enforces at decision time)
- Replay a proof (lifecycle state machine + replay store)
- Mutate parameters (adapter rejects unknown fields)

## What's in this repo

| Component | Location |
|---|---|
| Python SDK (sync + async) | `src/actenon_permit/sdk/` |
| TypeScript SDK | `ts-sdk/` |
| Unified CLI | `src/actenon_permit/unified_cli.py` |
| Boundary Kit (manifest + middleware) | `src/actenon_permit/boundary/` |
| Credential providers (5 types) | `src/actenon_permit/credentials.py` |
| Provider adapters (GitHub reference) | `src/actenon_permit/adapters/` |
| Intent lifecycle (14 states) | `src/actenon_permit/intent.py` |
| Brokered + resource-owned execution | `src/actenon_permit/execution_modes.py` |

## PyPI

```bash
pip install actenon-permit     # Python SDK + CLI
npm install @actenon/sdk       # TypeScript SDK (planned)
```

## Independence

Permit depends on `actenon-kernel` (runtime) and `actenon-protocol` (runtime). It does NOT depend on Cloud or Scan. The SDK, CLI, and Boundary Kit all work without Cloud.

## License

Apache-2.0
