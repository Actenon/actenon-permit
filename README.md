# Actenon-Permit

```
uv run permit demo
```

> Requires [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
> No uv? `pip install -e '.[dev]' && permit demo`, or `python -m actenon_permit.cli demo`.
> No API keys, no network, no real money — works from a fresh clone.

## Why

Most agent security incidents aren't clever exploits — they're
over-permissioned agents doing permitted-but-catastrophic things (a refund
bot that can also charge, an email helper with no spend cap, a coding agent
whose shell tool has no rate limit). Actenon-Permit is the enforcement layer
that sits between an agent and the real world: it issues bounded, expiring,
revocable capability "grants", enforces hard runtime limits the agent
physically cannot exceed, gates high-impact actions behind human approval,
and keeps a tamper-evident audit trail.

## The demo

`uv run permit demo --auto-approve` produces this exact 7-step arc (v0
in-process mode):

```
======================================================================
  Actenon-Permit demo — refund-bot (scripted agent, no LLM, no network)
======================================================================

  issued grant: id=grant_xxxxxxxxxxxxxxxx
  agent:        refund-bot
  budget:       USD 50 (remaining 50)
  scopes.allow: ['payment.refund', 'email.send']
  scopes.deny:  ['payment.charge', 'shell.*']
  approval:     ['email.send']

  step 1: refund($20)                -> [ALLOW]    allowed   (budget 50 -> 30 ...)
  step 2: refund($25)                -> [ALLOW]    allowed   (budget 30 -> 5 ...)
  step 3: refund($20)                -> [DENY]     would exceed USD 50 budget   (only $5 left)
  step 4: send_email(...)            -> [ALLOW]    approved by human (...)
  step 5: charge($100)               -> [DENY]     scope denied: payment.charge   (simulated injection)

  >>> kill switch: `permit revoke refund-bot` — grant REVOKED

  step 7: refund($1)                 -> [DENY]     grant status is revoked   (grant REVOKED)

  ledger chain intact: True

  proof the agent never held the real key:
    the call signature the agent used was `refund(amount=20)` — no `secret` arg.
    the broker resolved MOCK_STRIPE_KEY=sk_mock_*** internally and passed it
    only to the mock provider. the agent only saw the allow/deny result.

======================================================================
  demo complete.
======================================================================
```

### v1 gateway demo (out-of-process PEP)

`uv run permit demo --mode gateway --auto-approve` runs the same 7-step arc,
but every action goes through the v1 out-of-process gateway over HTTP. The
agent process never imports the mock providers, never holds the secret, and
only talks to the gateway via `POST /proxy/<tool>` with a bearer token. This
is the real airlock: even an agent with arbitrary code-exec cannot import the
provider SDK to bypass the wrapper, because the secret is not in its memory.

## How it works

1. **Grant** — a signed, scoped, expiring capability issued to an agent out-of-band.
2. **Decide** — every action runs through a deterministic, fail-closed PDP
   (status → expiry → deny-scope → allow-scope → rate → budget → approval).
3. **Broker** — on ALLOW, the broker swaps the grant for the real credential
   for that one call; the secret never enters the agent's context.
4. **Ledger** — every decision is appended to a hash-chained, tamper-evident
   log. The agent only ever sees the tool signature and the allow/deny result.

## v0 vs v1 — both shipped

**v0 = in-process cooperative enforcement.** The PEP is a Python decorator
(`@guard`) inside the agent's process. This defeats the dominant threat — an
injected or confused agent choosing a dangerous tool or argument, runaway
loops, overspend — because the agent picks tool + args from a fixed registry
and the raw key only exists inside the broker. This is ~90% of real agent
incidents (Step Finance, Grok, Replit were all "agent did a permitted-but-
catastrophic thing").

**v1 = out-of-process proxy / MCP-gateway PEP (now built).** The gateway runs
in a separate process, holds the real credentials, and enforces every
decision server-side. The agent only ever holds a signed bearer token. Two
transports are supported:

- **HTTP proxy** — `POST /proxy/{tool}` with `X-Actenon-Grant` header.
  Returns the tool's result on ALLOW, 403 with a JSON body on DENY.
- **MCP stdio** — JSON-RPC 2.0 over stdin/stdout. Compatible with Claude
  Desktop, Cursor, and any MCP-aware agent host. The grant token is passed
  in `params._meta.actenon_grant`.

Switch from v0 to v1 by changing one import in agent code:

```python
# v0 (in-process)
from actenon_permit import guard, GuardRegistry
@guard("payment.refund", cost_from="amount",
       credential_name="STRIPE_KEY", registry=reg)
def refund(secret, amount, reason=""): ...   # agent holds the secret

# v1 (out-of-process — agent never holds the secret)
from actenon_permit import remote_guard, RemoteGuardRegistry
reg = RemoteGuardRegistry("http://127.0.0.1:7780")
reg.set_grant_token(token)
@remote_guard("payment.refund", cost_from="amount", registry=reg)
def refund(amount, reason=""): ...   # no `secret` param — gateway holds it
```

### v1 CLI

```bash
# ONE-TIME: persist a stable dev signing key so grants validate across
# process restarts (essential for multi-terminal workflows).
permit init-key

# Start the control plane + gateway on one port
permit serve --with-gateway --port 7780

# In another terminal: issue a grant + mint a token
permit issue examples/refund-bot-policy.yaml --quiet
permit mint-token <grant_id> --quiet

# Or run just the MCP stdio server (for Claude Desktop / Cursor)
permit mcp-serve

# Derive a weaker sub-grant (UCAN-style multi-agent delegation)
permit attenuate <grant_id> --budget-limit 10 --scopes-allow payment.refund
```

> Without `permit init-key`, each `permit` invocation generates an ephemeral
> key, so a token minted by `permit mint-token` in one process won't validate
> in `permit serve` in another. `permit init-key` writes a stable key to
> `~/.actenon-permit/signing-key` (mode 0600) — run it once and forget.

### TS SDK (`ts-sdk/`)

A typed TypeScript SDK for non-Python agents:

```ts
import { ControlPlaneClient, GatewayClient } from "@actenon/permit-sdk";

const cp = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:7780" });
const grant = await cp.issueGrant({
  agent: "refund-bot", ttl: "1h",
  budget: { currency: "USD", limit: 50 },
  scopes: { allow: ["payment.refund"], deny: ["payment.charge"] },
});
const { token } = await cp.mintToken(grant.id);

const gw = new GatewayClient({ baseUrl: "http://127.0.0.1:7780", grantToken: token });
const result = await gw.callTool("refund", { amount: 20, reason: "customer" });
```

## Repo layout

```
actenon-permit/
├── README.md                 # this file — first code block is the working command
├── LICENSE                   # Apache-2.0
├── SPEC.md                   # the Grant / capability-token format (standards seed)
├── pyproject.toml            # uv/pip installable; console entrypoint `permit`
├── .env.example              # NAMES of secrets only — never real values
├── .gitignore                # .env, *.db, __pycache__, .venv
├── .github/workflows/ci.yml  # ruff + pytest + demo smoke on every push
├── src/actenon_permit/
│   ├── __init__.py           # public API (v0 + v1)
│   ├── __main__.py           # python -m actenon_permit
│   ├── model.py              # Grant, Action, Decision, Scope, Budget, Rate
│   ├── policy.py             # compile YAML/dict policy -> signed Grant
│   ├── pdp.py                # decide(): deterministic, fail-closed
│   ├── state.py              # StateStore iface + SQLiteStore (atomic reserve/commit)
│   ├── ledger.py             # append-only hash-chained log
│   ├── broker.py             # name->secret resolution; guarded execution
│   ├── enforce.py            # @guard decorator + wrap  (v0 in-process PEP)
│   ├── control.py            # FastAPI control plane: grants/approvals/ledger/attenuate
│   ├── token.py              # v1: grant bearer token wire format (v1.<b64url>)
│   ├── gateway.py            # v1: out-of-process PEP gateway (ToolRegistry + Gateway)
│   ├── _proxy_routes.py      # v1: HTTP proxy FastAPI routes (no future-annotations)
│   ├── pep_client.py         # v1: remote_guard + RemoteGuardRegistry (agent side)
│   ├── _demo.py              # v0 demo (in-process)
│   ├── _demo_gateway.py      # v1 demo (out-of-process HTTP gateway)
│   ├── _mock_providers.py    # fake payments + email — NO real network, NO real money
│   └── cli.py                # permit issue|revoke|watch|ledger|demo|serve|mcp-serve|attenuate|mint-token
├── ts-sdk/                   # v1: TypeScript SDK
│   ├── src/
│   │   ├── types.ts          # Grant, Action, Decision, Policy, AttenuateRequest, ...
│   │   ├── token.ts          # grant_to_token / verifyGrantToken (Web Crypto HMAC)
│   │   ├── client.ts         # ControlPlaneClient (issue/revoke/attenuate/ledger)
│   │   ├── gateway-client.ts # GatewayClient (callTool via HTTP proxy)
│   │   └── index.ts          # barrel export
│   ├── tests/sdk.test.ts     # 6 tests incl. end-to-end against a real Python gateway
│   ├── package.json          # @actenon/permit-sdk
│   └── tsconfig.json
├── examples/
│   ├── mock_providers.py     # thin re-export wrapper (canonical impl in package)
│   └── demo.py               # thin re-export wrapper
└── tests/
    ├── test_pdp.py             # v0: allow/deny/budget/rate/expiry/scope/fail-closed
    ├── test_state.py           # v0: concurrency — two parallel charges can't both clear $50
    ├── test_ledger.py          # v0: tamper-evidence — editing an entry breaks the chain
    ├── test_demo.py            # v0: full 7-step decision sequence end-to-end
    ├── test_token.py           # v1: grant token roundtrip, tamper detection, wrong-key
    ├── test_gateway.py         # v1: gateway direct + HTTP proxy + MCP stdio
    ├── test_remote_pep.py      # v1: remote_guard end-to-end against a live HTTP server
    └── test_attenuation_wire.py # v1: /grants/:id/attenuate + child token usable at gateway
```

## Non-goals for v0/v1

No SaaS/multi-tenant, no distributed state, no real payment integration, no
enterprise directory/SSO, no cloud, no Turing-complete policy DSL (declarative
YAML only; OPA/Rego is a later escape hatch). Local, single-user, one
unforgettable demo.

## Roadmap (beyond v1)

- **Distributed state** — Raft/CRDT-backed state store for multi-node
  gateways. Currently the gateway is single-process; the state store is a
  single SQLite file.
- **OPA/Rego policy escape hatch** — a `policy_engine: "opa"` option that
  delegates `decide()` to an embedded OPA server for Turing-complete rules.
- **Real provider SDKs** — first-class adapters for Stripe, SendGrid, AWS,
  etc. Currently the broker is provider-agnostic (just `real_call(secret, **args)`).
- **MCP gateway-as-a-sidecar** — a Docker image that runs `permit serve
  --with-gateway` so non-Python agents (Claude Desktop, Cursor, a Node.js
  agent) can mount it as a sidecar with zero local setup.

## License

Apache-2.0. See [LICENSE](LICENSE).
