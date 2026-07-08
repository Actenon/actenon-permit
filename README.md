# Actenon-Permit

```
uv run permit demo
```

(Or: `python -m actenon_permit.cli demo`. Both work from a fresh clone with no
API keys, no network, and no real money.)

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

`uv run permit demo --auto-approve` produces this exact sequence:

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

  approval mode: AUTO (CI)

  step 1: refund($20)                -> [ALLOW]    allowed   (budget 50 -> 30 ...)
  step 2: refund($25)                -> [ALLOW]    allowed   (budget 30 -> 5 ...)
  step 3: refund($20)                -> [DENY]     would exceed USD 50 budget   (budget: only $5 left of $50)
  step 4: send_email(...)            -> [ALLOW]    approved by human (...)
  step 5: charge($100)               -> [DENY]     scope denied: payment.charge   (simulated injection: payment.charge denied)

  >>> kill switch: `permit revoke refund-bot` — grant REVOKED

  step 7: refund($1)                 -> [DENY]     grant status is revoked   (grant REVOKED)

  ledger (last 8 entries):
    ALLOW   payment.refund           reason=allowed  hash=xxxxxxxxxxxx...
    ALLOW   payment.refund           reason=allowed  hash=xxxxxxxxxxxx...
    DENY    payment.refund           reason=would exceed USD 50 budget  hash=xxxxxxxxxxxx...
    REQUIRE_APPROVAL  email.send     reason=approval required: email.send  hash=xxxxxxxxxxxx...
    ALLOW   email.send               reason=allowed  hash=xxxxxxxxxxxx...
    DENY    payment.charge           reason=scope denied: payment.charge  hash=xxxxxxxxxxxx...
    DENY    payment.refund           reason=grant status is revoked  hash=xxxxxxxxxxxx...

  ledger chain intact: True

  proof the agent never held the real key:
    the call signature the agent used was `refund(amount=20)` — no `secret` arg.
    the broker resolved MOCK_STRIPE_KEY=sk_mock_*** internally and passed it
    only to the mock provider. the agent only saw the allow/deny result.

======================================================================
  demo complete.
======================================================================
```

## How it works

1. **Grant** — a signed, scoped, expiring capability issued to an agent out-of-band.
2. **Decide** — every action runs through a deterministic, fail-closed PDP
   (status → expiry → deny-scope → allow-scope → rate → budget → approval).
3. **Broker** — on ALLOW, the broker swaps the grant for the real credential
   for that one call; the secret never enters the agent's context.
4. **Ledger** — every decision is appended to a hash-chained, tamper-evident
   log. The agent only ever sees the tool signature and the allow/deny result.

## Honest limitation (v0 vs v1)

**v0 = in-process cooperative enforcement.** The PEP is a Python decorator
inside the agent's process. This defeats the dominant threat — an injected or
confused agent choosing a dangerous tool or argument, runaway loops, and
overspend — because the agent picks tool + args from a fixed registry and the
raw key only exists inside the broker. This is ~90% of real agent incidents
(Step Finance, Grok, Replit were all "agent did a permitted-but-catastrophic
thing").

**v1 = out-of-process proxy / MCP-gateway PEP.** This is the real airlock. It
closes the gap where an agent with arbitrary code-exec imports the provider
SDK directly to bypass the wrapper, by moving enforcement to the network
boundary. The v0 codebase is structured so this is an additive change, not a
rewrite. Being upfront about this is a credibility asset, not a weakness.

## Roadmap

- **TS SDK** — a typed TypeScript client for the control plane, so non-Python
  agents can use the same broker + ledger.
- **MCP-proxy PEP** — an out-of-process Model Context Protocol gateway that
  enforces decisions at the network boundary (the v1 trust boundary above).
- **Attenuated multi-agent delegation** — UCAN-style: an agent can derive a
  weaker sub-grant for a sub-agent, never a stronger one. The `Grant.attenuate()`
  API already enforces this; what's missing is the wire protocol for handing
  the sub-grant to a child process.

## Repo layout

```
Actenon-Permit/
├── README.md                 # this file — first code block is the working command
├── LICENSE                   # Apache-2.0
├── SPEC.md                   # the Grant / capability-token format (standards seed)
├── pyproject.toml            # uv/pip installable; console entrypoint `permit`
├── .env.example              # NAMES of secrets only — never real values
├── .gitignore                # .env, *.db, __pycache__, .venv
├── .github/workflows/ci.yml  # ruff + pytest + demo smoke on every push
├── src/actenon_permit/
│   ├── __init__.py           # public API
│   ├── model.py              # Grant, Action, Decision, Scope, Budget, Rate
│   ├── policy.py             # compile YAML/dict policy -> signed Grant
│   ├── pdp.py                # decide(): deterministic, fail-closed
│   ├── state.py              # StateStore iface + SQLiteStore (atomic reserve/commit)
│   ├── ledger.py             # append-only hash-chained log
│   ├── broker.py             # name->secret resolution; guarded execution
│   ├── enforce.py            # @guard decorator + wrap(tool)  ← in-process PEP
│   ├── control.py            # FastAPI: issue/list/revoke/approve/ledger + SSE
│   └── cli.py                # permit issue | revoke | watch | ledger | demo | serve
├── examples/
│   ├── mock_providers.py     # fake payments + email — NO real network, NO real money
│   └── demo.py               # scripted agent + the exact 7-step scenario
└── tests/
    ├── test_pdp.py           # allow/deny/budget/rate/expiry/scope/fail-closed
    ├── test_state.py         # concurrency: two parallel charges can't both clear $50
    ├── test_ledger.py        # tamper-evidence: editing an entry breaks the chain
    └── test_demo.py          # asserts the full 7-step decision sequence end-to-end
```

## Non-goals for v0

No SaaS/multi-tenant, no distributed state, no real payment integration, no
enterprise directory/SSO, no cloud, no second language, no Turing-complete
policy DSL (declarative YAML only; OPA/Rego is a later escape hatch). Local,
single-user, one language, one unforgettable demo.

## License

Apache-2.0. See [LICENSE](LICENSE).
