# Actenon-Permit: Insurable Agent Execution

### A one-page brief for agent-insurance underwriters

---

## The problem you have today

When an AI agent causes a loss — moves money, sends an email, deletes data,
executes a deploy — and a claim lands on your desk, you need to answer one
question: **was this specific action authorized, and can the insured prove it?**

Today they can't. What they hand you is:

- **Connection logs** (Okta / Auth0 / Microsoft Entra) that prove *who connected*
  but not *what exact action was authorized versus what executed*
- **Self-reported application logs** that are mutable, forgeable, and
  post-hoc editable — the insured controls the evidence
- **Policy configurations** that show what was *supposed* to be allowed,
  not what was *cryptographically bound* at the moment of execution

As one carrier guide put it: *"Proving the event was covered gets difficult
fast when the decision was made by a model."* The gap between "the agent was
allowed to do something" and "the agent was authorized for exactly this
$2,500 refund to this specific invoice and no more" is where claims go
unresolvable — and where you carry risk you can't price.

## What Actenon-Permit produces

Every consequential agent action that runs under Actenon generates a
**cryptographic receipt** — a tamper-evident record that proves, at the
moment of execution:

| Property | How it's proven | What logs can't do |
|---|---|---|
| **Exact-action binding** | The receipt is cryptographically bound to the precise action parameters (amount, target, account, invoice ID). Any deviation is refused before execution. | Logs show "a refund happened" — not "this specific $2,500 refund to INV-7831 was the authorized action" |
| **Authorization proof** | An Ed25519-signed PCCB (Proof of Constrained Capability Bound) was issued *before* the action executed, scoped to those exact parameters. | Logs show the action ran — not that it was *authorized for those exact parameters* before it ran |
| **Tamper-evidence** | Every receipt is hash-chained into an append-only ledger. Modifying any entry breaks the chain — detectable by any party, including you. | Logs are editable by the log owner. You trust the insured's word. |
| **Replay-proof** | Each proof is single-use with a unique nonce. A captured proof cannot be reused for a different action. | Logs can be copy-pasted; a log entry doesn't prove the action wasn't replayed |
| **Revocation record** | If the grant was revoked (kill switch), the next call is refused and the revocation is logged with a timestamp. | Logs show what happened — not what was *stopped* from happening |

## Why this is different from what Okta/Microsoft/Google produce

**They log connections; we bind actions.** Their records prove identity and
session — "agent X connected at 3pm." Our records prove authorization and
execution — "agent X was authorized for exactly $2,500 to INV-7831, the
edge verified the proof matched the exact parameters, the credential was
released for one call only, and the receipt is hash-chained and
tamper-evident."

**They are not neutral; we are.** Okta, Microsoft, and Google are
identity-and-platform vendors. Their logs favor their ecosystem and live in
their infrastructure. Actenon-Permit verifies locally — the secret never
leaves the broker, the kernel is a zero-dependency library that makes no
network calls during verification, and there is no telemetry or phone-home.
We can be the referee because we have no stake in which model, cloud, or
identity vendor the enterprise uses. They cannot.

## What this means for underwriting

An enterprise running agents under Actenon-Permit produces, for every
consequential action, a **claims-grade evidence file** that answers the
questions a claims adjuster will ask:

1. *Was this exact action authorized before it executed?* — The PCCB was
   issued and signed before the edge released the credential.
2. *Was the agent authorized for precisely this amount, target, and
   purpose?* — The PCCB is bound to those exact parameters; any deviation
   was refused at the edge.
3. *Could the logs have been altered after the fact?* — No. The hash-chained
   ledger is tamper-evident; any modification is detectable.
4. *Was the action replayed or reused?* — No. Each proof is single-use with
   a unique nonce.
5. *Was the agent's authority revoked in time?* — The revocation is logged
   with a timestamp; calls after revocation are refused.

Enterprises that **cannot** produce this evidence are a higher risk: their
agents' actions are unbound, their logs are mutable, and their
"authorization" is a policy config file, not a cryptographic proof.

## The offer

**"Insurable-by-default"**: enterprises that run their consequential agent
actions under Actenon-Permit produce the evidence file you need to
underwrite — or the claim file you need to adjudicate. We propose working
with you to define the evidence standard for agent-action insurance, so
that "Actenon-conformant receipts" become the underwriting requirement
that makes agent deployments insurable at scale.

This is not a feature pitch. It's a **risk-transfer enabler**: without
verifiable, action-bound, tamper-evident proof, agents are uninsurable at
scale. With it, you can price the risk — because you can verify what
happened.

---

## What's real today (verified, not promised)

- Ed25519-signed PCCBs (real asymmetric cryptography, not dev-HMAC)
- Exact-parameter binding verified at the edge (ACTION_MISMATCH on any deviation)
- Replay-proof (INTENT_MISMATCH on reuse)
- Hash-chained, tamper-evident ledger (modifications detected)
- Kill switch with hard revoke propagation
- Secret never enters agent memory (77 adversarial tests prove no exfiltration)
- Zero telemetry / no phone-home / local verification
- Open-source (Apache-2.0) — inspectable, auditable, no black box

## What's not yet real (honestly)

- No real production deployment (pilot_local_eddsa, not KMS/HSM)
- No real insurance partnership (this brief is the first step)
- No court-admitted evidence precedent (the artifact is designed for it; the precedent doesn't exist yet)
- Cloud control plane is pilot-stage (the open permit repo is production-ready for self-hosting)

---

*Actenon-Permit is open-source (Apache-2.0) at github.com/Actenon/actenon-permit.
The kernel (verifier + spec + conformance) is at github.com/Actenon/actenon-kernel.
The managed control plane is at github.com/Actenon/actenon-cloud.
All three are auditable. Run the demo: `uv run permit demo`*
