# Insurer-Facing Clarity Document

## Three separate questions

Actenon addresses three distinct questions that must not be conflated.
Cryptography proves the first two; it cannot prove the third.

---

### Question 1: Execution Integrity

**Did the action execute exactly as authorised, without mutation, replay,
or bypass?**

What Actenon proves:
- The action parameters were bound to the proof cryptographically (SHA-256
  action hash). Any mutation is detected at the edge.
- The proof was verified by the Kernel before the credential was released.
- The credential was never given to the agent — the broker resolved it
  internally and passed it only to the adapter.
- Replays are refused (single-use proof + lifecycle state machine).
- The provider's response was observed (or marked `outcome_unknown` if not).
- A receipt was issued and cryptographically signed.

What Actenon does NOT prove:
- That the provider (GitHub, Stripe, etc.) executed the action correctly
  on their end. The provider's own response is the evidence; Actenon
  verifies that the response was observed, not that the provider's
  internal state is correct.
- That the provider did not experience a partial failure (the
  `outcome_unknown` state exists precisely for this case).

---

### Question 2: Authority-Process Integrity

**Was the action authorised through the correct policy, approval, and
proof-issuance process?**

What Actenon proves:
- A policy decision was made (ALLOW/DENY/REQUIRE_APPROVAL) with a
  structured reason code.
- If approval was required, the approval was recorded with the approver's
  identity and timestamp.
- A proof (PCCB) was minted by the authority and verified at the edge.
- The grant's scopes, budget, rate limits, and expiry were enforced.
- The entire lifecycle is recorded in the evidence bundle with
  independently verifiable hashes.

What Actenon does NOT prove:
- That the policy itself was correct. If the policy says "allow all
  actions" and an agent deletes a production database, the authority
  process was followed — the policy was just bad. Actenon enforces
  policies; it does not write them.
- That the approver was the right person. If an unauthorised person has
  the `intent.approve` permission, they can approve. Actenon enforces
  that *someone* with the permission approved; it does not verify that
  the permission assignment was correct.

---

### Question 3: Business Decision Correctness

**Was the action the right thing to do for the business?**

What Actenon does NOT prove:
- That the action was wise, profitable, ethical, or free from fraud.
- That the parameters (e.g., refund amount, issue title, role assignment)
  were the correct business decision.
- That the person who requested the action was not themselves deceived,
  coerced, or acting maliciously within their authorised scope.
- That the provider's response was accurate (e.g., a refund may have
  been "succeeded" from Stripe's perspective but wrong for the business).

**Cryptography does not prove business correctness.** It proves that the
execution and authority processes were followed. A fraudulent actor with
valid credentials and correct permissions can execute a "correct"
(technically valid) action that is "wrong" (business-harmful). Actenon's
value is that it makes the action traceable, replayable, and auditable —
so the fraud can be detected after the fact — but it cannot prevent
insider fraud by someone who holds valid authority.

---

## What to tell an insurer

> "Actenon provides cryptographic proof that an AI agent's action was
> executed exactly as authorised, through the correct authority process,
> with a tamper-evident audit trail. It does not prove that the action
> was the correct business decision — that requires human review of the
> policy and the parameters, which Actenon makes possible but does not
> replace."

## Evidence bundle

The evidence bundle (retrievable via `GET /api/v1/intents/{id}/evidence`)
contains all 9 independent artefact layers, each with its own SHA-256
hash. The bundle can be verified independently using
`POST /api/v1/intents/{id}/evidence/verify` — the verifier recomputes
each artefact's hash and checks it matches, without trusting the Cloud UI.

The bundle does NOT contain:
- Credential values (redacted)
- Raw provider responses (redacted by the broker)
- Any Cloud-authored "summary" that replaces the Kernel or Permit artefacts

Each artefact is preserved independently. The Cloud correlation record
(layer 9) links them by stable identifiers — it does not replace them.
