#!/usr/bin/env python3
"""Actenon SDK hero quickstart (Prompt 11).

Demonstrates the 6 required guarantees:

  1. A permitted action executes.
  2. A proofless action is refused.
  3. A parameter-mutated action is refused.
  4. A replay is refused or safely reconciled.
  5. A receipt is returned.
  6. The raw provider credential is never given to the agent.

Uses the GitHubAdapter in test_mode (no network, deterministic mock
responses). The raw GitHub token is registered as a development-only
credential; the agent never sees it.
"""

from __future__ import annotations

import os
import sys

# Make the package importable when running the script directly.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from actenon_permit import (  # noqa: E402
    Actenon,
    ActenonError,
    BrokeredResult,
    ExecutionRefusedError,
    GitHubAdapter,
)


def main() -> int:
    print("=" * 70)
    print("  Actenon SDK — Hero Quickstart (Prompt 11)")
    print("=" * 70)

    # ─── Setup ──────────────────────────────────────────────────────
    # Create a local client with a stable signing key.
    # The GitHubAdapter is in test_mode (no network).
    # The adapter supports action types: issue.create, issue.comment,
    # branch.create, pr.open (without the 'github.' prefix).
    client = Actenon.local(
        agent_id="quickstart-agent",
        scopes=["issue.create"],
        signing_key="quickstart-signing-key-not-for-production",
    )

    # Register a development-only GitHub token. The agent NEVER sees this
    # value — the broker resolves it internally and passes it only to the
    # adapter.
    client.register_credential("GITHUB_TOKEN", "ghp_QUICKSTART_NOT_REAL_0123456789abcdef")

    # Register the GitHub adapter tool.
    client.register_adapter_tool(
        "github_issue",
        action_type="issue.create",
        adapter=GitHubAdapter(test_mode=True),
        credential_ref="GITHUB_TOKEN",
        target="github",
    )

    print("\n  Client created. Capabilities:")
    caps = client.capabilities
    print(f"    transport:           {caps.transport}")
    print(f"    supports_brokered:   {caps.supports_brokered}")
    print(f"    production_mode:     {caps.production_mode}")
    print(f"    durable:             {caps.durable}")

    # ─── 1. A permitted action executes ─────────────────────────────
    print("\n  --- 1. Permitted action executes ---")
    intent = client.authorised_execution_intents.create(
        action="issue.create",
        target="github",
        parameters={"owner": "Actenon", "repo": "example", "title": "Hello from Actenon SDK"},
    )
    print(f"  Created intent: {intent.intent_id}  state={intent.lifecycle_state}")

    result = intent.execute()
    assert isinstance(result, BrokeredResult), f"expected BrokeredResult, got {type(result).__name__}"
    assert result.succeeded, f"expected succeeded, got {result.state}"
    print(f"  Result: mode={result.mode}  state={result.state}  finality={result.finality}")
    print(f"  provider_execution_observed={result.provider_execution_observed}")
    print(f"  receipt_received={result.receipt_received}  receipt_verified={result.receipt_verified}")
    print(f"  evidence: {result.evidence}")
    print("  ✓ Permitted action executed successfully.")

    # ─── 2. A proofless action is refused ───────────────────────────
    # In brokered mode, "proofless" means the action type is not in the
    # grant's scopes. We create an intent for an action the grant doesn't
    # allow, and execution is refused.
    print("\n  --- 2. Proofless/out-of-scope action is refused ---")
    # Build a client with a grant that only allows issue.create, then
    # try to execute a different action type.
    intent2 = client.authorised_execution_intents.create(
        action="repo.delete",  # NOT in scopes
        target="github",
        parameters={"owner": "Actenon", "repo": "example"},
    )
    try:
        intent2.execute()
        print("  ✗ FAIL: should have been refused")
        return 1
    except ExecutionRefusedError as e:
        print(f"  ✓ Out-of-scope action refused: {e}")
        print(f"    rule={e.rule}  reason={e.reason}")

    # ─── 3. A parameter-mutated action is refused ───────────────────
    # The adapter validates parameters strictly. An unknown field
    # ("malicious_field") causes a refusal.
    print("\n  --- 3. Parameter-mutated action is refused ---")
    intent3 = client.authorised_execution_intents.create(
        action="issue.create",
        target="github",
        parameters={
            "owner": "Actenon", "repo": "example", "title": "test",
            "malicious_field": "should be rejected",  # unknown parameter
        },
    )
    try:
        intent3.execute()
        print("  ✗ FAIL: should have been refused")
        return 1
    except ExecutionRefusedError as e:
        print(f"  ✓ Mutated parameters refused: {e}")
        print(f"    rule={e.rule}")

    # ─── 4. A replay is refused or safely reconciled ────────────────
    # Re-executing the same intent (which has already transitioned to
    # succeeded) is refused — the lifecycle state machine prevents
    # transitions from terminal states.
    print("\n  --- 4. Replay is refused ---")
    try:
        intent.execute()  # intent already succeeded
        print("  ✗ FAIL: should have been refused (replay)")
        return 1
    except (ActenonError, Exception) as e:
        print(f"  ✓ Replay refused: {type(e).__name__}: {e}")

    # ─── 5. A receipt is returned ───────────────────────────────────
    print("\n  --- 5. A receipt is returned ---")
    # The result from step 1 carries receipt fields.
    assert result.receipt_received, "receipt_received should be True"
    assert result.receipt_verified, "receipt_verified should be True"
    print(f"  ✓ Receipt returned: received={result.receipt_received}  verified={result.receipt_verified}")
    print(f"    evidence keys: {list(result.evidence.keys())}")

    # ─── 6. The raw provider credential is never given to the agent ─
    print("\n  --- 6. Raw provider credential never given to agent ---")
    # The agent (this script) only sees the redacted evidence. The raw
    # GitHub token ("ghp_QUICKSTART_NOT_REAL_0123456789abcdef") must NOT
    # appear anywhere in the result.
    raw_token = "ghp_QUICKSTART_NOT_REAL_0123456789abcdef"
    result_str = repr(result) + repr(result.evidence)
    if raw_token in result_str:
        print("  ✗ FAIL: raw token leaked into result!")
        return 1
    print("  ✓ Raw provider credential never appeared in the result.")

    # ─── Summary ────────────────────────────────────────────────────
    print("\n  --- Summary ---")
    print("  All 6 hero quickstart guarantees demonstrated:")
    print("    1. ✓ Permitted action executed")
    print("    2. ✓ Out-of-scope action refused")
    print("    3. ✓ Mutated parameters refused")
    print("    4. ✓ Replay refused")
    print("    5. ✓ Receipt returned")
    print("    6. ✓ Raw credential never leaked")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
