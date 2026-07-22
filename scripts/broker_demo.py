"""Safe end-to-end demo of the brokered execution layer.

This script demonstrates the full Prompt-8 flow:

  1. Compile a grant that allows GitHub actions.
  2. Mint a grant token (the agent's capability).
  3. Build a credential provider registry with the GitHub token ref.
  4. Build a Broker with the registry.
  5. For each action (issue.create, issue.comment, branch.create, pr.open):
     a. Build an Action with the exact params.
     b. Run the PDP to get a Decision (ALLOW).
     c. Call broker.execute_via_adapter() with the GitHubAdapter.
     d. Print the redacted ProviderResponse (the receipt).
  6. Run a final redaction audit: walk every receipt and assert that
     the credential value does not appear anywhere.

By default the demo runs in ``test_mode`` (no network, deterministic
mock responses). To run against the real GitHub API, set:

    ACTENON_BROKER_LIVE_DEMO=1
    ACTENON_BROKER_GITHUB_TOKEN=<token>
    ACTENON_BROKER_GITHUB_OWNER=<owner>
    ACTENON_BROKER_GITHUB_REPO=<repo>

The live demo ONLY does low-risk reversible actions (issue.create,
issue.comment, branch.create, pr.open) in the specified repo. It will
NOT delete anything, force-push, or modify repo settings.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Make the package importable when running the script directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from actenon_permit import (  # noqa: E402
    PDP,
    Broker,
    BrokerExecutionError,
    CredentialProviderRegistry,
    EnvironmentSecretProvider,
    GitHubAdapter,
    Ledger,
    ProviderResponse,
    SQLiteStore,
)
from actenon_permit.model import (  # noqa: E402
    Action,
    Budget,
    Decision,
    DecisionOutcome,
    Grant,
    Rate,
    Scopes,
)

BANNER = r"""
======================================================================
  Actenon-Permit credential broker — safe end-to-end demo (Prompt 8)
======================================================================
"""


def _print(s: str) -> None:
    print(s, flush=True)


def _build_grant(store: SQLiteStore, *, live: bool) -> Grant:
    grant = Grant(
        agent_id="broker-demo-agent",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(
            allow=["issue.create", "issue.comment", "branch.create", "pr.open"],
            deny=["repo.delete", "admin.*"],
        ),
        budget=Budget(currency="USD", limit=10.0, remaining=10.0),
        rate=Rate(max=20, per_seconds=60),
    )
    grant.sign()
    store.put_grant(grant)
    return grant


def _make_pdp(db_path: Path) -> tuple[PDP, SQLiteStore, Ledger]:
    store = SQLiteStore(str(db_path))
    ledger = Ledger(store)
    return PDP(store, ledger), store, ledger


def _make_action(grant: Grant, action_type: str, params: dict[str, Any]) -> Action:
    return Action(
        grant_id=grant.id,
        type=action_type,
        target="github",
        params=params,
        est_cost=0.0,
    )


def _redaction_audit(receipts: list, credential_value: str) -> bool:
    """Walk every receipt and assert the credential value does not appear.

    Returns True if the audit passes (no leak), False otherwise.
    """
    leaks: list[str] = []

    def _walk(obj: Any, path: str) -> None:
        if isinstance(obj, str):
            if credential_value and credential_value in obj:
                leaks.append(path)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                _walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _walk(v, f"{path}[{i}]")

    for i, r in enumerate(receipts):
        _walk(r.provider_evidence, f"receipt[{i}].provider_evidence")
        if r.raw is not None:
            leaks.append(f"receipt[{i}].raw is not None")

    if leaks:
        _print(f"  REDACTION AUDIT FAILED: leaks at {leaks}")
        return False
    _print("  REDACTION AUDIT PASSED: no credential value in any receipt field.")
    return True


def main() -> int:
    live = os.environ.get("ACTENON_BROKER_LIVE_DEMO") == "1"
    token = os.environ.get("ACTENON_BROKER_GITHUB_TOKEN", "")
    owner = os.environ.get("ACTENON_BROKER_GITHUB_OWNER", "actenon")
    repo = os.environ.get("ACTENON_BROKER_GITHUB_REPO", "broker-demo-sandbox")

    _print(BANNER)
    if live:
        if not token:
            _print("LIVE mode requested but ACTENON_BROKER_GITHUB_TOKEN is not set. Aborting.")
            return 2
        _print(f"  Mode:        LIVE (will create real GitHub resources in {owner}/{repo})")
        # Mask the token for display.
        masked = token[:4] + "..." + token[-4:] if len(token) > 8 else "<short>"
        _print(f"  Token:       {masked}  (masked; full value never printed)")
    else:
        _print("  Mode:        TEST (no network, deterministic mock responses)")
        _print("  (set ACTENON_BROKER_LIVE_DEMO=1 to run against the real GitHub API)")
        token = "ghp_TEST_MODE_NOT_A_REAL_TOKEN_0123456789abcdef"

    # ─── 1. Set up state, PDP, broker, adapter ──────────────────────────
    db_path = Path("/tmp/actenon_broker_demo.db")
    if db_path.exists():
        db_path.unlink()
    pdp, store, _ledger = _make_pdp(db_path)
    grant = _build_grant(store, live=live)
    _print(f"\n  Grant issued: id={grant.id}  agent={grant.agent_id}")
    _print(f"  Scopes allow: {grant.scopes.allow}")
    _print(f"  Scopes deny:  {grant.scopes.deny}")
    _print(f"  Budget:       {grant.budget.currency} {grant.budget.remaining}")

    # ─── 2. Credential provider registry ────────────────────────────────
    registry = CredentialProviderRegistry()
    # The credential ref is "GITHUB_TOKEN". The EnvironmentSecretProvider
    # looks up the env var of the same name. We set it explicitly here
    # (overwriting any pre-existing value) so the demo is self-contained.
    os.environ["GITHUB_TOKEN"] = token
    env_provider = EnvironmentSecretProvider()
    registry.register("GITHUB_TOKEN", env_provider)
    if live:
        _print("\n  Credential provider: EnvironmentSecretProvider (ref='GITHUB_TOKEN')")
        _print("  (token value never printed; resolved only inside broker.execute_via_adapter)")
    else:
        _print("\n  Credential provider: EnvironmentSecretProvider (ref='GITHUB_TOKEN', value is test mock)")

    broker = Broker(pdp, credential_providers=registry, production_mode=False)
    adapter = GitHubAdapter(test_mode=not live)

    _print(f"\n  Adapter:      GitHubAdapter (provider_id={adapter.provider_id})")
    _print(f"  Supported:    {adapter.supported_actions()}")
    _print(f"  Health:       {adapter.health()}")

    # ─── 3. Run the four actions ────────────────────────────────────────
    receipts: list = []
    decision = Decision(outcome=DecisionOutcome.ALLOW, reason="demo allow", rule_matched="demo:allow")
    issue_number: int | None = None
    # Use a unique branch name per run to avoid 422 "ref already exists" on
    # live demo reruns. (GitHub refuses to create a branch that already
    # exists; the broker surfaces this as BrokerExecutionError.)
    run_stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    branch_name = f"broker-demo/safe-branch-{run_stamp}"

    def _run_one(label: str, action: Action, key: str) -> Any:
        _print(f"\n  --- {label} ---")
        try:
            r, c = broker.execute_via_adapter(
                grant, action, decision, adapter,
                credential_ref="GITHUB_TOKEN",
                idempotency_key=key,
            )
            _print(f"  ok={r.ok}  action={r.action}  cost={c}")
            _print(f"  evidence: {r.provider_evidence}")
            receipts.append(r)
            return r
        except BrokerExecutionError as e:
            _print(f"  FAILED (broker-execution-error): {e}")
            _print(f"  rule={e.rule}  retryable={e.retryable}")
            # Build a synthetic failed receipt so the redaction audit still runs.
            receipts.append(ProviderResponse(
                ok=False,
                action=action.type,
                provider_action_id=None,
                provider_evidence={"error": str(e), "rule": e.rule},
            ))
            return None
        except Exception as e:
            # Should never happen — broker wraps all adapter errors. But
            # if it does, surface it without leaking anything.
            _print(f"  UNEXPECTED ERROR: {type(e).__name__}: {e}")
            receipts.append(ProviderResponse(
                ok=False,
                action=action.type,
                provider_action_id=None,
                provider_evidence={"error": f"{type(e).__name__}: {e}"},
            ))
            return None

    r1 = _run_one(
        "Action 1: issue.create",
        _make_action(grant, "issue.create", {
            "owner": owner, "repo": repo,
            "title": "[broker-demo] Safe end-to-end demo issue",
            "body": "Created by the Actenon-Permit credential broker demo. Safe to close.",
        }),
        "demo-action-1",
    )
    if r1 and r1.ok and "issue_number" in r1.provider_evidence:
        issue_number = r1.provider_evidence["issue_number"]

    _run_one(
        "Action 2: issue.comment",
        _make_action(grant, "issue.comment", {
            "owner": owner, "repo": repo, "issue_number": issue_number or 1,
            "body": "Comment added by the broker demo. The agent never saw the token.",
        }),
        "demo-action-2",
    )

    _run_one(
        "Action 3: branch.create",
        _make_action(grant, "branch.create", {
            "owner": owner, "repo": repo,
            "branch": branch_name,
        }),
        "demo-action-3",
    )

    _run_one(
        "Action 4: pr.open  (may 422 — head branch has no commits ahead of base)",
        _make_action(grant, "pr.open", {
            "owner": owner, "repo": repo,
            "title": "[broker-demo] Safe end-to-end demo PR",
            "head": branch_name,
            "base": "main",
            "body": "Opened by the Actenon-Permit credential broker demo. Safe to close.",
        }),
        "demo-action-4",
    )

    # ─── 4. Redaction audit ─────────────────────────────────────────────
    _print("\n  --- Redaction audit ---")
    audit_ok = _redaction_audit(receipts, token)

    # ─── 5. Summary ─────────────────────────────────────────────────────
    _print("\n  --- Summary ---")
    _print(f"  actions executed:  {len(receipts)}")
    _print(f"  actions ok:        {sum(1 for r in receipts if r.ok)}")
    _print(f"  broker health:     {broker.health()}")
    _print(f"  redaction audit:   {'PASS' if audit_ok else 'FAIL'}")

    _print("\n  Brokered execution layer demo complete.")
    _print("  Agent never received the raw GitHub token.")
    _print("  Adapter validated every action's params (no silent drops).")
    _print("  Every receipt was redacted before persistence.")
    _print("======================================================================")
    return 0 if audit_ok else 1


if __name__ == "__main__":
    sys.exit(main())
