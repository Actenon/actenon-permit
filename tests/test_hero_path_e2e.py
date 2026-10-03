"""End-to-end hero path, in process, exactly as the README describes it.

Actenon.local() grant -> PDP ALLOW -> kernel-minted PCCB -> edge verification
-> brokered adapter executes once -> kernel Receipt that verifies offline with
the kernel CLI; then replay, widened parameters, a revoked grant and an
expired grant are each refused, and the adapter is never called for them.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import warnings
from datetime import UTC, datetime, timedelta

import pytest
from actenon.core.errors import ProofVerificationError
from actenon.models.contracts import PCCB, ActionIntent

from actenon_permit import Actenon, ActenonError, ExecutionRefusedError, GitHubAdapter
from actenon_permit.kernel_bridge import verify_pccb_at_edge
from actenon_permit.model import Action, Grant, GrantStatus
from actenon_permit.token import grant_to_token

SECRET = "ghp_HERO_PATH_NOT_REAL_0123456789"
PARAMS = {"owner": "Actenon", "repo": "example", "title": "Hello"}


class CountingGitHubAdapter(GitHubAdapter):
    def __init__(self) -> None:
        super().__init__(test_mode=True)
        self.executions = 0

    def execute(self, action, params, credential, **kwargs):
        self.executions += 1
        return super().execute(action, params, credential, **kwargs)


@pytest.fixture
def hero(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("ACTENON_ED25519_KEY_FILE", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        client = Actenon.local(
            agent_id="my-agent",
            scopes=["github.issue.create"],
            signing_key="hero-path-signing-key",
        )
        client.register_credential("GITHUB_TOKEN", SECRET)
    adapter = CountingGitHubAdapter()
    client.register_adapter_tool(
        "github_issue",
        action_type="github.issue.create",
        adapter=adapter,
        credential_ref="GITHUB_TOKEN",
        target="github",
    )
    return client, adapter


def _create(client, params=PARAMS):
    return client.authorised_execution_intents.create(
        action="github.issue.create", target="github", parameters=dict(params)
    )


def _kernel_cli(*args: str, cwd) -> subprocess.CompletedProcess:
    # The PCCB is HS256 under the dev signing key; kernels that also verify
    # the linked PCCB's signature take that key from ACTENON_LOCAL_HMAC_SECRET.
    env = {**os.environ, "ACTENON_LOCAL_HMAC_SECRET": "hero-path-signing-key"}
    return subprocess.run(
        [sys.executable, "-m", "actenon.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
    )


def test_hero_path_end_to_end(hero, tmp_path):
    client, adapter = hero

    # 1. Grant -> ALLOW -> PCCB -> edge verification -> executes once.
    intent = _create(client)
    result = intent.execute()
    assert (result.state, result.finality) == ("succeeded", "final")
    assert adapter.executions == 1
    assert SECRET not in json.dumps([result.evidence, result.receipt, result.proof])

    # 2. The Receipt verifies offline with the kernel CLI, linked to the
    #    exact Action Intent and PCCB.
    assert result.receipt_received and result.receipt_verified
    files = {
        "receipt": result.receipt,
        "intent": result.proof["intent"],
        "pccb": result.proof["pccb"],
    }
    for name, payload in files.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(payload))
    proc = _kernel_cli(
        "verify-receipt",
        "--receipt",
        "receipt.json",
        "--intent",
        "intent.json",
        "--pccb",
        "pccb.json",
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # kernel <= 1.2.1: "Receipt verified."; newer: "Receipt links verified."
    assert re.search(r"Receipt (links )?verified\.", proc.stdout), proc.stdout

    # 3. Replay: the same intent cannot execute again.
    with pytest.raises(ActenonError):
        intent.execute()
    assert adapter.executions == 1

    # 4. Widened parameters: the issued PCCB does not verify for a different
    #    action (e.g. a different repo), so it cannot be reused for one.
    kernel_intent = ActionIntent.from_dict(result.proof["intent"])
    pccb = PCCB.from_dict(result.proof["pccb"])
    grant = client._state.get_grant(client._grant.id)
    widened = Action(
        action_id=kernel_intent.intent_id,
        grant_id=grant.id,
        ts=kernel_intent.issued_at,
        type="github.issue.create",
        target="github",
        params={**PARAMS, "repo": "production-secrets"},
    )
    with pytest.raises(ProofVerificationError):
        verify_pccb_at_edge(kernel_intent, pccb, grant, widened)

    # 5. Revoked grant: the next intent is refused, nothing executes.
    client._state.set_status(client._grant.id, GrantStatus.REVOKED)
    with pytest.raises(ExecutionRefusedError):
        _create(client).execute()
    assert adapter.executions == 1


def test_hero_path_expired_grant_refused(hero):
    client, adapter = hero
    gateway = client._gateway
    expired = Grant(
        agent_id="my-agent",
        issued_at=datetime.now(UTC) - timedelta(hours=2),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        scopes=client._grant.scopes,
        budget=client._grant.budget,
    ).sign()
    client._state.put_grant(expired)
    handle = _create(client)
    response = gateway.execute_intent(handle.intent_id, grant_token=grant_to_token(expired))
    assert response["outcome"] == "DENY"
    assert response["reason"] == "expired"
    assert adapter.executions == 0


def test_hero_path_out_of_scope_refused(hero):
    client, adapter = hero
    with pytest.raises(ExecutionRefusedError):
        client.authorised_execution_intents.create(
            action="github.pr.open",
            target="github",
            parameters={**PARAMS, "head": "x", "base": "main"},
        ).execute()
    assert adapter.executions == 0


def test_replayed_intent_is_refused_before_the_pdp(hero):
    """A replay must not reach the PDP: no ALLOW ledger entry, no reservation."""
    client, adapter = hero
    intent = _create(client)
    intent.execute()
    entries_before = len(client._ledger.list_entries())
    with pytest.raises(ActenonError):
        intent.execute()
    assert len(client._ledger.list_entries()) == entries_before
    assert adapter.executions == 1
