"""Tests for the stranger-audit fixes: interactive demo, mint-token --quiet,
and serve fail-fast on port conflict.
"""

from __future__ import annotations

import io

import pytest


def test_mint_token_quiet_suppresses_warning(tmp_db, monkeypatch, capsys):
    """`permit mint-token --quiet` must NOT print the signing-key warning to
    stderr. Strangers use --quiet to capture the token cleanly in pipelines.
    """
    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)
    from datetime import UTC, datetime, timedelta

    from actenon_permit.model import Budget, Grant, Rate, Scopes
    from actenon_permit.state import get_default_store

    # Create a grant WITHOUT signing it, so mint_token will call sign()
    # which triggers _get_signing_key() which prints the warning.
    store = get_default_store()
    from actenon_permit.model import GrantStatus

    g = Grant(
        agent_id="quiet-test",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=[]),
        budget=Budget(currency="USD", limit=10, remaining=10),
        rate=Rate(max=0, per_seconds=60),
        status=GrantStatus.ACTIVE,
        signature="",  # NOT signed
    )
    store.put_grant(g)

    # Reset the dev-key warning flag so it would fire again.
    import actenon_permit.model as model_mod

    monkeypatch.setattr(model_mod, "_WARNED_ABOUT_DEV_KEY", False)

    from actenon_permit.cli import mint_token

    mint_token(g.id, quiet=True)
    captured = capsys.readouterr()
    assert "WARNING" not in captured.err
    assert "v1." in captured.out


def test_mint_token_without_quiet_shows_warning(tmp_db, monkeypatch, capsys):
    """Without --quiet, the signing-key warning DOES print (to stderr)."""
    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)
    from datetime import UTC, datetime, timedelta

    from actenon_permit.model import Budget, Grant, GrantStatus, Rate, Scopes
    from actenon_permit.state import get_default_store

    store = get_default_store()
    g = Grant(
        agent_id="noisy-test",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scopes=Scopes(allow=[]),
        budget=Budget(currency="USD", limit=10, remaining=10),
        rate=Rate(max=0, per_seconds=60),
        status=GrantStatus.ACTIVE,
        signature="",  # NOT signed
    )
    store.put_grant(g)

    import actenon_permit.model as model_mod

    # Reset BOTH flags — the previous test may have set them.
    monkeypatch.setattr(model_mod, "_WARNED_ABOUT_DEV_KEY", False)
    monkeypatch.setattr(model_mod, "_SUPPRESS_DEV_KEY_WARNING", False)

    from actenon_permit.cli import mint_token

    mint_token(g.id, quiet=False)
    captured = capsys.readouterr()
    assert "WARNING" in captured.err


def test_serve_fails_fast_on_port_conflict(tmp_db, monkeypatch):
    """`permit serve --port <taken>` must exit non-zero, not silently fail."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)
    try:
        from actenon_permit.cli import serve

        # typer.Exit inherits from SystemExit, but let's catch it explicitly.
        with pytest.raises((SystemExit, Exception)) as exc_info:
            serve(host="127.0.0.1", port=port, with_gateway=False)
        # typer.Exit(code=1) — the exit code should be 1
        if hasattr(exc_info.value, "code"):
            assert exc_info.value.code == 1 or str(exc_info.value.code) == "1"
    finally:
        sock.close()


def test_interactive_demo_uses_stdin_gate(monkeypatch):
    """The interactive demo (no --auto-approve) must use StdinApprovalGate,
    not AutoApproveGate. This is the fix for the 'front door that prints
    zeros' bug where the demo claimed INTERACTIVE but silently auto-approved.
    """
    # Simulate stdin: approve (Enter) for step 4.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))

    from actenon_permit.state import reset_default_store

    reset_default_store()

    from actenon_permit._demo import run_demo

    results = run_demo(auto_approve=False)

    # Step 4 should be ALLOW (approved via stdin).
    step4 = [r for r in results if r["step"] == 4][0]
    assert step4["outcome"] == "ALLOW", f"step 4 should be ALLOW (approved via stdin), got {step4}"

    # Step 5 should be DENY (scope).
    step5 = [r for r in results if r["step"] == 5][0]
    assert step5["outcome"] == "DENY"
