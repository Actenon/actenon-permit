"""Actenon-Permit CLI.

Commands:
    permit issue <policy.yaml>          compile a policy file to a signed grant
    permit revoke <agent_id>            kill switch — revoke all grants for an agent
    permit watch                        live TUI: pending approvals, a/d to approve/deny
    permit ledger [--verify]            print the action log (and verify the chain)
    permit demo [--auto-approve]        run the built-in 7-step scenario
    permit serve [--host H --port P]    run the localhost control plane
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from pathlib import Path

import typer

from . import __version__
from .ledger import Ledger
from .model import Grant, GrantStatus
from .policy import compile_policy, load_policy
from .state import get_default_store

app = typer.Typer(
    name="permit",
    help="Actenon-Permit: an authority broker for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_grant(g: Grant) -> None:
    typer.echo(json.dumps(json.loads(g.model_dump_json()), indent=2))


def _reset_db_for_demo() -> None:
    """Wipe the local DB so the demo runs from a clean state every time."""
    db_path = os.environ.get("ACTENON_DB_PATH", "actenon.db")
    for suffix in ("", "-journal", "-wal", "-shm"):
        p = Path(db_path + suffix)
        if p.exists():
            with contextlib.suppress(OSError):
                p.unlink()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def issue(
    policy: Path = typer.Argument(..., help="Path to a YAML policy file."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print only the grant id."),
) -> None:
    """Compile a policy file to a signed grant and store it."""
    policy_dict = load_policy(policy)
    grant = compile_policy(policy_dict)
    store = get_default_store()
    store.put_grant(grant)
    if quiet:
        typer.echo(grant.id)
    else:
        _print_grant(grant)


@app.command()
def revoke(
    agent_id: str = typer.Argument(..., help="Agent id whose grants to revoke."),
    grant_id: str | None = typer.Option(
        None, "--grant-id", help="Revoke a specific grant id instead of all grants for the agent."
    ),
) -> None:
    """Kill switch — revoke a grant (or all grants for an agent)."""
    store = get_default_store()
    if grant_id:
        g = store.get_grant(grant_id)
        if g is None:
            typer.echo(f"grant {grant_id} not found", err=True)
            raise typer.Exit(code=1)
        store.set_status(grant_id, GrantStatus.REVOKED)
        typer.echo(f"revoked grant {grant_id} (agent={g.agent_id})")
        return
    grants = store.list_grants(agent_id=agent_id)
    if not grants:
        typer.echo(f"no grants found for agent {agent_id}", err=True)
        raise typer.Exit(code=1)
    for g in grants:
        store.set_status(g.id, GrantStatus.REVOKED)
        typer.echo(f"revoked grant {g.id} (agent={g.agent_id})")


@app.command()
def ledger(
    verify: bool = typer.Option(False, "--verify", help="Verify the hash chain and exit."),
    grant_id: str | None = typer.Option(None, "--grant-id", help="Filter by grant id."),
    limit: int = typer.Option(1000, "--limit", help="Max entries to print."),
) -> None:
    """Print the action log (and optionally verify the chain)."""
    store = get_default_store()
    led = Ledger(store)
    if verify:
        ok = led.verify()
        typer.echo(f"chain intact: {ok}")
        raise typer.Exit(code=0 if ok else 1)
    entries = led.list_entries(grant_id=grant_id, limit=limit)
    if not entries:
        typer.echo("(ledger empty)")
        return
    for e in entries:
        typer.echo(
            f"#{e['seq']:>4}  {e['ts']}  {e['outcome']:<18}  "
            f"{e['action_type']:<22}  reason={e['reason']}  "
            f"hash={e['hash'][:12]}..."
        )


@app.command()
def watch() -> None:
    """Live TUI for pending approvals. Press a/d to approve/deny, q to quit."""
    # Import here so the demo path doesn't depend on control.py being importable.
    from .control import ApprovalStore

    approvals = ApprovalStore()

    try:
        import termios
        import tty

        old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
    except (ImportError, AttributeError):
        # Not a TTY (e.g. CI). Fall back to polling prints.
        old_settings = None
    try:
        typer.echo("Actenon-Permit watch — press a=approve, d=deny, q=quit")
        typer.echo("(when no terminal is attached, this just polls and prints)")
        last_seen: set[str] = set()
        while True:
            pending = approvals.list_pending()
            new = [p for p in pending if p["action_id"] not in last_seen]
            for p in new:
                last_seen.add(p["action_id"])
                typer.echo(
                    f"\n[pending] {p['action_id']}  agent-grant={p['grant_id']}  "
                    f"type={p['action_type']}  reason={p['reason']}"
                )
                typer.echo("  press a=approve, d=deny")
            time.sleep(0.2)
    except KeyboardInterrupt:
        typer.echo("\nbye.")
    finally:
        if old_settings is not None:
            with contextlib.suppress(Exception):
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (localhost only in v0)."),
    port: int = typer.Option(7780, "--port", help="Bind port."),
) -> None:
    """Run the localhost control plane (FastAPI + uvicorn)."""
    import uvicorn

    from .control import create_app

    application = create_app()
    uvicorn.run(application, host=host, port=port, log_level="info")


@app.command()
def demo(
    auto_approve: bool = typer.Option(
        False, "--auto-approve", help="Auto-approve step 4 so the demo runs non-interactively."
    ),
) -> None:
    """Run the built-in 7-step scripted demo. No LLM, no network, no real money."""
    # The demo logic lives in the package so it works after `pip install`.
    from ._demo import run_demo

    _reset_db_for_demo()
    run_demo(auto_approve=auto_approve)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
