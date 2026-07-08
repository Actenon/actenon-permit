"""Actenon-Permit CLI.

Commands:
    permit issue <policy.yaml>          compile a policy file to a signed grant
    permit revoke <agent_id>            kill switch — revoke all grants for an agent
    permit watch                        live TUI: pending approvals, a/d to approve/deny
    permit ledger [--verify]            print the action log (and verify the chain)
    permit demo [--auto-approve]        run the built-in 7-step scenario (v0 in-process)
    permit demo --mode gateway          run the demo through the v1 out-of-process gateway
    permit serve [--with-gateway]       run the control plane (+ v1 gateway if requested)
    permit mcp-serve                    run the v1 MCP stdio server (JSON-RPC over stdin/stdout)
    permit attenuate <grant_id> ...     derive a strictly-weaker sub-grant (UCAN-style)
    permit mint-token <grant_id>        mint a v1 bearer token for a grant
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from datetime import UTC
from pathlib import Path
from typing import Any

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


def _build_demo_gateway():
    """Build a Gateway wired to the demo's mock providers.

    Used by `permit serve --with-gateway` and `permit mcp-serve` so the demo
    tools (refund / charge / send_email) work out of the box. Production
    deployments should build their own Gateway with their own ToolRegistry.
    """
    os.environ.setdefault("MOCK_STRIPE_KEY", "sk_mock_123")

    from ._mock_providers import mock_send_email, mock_stripe_charge, mock_stripe_refund
    from .broker import Broker
    from .enforce import AutoApproveGate
    from .gateway import Gateway, ToolRegistry
    from .pdp import PDP
    from .state import get_default_store

    store = get_default_store()
    ledger = Ledger(store)
    pdp = PDP(store, ledger)
    broker = Broker(pdp)
    tools = ToolRegistry()
    tools.register(
        "refund",
        action_type="payment.refund",
        target="stripe",
        description="Issue a refund via the (mock) Stripe provider.",
        input_schema={
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Amount to refund, in major currency units."},
                "reason": {"type": "string", "default": "customer_request"},
            },
            "required": ["amount"],
        },
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, reason="customer_request": mock_stripe_refund(secret, amount, reason),
    )
    tools.register(
        "charge",
        action_type="payment.charge",
        target="stripe",
        description="Charge a card via the (mock) Stripe provider.",
        input_schema={
            "type": "object",
            "properties": {
                "amount": {"type": "number"},
                "description": {"type": "string", "default": ""},
            },
            "required": ["amount"],
        },
        cost_from="amount",
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, amount, description="": mock_stripe_charge(secret, amount, description),
    )
    tools.register(
        "send_email",
        action_type="email.send",
        target="smtp",
        description="Send an email via the (mock) SMTP provider.",
        input_schema={
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string", "default": ""},
            },
            "required": ["to", "subject"],
        },
        credential_name="MOCK_STRIPE_KEY",
        real_call=lambda secret, to, subject, body="": mock_send_email(secret, to, subject, body),
    )
    return Gateway(
        state=store, ledger=ledger, pdp=pdp, broker=broker, tools=tools,
        approval_gate=AutoApproveGate(),
    )


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
def watch(
    url: str = typer.Option(
        "http://127.0.0.1:7780",
        "--url",
        help="Control plane URL to poll for pending approvals.",
    ),
    once: bool = typer.Option(
        False,
        "--once",
        help="Print pending approvals once and exit (non-interactive, for scripts/CI).",
    ),
) -> None:
    """Live TUI for pending approvals. Polls the control plane's /approvals
    endpoint. Press a=approve, d=deny on the most recent pending request,
    q=quit.

    This command talks to a running `permit serve` (or `permit serve
    --with-gateway`) instance over HTTP. It does NOT hold any in-memory
    state — every action is a real API call to the control plane.
    """
    import json as _json
    import urllib.error
    import urllib.request

    def _get(path: str):
        req = urllib.request.Request(f"{url}{path}", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return _json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            typer.echo(f"cannot reach control plane at {url}: {e}", err=True)
            raise typer.Exit(code=1) from e

    def _post(path: str):
        req = urllib.request.Request(f"{url}{path}", method="POST", data=b"")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except urllib.error.HTTPError:
            return False

    # Non-interactive mode: print and exit.
    if once:
        pending = _get("/approvals")
        if not pending:
            typer.echo("(no pending approvals)")
            return
        for p in pending:
            typer.echo(
                f"{p['action_id']}  grant={p['grant_id']}  "
                f"type={p['action_type']}  reason={p['reason']}"
            )
        return

    # Interactive mode — needs a TTY.
    try:
        import termios
        import tty

        old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
    except (ImportError, AttributeError):
        typer.echo(
            "watch: no TTY available. Use `permit watch --once` to print pending "
            "approvals non-interactively, or approve directly via the API:\n"
            "  curl -X POST http://127.0.0.1:7780/approvals/<action_id>/approve",
            err=True,
        )
        raise typer.Exit(code=1) from None

    typer.echo(f"Actenon-Permit watch — polling {url}/approvals every 0.5s")
    typer.echo("press a=approve, d=deny on the most recent pending, q=quit")
    typer.echo()
    last_seen: set[str] = set()
    current: dict[str, Any] | None = None
    try:
        while True:
            try:
                pending = _get("/approvals")
            except typer.Exit:
                raise
            except Exception:
                pending = []
            # Print newly-seen pending requests.
            for p in pending:
                if p["action_id"] not in last_seen:
                    last_seen.add(p["action_id"])
                    current = p
                    typer.echo(
                        f"\n[pending] {p['action_id']}  grant={p['grant_id']}  "
                        f"type={p['action_type']}  reason={p['reason']}"
                    )
                    typer.echo("  press a=approve, d=deny")
            # Non-blocking read of one char if available.
            ch = sys.stdin.read(1)
            if ch == "q":
                typer.echo("\nbye.")
                break
            if ch in ("a", "d") and current is not None:
                action_id = current["action_id"]
                if ch == "a":
                    ok = _post(f"/approvals/{action_id}/approve")
                    typer.echo(f"\n  approved {action_id}: {'ok' if ok else 'FAILED'}")
                else:
                    ok = _post(f"/approvals/{action_id}/deny")
                    typer.echo(f"\n  denied {action_id}: {'ok' if ok else 'FAILED'}")
                current = None
            time.sleep(0.5)
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
    with_gateway: bool = typer.Option(
        False,
        "--with-gateway",
        help="Also mount the v1 out-of-process PEP proxy (/proxy/*) on the same port.",
    ),
) -> None:
    """Run the localhost control plane (FastAPI + uvicorn).

    With --with-gateway, also mounts the v1 HTTP proxy endpoints so a single
    `permit serve --with-gateway` can host both the control plane and the
    gateway. Tools are registered from the demo's mock providers (so the
    demo works out of the box); production deployments should register their
    own tools via a custom entrypoint.
    """
    import uvicorn

    from .control import create_app

    gateway = None
    if with_gateway:
        gateway = _build_demo_gateway()
    application = create_app(gateway=gateway)
    uvicorn.run(application, host=host, port=port, log_level="info")


@app.command()
def mcp_serve() -> None:
    """Run the v1 MCP stdio server (JSON-RPC 2.0 over stdin/stdout).

    The agent host (Claude Desktop, Cursor, etc.) connects to this process
    via stdio and calls tools/list + tools/call. The grant token is passed
    in params._meta.actenon_grant on each tools/call.
    """
    from .gateway import mcp_serve as _mcp_serve

    gateway = _build_demo_gateway()
    _mcp_serve(gateway)


@app.command()
def attenuate(
    grant_id: str = typer.Argument(..., help="Parent grant id to attenuate."),
    agent_id: str | None = typer.Option(None, "--agent-id", help="New agent id for the child grant."),
    budget_limit: float | None = typer.Option(None, "--budget-limit", help="Smaller budget cap."),
    scopes_allow: str | None = typer.Option(
        None, "--scopes-allow", help="Comma-separated subset of parent's allow scopes."
    ),
    scopes_deny: str | None = typer.Option(
        None, "--scopes-deny", help="Comma-separated additional deny scopes."
    ),
    expires_at: str | None = typer.Option(None, "--expires-at", help="Earlier expiry (ISO-8601)."),
) -> None:
    """Derive a strictly-weaker sub-grant from an existing grant (UCAN-style)."""
    from .model import GrantStatus
    from .policy import compile_policy  # noqa: F401 — kept for future YAML attenuate
    from .state import get_default_store

    store = get_default_store()
    parent = store.get_grant(grant_id)
    if parent is None:
        typer.echo(f"parent grant {grant_id} not found", err=True)
        raise typer.Exit(code=1)
    if parent.status != GrantStatus.ACTIVE:
        typer.echo(f"parent grant status is {parent.status.value}, must be active", err=True)
        raise typer.Exit(code=1)

    from datetime import datetime

    kwargs: dict[str, Any] = {}
    if agent_id is not None:
        kwargs["agent_id"] = agent_id
    if budget_limit is not None:
        kwargs["budget_limit"] = budget_limit
    if scopes_allow is not None:
        kwargs["scopes_allow"] = [s.strip() for s in scopes_allow.split(",") if s.strip()]
    if scopes_deny is not None:
        kwargs["scopes_deny"] = [s.strip() for s in scopes_deny.split(",") if s.strip()]
    if expires_at is not None:
        dt = datetime.fromisoformat(expires_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        kwargs["expires_at"] = dt

    try:
        child = parent.attenuate(**kwargs)
    except ValueError as e:
        typer.echo(f"attenuation rejected: {e}", err=True)
        raise typer.Exit(code=1) from e
    store.put_grant(child)
    typer.echo(json.dumps(json.loads(child.model_dump_json()), indent=2))


@app.command()
def mint_token(
    grant_id: str = typer.Argument(..., help="Grant id to mint a bearer token for."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print only the token (no warnings)."),
) -> None:
    """Mint a v1 bearer token for a grant. The token is presented to the
    gateway as the X-Actenon-Grant header."""
    from .state import get_default_store
    from .token import grant_to_token

    store = get_default_store()
    g = store.get_grant(grant_id)
    if g is None:
        typer.echo(f"grant {grant_id} not found", err=True)
        raise typer.Exit(code=1)
    if not g.signature:
        g.sign()
        store.put_grant(g)
    typer.echo(grant_to_token(g))


@app.command()
def demo(
    auto_approve: bool = typer.Option(
        False, "--auto-approve", help="Auto-approve step 4 so the demo runs non-interactively."
    ),
    mode: str = typer.Option(
        "in-process",
        "--mode",
        help="Demo mode: 'in-process' (v0) or 'gateway' (v1, out-of-process PEP).",
    ),
) -> None:
    """Run the built-in 7-step scripted demo. No LLM, no network, no real money."""
    if mode == "in-process":
        from ._demo import run_demo

        _reset_db_for_demo()
        run_demo(auto_approve=auto_approve)
    elif mode == "gateway":
        from ._demo_gateway import run_gateway_demo

        _reset_db_for_demo()
        run_gateway_demo(auto_approve=auto_approve)
    else:
        typer.echo(f"unknown mode: {mode} (use 'in-process' or 'gateway')", err=True)
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
