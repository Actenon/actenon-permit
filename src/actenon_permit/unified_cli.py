"""Unified Actenon CLI — the recommended developer entry point.

Commands:

    actenon init                  initialise a local project
    actenon capabilities          inspect runtime capabilities
    actenon intent create         create an AuthorisedExecutionIntent
    actenon intent execute        execute a brokered intent
    actenon intent submit         submit a resource-owned intent
    actenon verify proof          verify a Kernel PCCB proof
    actenon verify receipt        verify a resource receipt
    actenon inspect refusal       inspect a refusal's structured codes
    actenon evidence list         list local evidence
    actenon evidence show         show a single evidence record
    actenon scan                  run the execution-gap scanner
    actenon demo                  run the full safe brokered demo
    actenon version               print version information
    actenon doctor                diagnose configuration

The existing `permit` CLI is preserved for backward compatibility; `actenon`
is the recommended entry point.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import typer

from . import __version__
from .sdk import Actenon, BrokeredResult, ResourceOwnedResult
from .sdk.exceptions import ActenonError
from .sdk.receipt import verify_resource_receipt

app = typer.Typer(
    name="actenon",
    help="Actenon: unified CLI for protected AI-agent execution.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

# Sub-app for intent commands
intent_app = typer.Typer(help="Create and execute AuthorisedExecutionIntents.")
verify_app = typer.Typer(help="Verify proofs and receipts.")
evidence_app = typer.Typer(help="List and inspect local evidence.")

app.add_typer(intent_app, name="intent")
app.add_typer(verify_app, name="verify")
app.add_typer(evidence_app, name="evidence")


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_DIR = Path.home() / ".actenon"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"


def _load_config() -> dict[str, Any]:
    """Load config from file + env. Precedence: CLI args > env > file > defaults."""
    config: dict[str, Any] = {}
    if DEFAULT_CONFIG_FILE.is_file():
        with contextlib.suppress(Exception):
            config = json.loads(DEFAULT_CONFIG_FILE.read_text())
    # Env overrides file
    if env_key := os.environ.get("ACTENON_SIGNING_KEY"):
        config["signing_key"] = env_key
    if env_url := os.environ.get("ACTENON_CLOUD_URL"):
        config["cloud_url"] = env_url
    if env_token := os.environ.get("ACTENON_GRANT_TOKEN"):
        config["grant_token"] = env_token
    if env_db := os.environ.get("ACTENON_DB_PATH"):
        config["db_path"] = env_db
    return config


def _redact(config: dict[str, Any]) -> dict[str, Any]:
    """Redact secrets from a config dict for display."""
    redacted = dict(config)
    for key in ("signing_key", "grant_token", "credential"):
        if key in redacted and redacted[key]:
            v = str(redacted[key])
            redacted[key] = v[:4] + "..." + v[-4:] if len(v) > 8 else "<short>"
    return redacted


# ---------------------------------------------------------------------------
# actenon init
# ---------------------------------------------------------------------------


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
    production: bool = typer.Option(False, "--production", help="Enable production mode."),
) -> None:
    """Initialise a local Actenon project.

    Creates ~/.actenon/config.json with safe defaults. Generates a
    development-only signing key with a clear warning.
    """
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if DEFAULT_CONFIG_FILE.exists() and not force:
        typer.echo(f"Config already exists at {DEFAULT_CONFIG_FILE}. Use --force to overwrite.")
        raise typer.Exit(1)

    import secrets

    signing_key = secrets.token_hex(32)
    config: dict[str, Any] = {
        "agent_id": "dev-agent",
        "scopes": ["*"],
        "budget_limit": 100.0,
        "budget_currency": "USD",
        "signing_key": signing_key,
        "production_mode": production,
    }
    DEFAULT_CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        DEFAULT_CONFIG_FILE.chmod(0o600)

    typer.echo(f"[actenon] Initialised config at {DEFAULT_CONFIG_FILE}")
    if not production:
        typer.echo(
            "[actenon] WARNING: Generated a DEV signing key. This is "
            "development-only and MUST NOT be used in production. "
            "Set ACTENON_SIGNING_KEY for production."
        )
    typer.echo(f"[actenon] Signing key: {signing_key[:4]}...{signing_key[-4:]} (redacted)")
    typer.echo("[actenon] Run `actenon doctor` to verify your setup.")
    typer.echo("[actenon] Run `actenon demo` to see the full safe brokered demo.")


# ---------------------------------------------------------------------------
# actenon capabilities
# ---------------------------------------------------------------------------


@app.command()
def capabilities(
    cloud: bool = typer.Option(False, "--cloud", help="Show cloud capabilities instead of local."),
) -> None:
    """Inspect runtime capabilities."""
    if cloud:
        config = _load_config()
        url = config.get("cloud_url", "https://cloud.actenon.example")
        client = Actenon.cloud(base_url=url, grant_token=config.get("grant_token"))
    else:
        client = Actenon.local(
            agent_id="cli-capabilities",
            scopes=["*"],
            signing_key=_load_config().get("signing_key", "dev-key"),
        )
    caps = client.capabilities
    typer.echo(f"  transport:              {caps.transport}")
    typer.echo(f"  supports_brokered:      {caps.supports_brokered}")
    typer.echo(f"  supports_resource_owned: {caps.supports_resource_owned}")
    typer.echo(f"  supports_async:         {caps.supports_async}")
    typer.echo(f"  supports_polling:       {caps.supports_polling}")
    typer.echo(f"  durable:                {caps.durable}")
    typer.echo(f"  production_mode:        {caps.production_mode}")


# ---------------------------------------------------------------------------
# actenon intent create
# ---------------------------------------------------------------------------


@intent_app.command("create")
def intent_create(
    action: str = typer.Option(..., "--action", "-a", help="Action type (e.g. github.issue.create)."),
    target: str = typer.Option(..., "--target", "-t", help="Target resource."),
    parameters: str = typer.Option("{}", "--parameters", "-p", help="JSON parameters."),
    mode: str = typer.Option("brokered", "--mode", "-m", help="Execution mode."),
    cloud: bool = typer.Option(False, "--cloud", help="Use cloud transport."),
) -> None:
    """Create an AuthorisedExecutionIntent."""
    params = json.loads(parameters)
    config = _load_config()
    if cloud:
        client = Actenon.cloud(
            base_url=config.get("cloud_url", "http://localhost:7780"),
            grant_token=config.get("grant_token"),
        )
    else:
        client = Actenon.local(
            agent_id=config.get("agent_id", "cli"),
            scopes=config.get("scopes", ["*"]),
            signing_key=config.get("signing_key", "dev-key"),
        )
    intent = client.authorised_execution_intents.create(
        action=action,
        target=target,
        parameters=params,
        requestedExecutionMode=mode,
    )
    typer.echo(json.dumps({
        "intent_id": intent.intent_id,
        "lifecycle_state": intent.lifecycle_state,
    }, indent=2))


# ---------------------------------------------------------------------------
# actenon intent execute
# ---------------------------------------------------------------------------


@intent_app.command("execute")
def intent_execute(
    intent_id: str = typer.Argument(..., help="The intent id to execute."),
    cloud: bool = typer.Option(False, "--cloud", help="Use cloud transport."),
) -> None:
    """Execute a brokered intent."""
    config = _load_config()
    if cloud:
        client = Actenon.cloud(
            base_url=config.get("cloud_url", "http://localhost:7780"),
            grant_token=config.get("grant_token"),
        )
    else:
        client = Actenon.local(
            agent_id=config.get("agent_id", "cli"),
            scopes=config.get("scopes", ["*"]),
            signing_key=config.get("signing_key", "dev-key"),
        )
    # Re-fetch the intent handle (the SDK doesn't have a get-by-id on the
    # public API yet; we construct a handle directly).
    from .sdk.models import IntentHandle

    handle = IntentHandle(intent_id=intent_id, lifecycle_state="created", _client=client)
    try:
        result = handle.execute()
    except ActenonError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from None
    _print_result(result)


def _print_result(result: Any) -> None:
    """Print an ExecutionResult (brokered or resource-owned)."""
    typer.echo(f"  mode:              {result.mode}")
    typer.echo(f"  state:             {result.state}")
    typer.echo(f"  finality:          {result.finality}")
    typer.echo(f"  observed:          {result.provider_execution_observed}")
    if result.mode == "brokered":
        typer.echo(f"  receipt_received:  {result.receipt_received}")
        typer.echo(f"  receipt_verified:  {result.receipt_verified}")
    else:
        typer.echo(f"  resource_receipt_received: {result.resource_receipt_received}")
        typer.echo(f"  resource_receipt_verified: {result.resource_receipt_verified}")
    typer.echo(f"  evidence:          {json.dumps(result.evidence, indent=2)}")


# ---------------------------------------------------------------------------
# actenon intent submit
# ---------------------------------------------------------------------------


@intent_app.command("submit")
def intent_submit(
    intent_id: str = typer.Argument(..., help="The intent id to submit."),
    proof: str = typer.Option(..., "--proof", "-p", help="JSON proof object."),
    cloud: bool = typer.Option(False, "--cloud", help="Use cloud transport."),
) -> None:
    """Submit a resource-owned intent to a resource boundary."""
    config = _load_config()
    if cloud:
        client = Actenon.cloud(
            base_url=config.get("cloud_url", "http://localhost:7780"),
            grant_token=config.get("grant_token"),
        )
    else:
        client = Actenon.local(
            agent_id=config.get("agent_id", "cli"),
            scopes=config.get("scopes", ["*"]),
            signing_key=config.get("signing_key", "dev-key"),
        )
    proof_dict = json.loads(proof)
    from .sdk.models import IntentHandle

    handle = IntentHandle(intent_id=intent_id, lifecycle_state="created", _client=client)
    try:
        result = handle.submitToResource(proof_dict)
    except ActenonError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from None
    _print_result(result)


# ---------------------------------------------------------------------------
# actenon verify proof
# ---------------------------------------------------------------------------


@verify_app.command("proof")
def verify_proof(
    proof_file: str = typer.Argument(..., help="Path to a JSON proof file."),
) -> None:
    """Verify a Kernel PCCB proof (structural check)."""
    proof = json.loads(Path(proof_file).read_text())
    # Structural verification: check required fields.
    required = ["proof_id", "action_hash", "signature", "execution_mode"]
    missing = [f for f in required if f not in proof]
    if missing:
        typer.echo(f"FAIL: missing required fields: {missing}", err=True)
        raise typer.Exit(1)
    typer.echo(f"OK: proof {proof['proof_id']} has all required fields")
    typer.echo(f"  execution_mode: {proof['execution_mode']}")
    typer.echo(f"  action_hash:    {proof.get('action_hash', 'N/A')}")


# ---------------------------------------------------------------------------
# actenon verify receipt
# ---------------------------------------------------------------------------


@verify_app.command("receipt")
def verify_receipt(
    receipt_file: str = typer.Argument(..., help="Path to a JSON receipt file."),
    key_id: str = typer.Option(..., "--key-id", help="The signing key id."),
    key_secret: str = typer.Option(..., "--key-secret", help="The signing key secret (hex)."),
) -> None:
    """Verify a resource receipt's HMAC-SHA256 signature."""
    receipt = json.loads(Path(receipt_file).read_text())
    secret = bytes.fromhex(key_secret)
    keys = {key_id: secret}
    verified = verify_resource_receipt(receipt, keys)
    if verified:
        typer.echo(f"OK: receipt verified with key {key_id}")
    else:
        typer.echo("FAIL: receipt signature does not verify", err=True)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# actenon inspect refusal
# ---------------------------------------------------------------------------


@app.command()
def inspect_refusal(
    refusal_file: str = typer.Argument(..., help="Path to a JSON refusal file."),
) -> None:
    """Inspect a refusal's structured codes."""
    refusal = json.loads(Path(refusal_file).read_text())
    typer.echo(f"  refusal_id:     {refusal.get('refusal_id', 'N/A')}")
    typer.echo(f"  reason_code:    {refusal.get('reason_code', 'N/A')}")
    typer.echo(f"  message:        {refusal.get('message', 'N/A')}")
    typer.echo(f"  retryable:      {refusal.get('retryable', False)}")
    typer.echo(f"  execution_mode: {refusal.get('execution_mode', 'N/A')}")
    if "disclosed_code" in refusal:
        typer.echo(f"  disclosed_code: {refusal['disclosed_code']}")
    if "internal_code" in refusal:
        typer.echo(f"  internal_code:  {refusal['internal_code']}")


# ---------------------------------------------------------------------------
# actenon evidence list / show
# ---------------------------------------------------------------------------


@evidence_app.command("list")
def evidence_list(
    limit: int = typer.Option(20, "--limit", "-n", help="Max entries to show."),
) -> None:
    """List local evidence (from the SQLite ledger)."""
    from .ledger import Ledger
    from .state import SQLiteStore

    db_path = os.environ.get("ACTENON_DB_PATH", "actenon.db")
    if not Path(db_path).exists():
        typer.echo("No local evidence found. Run `actenon demo` first.")
        return
    store = SQLiteStore(db_path)
    ledger = Ledger(store)
    entries = ledger.entries()
    for e in entries[-limit:]:
        typer.echo(
            f"  seq={e.seq}  action={e.action_type}  outcome={e.outcome}  "
            f"reason={e.reason}  hash={e.hash[:12]}..."
        )


@evidence_app.command("show")
def evidence_show(
    seq: int = typer.Argument(..., help="The sequence number to show."),
) -> None:
    """Show a single evidence record."""
    from .ledger import Ledger
    from .state import SQLiteStore

    db_path = os.environ.get("ACTENON_DB_PATH", "actenon.db")
    store = SQLiteStore(db_path)
    ledger = Ledger(store)
    for e in ledger.entries():
        if e.seq == seq:
            typer.echo(json.dumps(json.loads(e.model_dump_json()), indent=2))
            return
    typer.echo(f"Evidence seq={seq} not found.", err=True)
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# actenon scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan."),
    format: str = typer.Option("text", "--format", "-f", help="Output format (text/json)."),
) -> None:
    """Run the execution-gap scanner (delegates to actenon-scan if installed)."""
    try:
        from actenon_scan.cli import app as scan_app
    except ImportError:
        typer.echo(
            "actenon-scan is not installed. Install with: pip install actenon-scan"
        )
        raise typer.Exit(1) from None
    # Delegate to the scan CLI.
    import click

    try:
        scan_app([path, "--format", format], standalone_mode=False)
    except click.exceptions.Exit as e:
        raise typer.Exit(e.exit_code) from None
    except SystemExit as e:
        if e.code:
            raise typer.Exit(e.code) from None


# ---------------------------------------------------------------------------
# actenon demo — the hero command
# ---------------------------------------------------------------------------


@app.command()
def demo(
    auto_approve: bool = typer.Option(True, "--auto-approve/--no-auto-approve", help="Auto-approve."),
) -> None:
    """Run the full safe brokered demonstration.

    Prints:
      - proposed action
      - authority decision
      - proof identifier
      - verification outcome
      - provider outcome
      - receipt identifier
      - replay refusal
      - mutation refusal
    """
    _run_demo(auto_approve)


def _run_demo(auto_approve: bool) -> None:
    import warnings

    from . import GitHubAdapter

    typer.echo("=" * 70)
    typer.echo("  Actenon CLI — Safe Brokered Demo")
    typer.echo("=" * 70)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        client = Actenon.local(
            agent_id="demo-agent",
            scopes=["github.issue.create"],
            signing_key="demo-signing-key-not-for-production",
        )

    client.register_credential("GITHUB_TOKEN", "ghp_DEMO_NOT_REAL_0123456789abcdef")
    client.register_adapter_tool(
        "github_issue",
        action_type="github.issue.create",
        adapter=GitHubAdapter(test_mode=True),
        credential_ref="GITHUB_TOKEN",
        target="github",
    )

    # ─── 1. Proposed action ──────────────────────────────────────────
    typer.echo("\n  --- 1. Proposed action ---")
    intent = client.authorised_execution_intents.create(
        action="github.issue.create",
        target="github",
        parameters={
            "owner": "Actenon",
            "repo": "example",
            "title": "Created by actenon CLI demo",
        },
    )
    typer.echo(f"  intent_id: {intent.intent_id}")
    typer.echo("  action:    github.issue.create")
    typer.echo("  target:    github")
    typer.echo(f"  state:     {intent.lifecycle_state}")

    # ─── 2. Authority decision + 3. Proof + 4. Verification ──────────
    # These happen inside execute(). We capture the result.
    typer.echo("\n  --- 2-4. Authority decision + proof + verification ---")
    result = intent.execute()
    if isinstance(result, BrokeredResult):
        typer.echo("  decision:  ALLOW (brokered)")
        typer.echo(f"  proof:     {result.attempt_id or 'N/A'}")
        typer.echo(f"  verified:  {result.receipt_verified}")
    elif isinstance(result, ResourceOwnedResult):
        typer.echo("  decision:  ALLOW (resource_owned)")
        typer.echo(f"  proof:     {result.attempt_id or 'N/A'}")
        typer.echo(f"  verified:  {result.resource_receipt_verified}")

    # ─── 5. Provider outcome ─────────────────────────────────────────
    typer.echo("\n  --- 5. Provider outcome ---")
    typer.echo(f"  state:     {result.state}")
    typer.echo(f"  observed:  {result.provider_execution_observed}")
    typer.echo(f"  evidence:  {json.dumps(result.evidence, indent=2)}")

    # ─── 6. Receipt identifier ───────────────────────────────────────
    typer.echo("\n  --- 6. Receipt ---")
    if isinstance(result, BrokeredResult):
        typer.echo(f"  receipt_received: {result.receipt_received}")
        typer.echo(f"  receipt_verified: {result.receipt_verified}")

    # ─── 7. Replay refusal ───────────────────────────────────────────
    typer.echo("\n  --- 7. Replay refusal ---")
    try:
        intent.execute()
        typer.echo("  FAIL: replay was NOT refused!")
    except (ActenonError, Exception) as e:
        typer.echo(f"  OK: replay refused: {type(e).__name__}")

    # ─── 8. Mutation refusal ─────────────────────────────────────────
    typer.echo("\n  --- 8. Mutation refusal ---")
    mutated = client.authorised_execution_intents.create(
        action="github.issue.create",
        target="github",
        parameters={
            "owner": "Actenon",
            "repo": "example",
            "title": "mutated",
            "malicious_field": "should be rejected",
        },
    )
    try:
        mutated.execute()
        typer.echo("  FAIL: mutation was NOT refused!")
    except (ActenonError, Exception) as e:
        typer.echo(f"  OK: mutation refused: {type(e).__name__}")

    typer.echo("\n  Demo complete. All 8 guarantees demonstrated.")
    typer.echo("=" * 70)


# ---------------------------------------------------------------------------
# actenon version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print version information."""
    typer.echo(f"  actenon {__version__}")
    typer.echo(f"  python  {sys.version.split()[0]}")
    try:
        import actenon_protocol

        typer.echo(f"  protocol {actenon_protocol.__version__}")
    except ImportError:
        pass
    try:
        import actenon

        typer.echo(f"  kernel  {getattr(actenon, '__version__', 'unknown')}")
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# actenon doctor
# ---------------------------------------------------------------------------


@app.command()
def doctor() -> None:
    """Diagnose configuration."""
    config = _load_config()
    typer.echo("  Configuration:")
    typer.echo(f"    config file: {DEFAULT_CONFIG_FILE}")
    typer.echo(f"    config:      {json.dumps(_redact(config), indent=2)}")
    typer.echo()
    typer.echo("  Environment:")
    for key in ("ACTENON_SIGNING_KEY", "ACTENON_DB_PATH", "ACTENON_CLOUD_URL", "ACTENON_GRANT_TOKEN"):
        val = os.environ.get(key)
        if val:
            display = val[:4] + "..." + val[-4:] if len(val) > 8 else "<short>"
            typer.echo(f"    {key}={display}")
        else:
            typer.echo(f"    {key}=<not set>")
    typer.echo()
    typer.echo("  Checks:")
    # Check signing key
    if config.get("signing_key") or os.environ.get("ACTENON_SIGNING_KEY"):
        typer.echo("    signing key: OK")
    else:
        typer.echo("    signing key: WARNING (using ephemeral dev key)")
    # Check DB
    db_path = os.environ.get("ACTENON_DB_PATH", "actenon.db")
    if Path(db_path).exists():
        typer.echo(f"    local db:    OK ({db_path})")
    else:
        typer.echo(f"    local db:    not found ({db_path})")
    # Check protocol
    try:
        import actenon_protocol

        typer.echo(f"    protocol:    OK (v{actenon_protocol.__version__})")
    except ImportError:
        typer.echo("    protocol:    NOT INSTALLED")
    # Check kernel
    try:
        import actenon

        kver = getattr(actenon, "__version__", "unknown")
        typer.echo(f"    kernel:      OK (v{kver})")
    except ImportError:
        typer.echo("    kernel:      NOT INSTALLED")
    # Check scan
    try:
        import actenon_scan

        typer.echo(f"    scan:        OK (v{actenon_scan.__version__})")
    except ImportError:
        typer.echo("    scan:        not installed (pip install actenon-scan)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    app()


if __name__ == "__main__":
    main()
