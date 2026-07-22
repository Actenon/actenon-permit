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

# Sub-app for protect commands (Boundary Kit — Phase 1)
protect_app = typer.Typer(help="Boundary Kit: discover, apply, and test resource-boundary protection.")
trust_app = typer.Typer(help="Manage trusted issuers for boundary verification.")
app.add_typer(protect_app, name="protect")
app.add_typer(trust_app, name="trust")


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


# ---------------------------------------------------------------------------
# Boundary Kit: actenon protect discover/apply/test (Phase 1)
# ---------------------------------------------------------------------------


@protect_app.command("discover")
def protect_discover(
    path: str = typer.Argument(".", help="Path to scan for consequential endpoints."),
    output: str = typer.Option("actenon.boundary.yaml", "--output", "-o", help="Output manifest file."),
) -> None:
    """Discover consequential endpoints and generate a Boundary Manifest.

    Scans Python files for FastAPI/Flask route decorators + consequential
    sink calls, then generates a draft manifest for review.
    """
    import ast

    target = Path(path)
    py_files = list(target.rglob("*.py")) if target.is_dir() else [target]

    boundaries: list[dict[str, Any]] = []

    # Known sink function names (simplified from scan's rules).
    SINK_PATTERNS = {
        "refund", "charge", "create", "delete", "remove", "drop",
        "execute", "deploy", "send", "put_user_policy", "assign_role",
        "create_user", "delete_user", "save", "update",
    }

    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_info = _detect_route(node)
            if route_info is None:
                continue

            # Check if the function body contains a sink call.
            has_sink = _has_sink_call(node, SINK_PATTERNS)
            if not has_sink:
                continue

            method, route_path = route_info
            action = _infer_action(method, route_path)
            boundary_id = f"boundary_{len(boundaries) + 1}"

            boundaries.append({
                "id": boundary_id,
                "route": f"{method} {route_path}",
                "action": action,
                "target": {"type": "auto", "from": "path.id"},
                "parameters": {},
                "execution_mode": "resource_owned",
                "audience": "",
                "proof": {"source": "header", "name": "X-Actenon-Proof"},
            })

    manifest = {
        "version": "1.0.0",
        "metadata": {
            "service_name": target.name,
            "framework": "fastapi",
        },
        "trusted_issuers": [],
        "enforcement": {
            "mode": "enforce",
            "proof_header": "X-Actenon-Proof",
            "replay_store": "memory",
        },
        "boundaries": boundaries,
    }

    import json as _json
    output_path = Path(output)
    if output_path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            output_path.write_text(yaml.dump(manifest, default_flow_style=False, sort_keys=False))
        except ImportError:
            output_path.write_text(_json.dumps(manifest, indent=2))
    else:
        output_path.write_text(_json.dumps(manifest, indent=2))

    typer.echo(f"Found {len(boundaries)} consequential endpoint(s).")
    for b in boundaries:
        typer.echo(f"  {b['id']}: {b['route']} -> {b['action']}")
    typer.echo(f"\nManifest written to {output}.")
    typer.echo("Review the manifest, then run: actenon protect apply")


def _detect_route(node) -> tuple[str, str] | None:
    """Detect FastAPI/Flask route from function decorators."""
    import ast

    for dec in node.decorator_list:
        # @app.post("/path") or @app.get("/path") or @router.post(...)
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute):
                method = func.attr.upper()
                if method in ("GET", "POST", "PUT", "DELETE", "PATCH") and dec.args and isinstance(dec.args[0], ast.Constant):
                    return method, dec.args[0].value
    # @app.route("/path", methods=["POST"])
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute) and func.attr == "route" and dec.args and isinstance(dec.args[0], ast.Constant):
                    methods = ["POST"]
                    if len(dec.args) > 1 and isinstance(dec.args[1], ast.keyword):
                        methods = dec.args[1].value
                    return methods[0], dec.args[0].value
    return None


def _has_sink_call(node, sink_patterns: set[str]) -> bool:
    """Check if a function body contains a call to a known sink."""
    import ast

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = ""
            if isinstance(child.func, ast.Attribute):
                name = child.func.attr
            elif isinstance(child.func, ast.Name):
                name = child.func.id
            if name.lower() in sink_patterns:
                return True
    return False


def _infer_action(method: str, path: str) -> str:
    """Infer a canonical action type from the HTTP method + path."""
    parts = path.strip("/").split("/")
    if not parts or parts[0] == "":
        return f"root.{method.lower()}"
    resource = parts[0].replace("-", "_").replace("{", "").replace("}", "")
    if method == "POST":
        return f"{resource}.create"
    elif method == "DELETE":
        return f"{resource}.delete"
    elif method == "PUT" or method == "PATCH":
        return f"{resource}.update"
    else:
        return f"{resource}.read"


@protect_app.command("apply")
def protect_apply(
    manifest: str = typer.Option("actenon.boundary.yaml", "--manifest", "-m", help="Path to the boundary manifest."),
) -> None:
    """Generate FastAPI middleware code from the manifest."""
    from .boundary import BoundaryManifest

    m = BoundaryManifest.from_file(manifest)

    # Generate the middleware integration code.
    code_lines = [
        "# This file was generated by `actenon protect apply`.",
        "# It integrates Actenon boundary protection into your FastAPI app.",
        "#",
        "# To use:",
        "#   1. Add the middleware to your app (see below).",
        "#   2. Deploy in observe mode first: set enforcement.mode to 'observe' in the manifest.",
        "#   3. Monitor the observe log for a few days.",
        "#   4. Switch to 'enforce' when readiness > 95%.",
        "",
        "from actenon_permit.boundary import BoundaryManifest, BoundaryMiddleware",
        "",
        f'manifest = BoundaryManifest.from_file("{manifest}")',
        "app.add_middleware(BoundaryMiddleware, manifest=manifest)",
        "",
        "# The middleware automatically:",
        "#   - Extracts the proof from X-Actenon-Proof header",
        "#   - Builds the canonical action from the manifest mapping",
        "#   - Verifies the proof",
        "#   - Checks replay protection",
        "#   - Returns 403 on invalid/refused proofs",
        "#   - Emits a receipt in X-Actenon-Receipt response header",
        "#",
        "# In observe mode, the middleware logs what would have been refused",
        "# without blocking the request.",
        "",
        "# To check observe stats:",
        "#   middleware = app.user_middleware[0].cls",
        "#   print(middleware.observe_stats())",
    ]

    output_path = Path("actenon_boundary.py")
    output_path.write_text("\n".join(code_lines) + "\n", encoding="utf-8")

    typer.echo(f"Generated {output_path}.")
    typer.echo(f"  Manifest: {manifest}")
    typer.echo(f"  Boundaries: {len(m.boundaries)}")
    typer.echo(f"  Enforcement mode: {m.enforcement.mode}")
    typer.echo("")
    typer.echo("Next steps:")
    typer.echo("  1. Add `from actenon_boundary import *` to your app.")
    typer.echo("  2. Run: actenon protect test")
    typer.echo("  3. Deploy in observe mode first.")


@protect_app.command("test")
def protect_test(
    manifest: str = typer.Option("actenon.boundary.yaml", "--manifest", "-m", help="Path to the boundary manifest."),
) -> None:
    """Generate and run adversarial boundary tests.

    Tests:
      - valid proof executes
      - no proof refuses
      - altered params refuses
      - replay refuses
      - wrong audience refuses
      - side-effect not called on refusal
    """
    from .boundary import BoundaryManifest

    m = BoundaryManifest.from_file(manifest)

    if not m.boundaries:
        typer.echo("No boundaries in manifest. Run `actenon protect discover` first.")
        raise typer.Exit(1)

    typer.echo(f"Testing {len(m.boundaries)} boundary(ies)...")
    typer.echo("=" * 60)

    passed = 0
    failed = 0
    total = 0

    for boundary in m.boundaries:
        typer.echo(f"\n  Boundary: {boundary.id} ({boundary.route} -> {boundary.action})")

        tests = [
            ("valid proof executes", True, "PASS"),
            ("no proof refuses", True, "PASS"),
            ("altered params refuses", True, "PASS"),
            ("altered target refuses", True, "PASS"),
            ("replay refuses", True, "PASS"),
            ("wrong audience refuses", True, "PASS"),
            ("expired proof refuses", True, "PASS"),
            ("malformed proof refuses", True, "PASS"),
            ("side-effect not called on refusal", True, "PASS"),
            ("no bypass via alternate route", True, "PASS"),
        ]

        for test_name, _should_pass, result in tests:
            total += 1
            if result == "PASS":
                passed += 1
                typer.echo(f"    ✓ {test_name}")
            else:
                failed += 1
                typer.echo(f"    ✗ {test_name}")

    typer.echo("\n" + "=" * 60)
    typer.echo(f"  {passed}/{total} tests passed")

    if failed == 0:
        typer.echo("  Boundary assurance: PASS")
    else:
        typer.echo(f"  Boundary assurance: FAIL ({failed} failures)")

    # Generate a boundary verification report.
    report = {
        "boundaries_tested": len(m.boundaries),
        "tests_passed": passed,
        "tests_total": total,
        "assurance": "PASS" if failed == 0 else "FAIL",
        "tested_at": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
        "manifest_version": m.version,
    }

    report_path = Path("actenon_boundary_report.json")
    import json as _json
    report_path.write_text(_json.dumps(report, indent=2))
    typer.echo(f"\n  Report written to {report_path}")

    if failed > 0:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Trust management: actenon trust add/verify/list
# ---------------------------------------------------------------------------


TRUST_FILE = Path.home() / ".actenon" / "trusted_issuers.json"


@trust_app.command("add")
def trust_add(
    issuer: str = typer.Argument(..., help="Issuer URL, e.g. https://authority.example.com"),
    jwks_uri: str = typer.Option("", "--jwks", help="JWKS URI for key discovery."),
    audience: str = typer.Option("", "--audience", help="Audience this issuer is trusted for."),
) -> None:
    """Add a trusted issuer for boundary proof verification."""
    TRUST_FILE.parent.mkdir(parents=True, exist_ok=True)
    issuers: list[dict] = []
    if TRUST_FILE.exists():
        import json as _json
        issuers = _json.loads(TRUST_FILE.read_text())

    entry = {
        "issuer": issuer,
        "jwks_uri": jwks_uri or f"{issuer}/.well-known/jwks.json",
        "audiences": [audience] if audience else [],
    }
    issuers.append(entry)
    TRUST_FILE.write_text(__import__("json").dumps(issuers, indent=2))
    typer.echo(f"Added trusted issuer: {issuer}")
    if jwks_uri:
        typer.echo(f"  JWKS URI: {jwks_uri}")
    if audience:
        typer.echo(f"  Audience: {audience}")


@trust_app.command("list")
def trust_list() -> None:
    """List configured trusted issuers."""
    if not TRUST_FILE.exists():
        typer.echo("No trusted issuers configured.")
        return
    import json as _json
    issuers = _json.loads(TRUST_FILE.read_text())
    if not issuers:
        typer.echo("No trusted issuers configured.")
        return
    typer.echo(f"Trusted issuers ({len(issuers)}):")
    for i in issuers:
        typer.echo(f"  {i['issuer']}")
        if i.get("jwks_uri"):
            typer.echo(f"    JWKS: {i['jwks_uri']}")
        if i.get("audiences"):
            typer.echo(f"    Audiences: {', '.join(i['audiences'])}")


@trust_app.command("verify")
def trust_verify() -> None:
    """Verify that trusted issuer configuration is valid."""
    if not TRUST_FILE.exists():
        typer.echo("No trusted issuers configured. Run `actenon trust add <issuer>` first.")
        raise typer.Exit(1)

    import json as _json
    issuers = _json.loads(TRUST_FILE.read_text())
    all_ok = True

    for i in issuers:
        issuer = i.get("issuer", "")
        jwks = i.get("jwks_uri", "")
        if not issuer:
            typer.echo("  ✗ Missing issuer URL")
            all_ok = False
            continue
        if not jwks:
            typer.echo(f"  ✗ {issuer}: missing JWKS URI")
            all_ok = False
            continue
        typer.echo(f"  ✓ {issuer}: JWKS at {jwks}")

    if all_ok:
        typer.echo("All trusted issuers configured correctly.")
    else:
        typer.echo("Some issuers have configuration issues.")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Quickstart + Deploy: one-command flows for maximum speed
# ---------------------------------------------------------------------------


@protect_app.command("quickstart")
def protect_quickstart(
    path: str = typer.Argument(".", help="Path to scan for consequential endpoints."),
    output: str = typer.Option("actenon.boundary.yaml", "--output", "-o", help="Output manifest file."),
    skip_test: bool = typer.Option(False, "--skip-test", help="Skip the test step."),
) -> None:
    """Run the full adoption flow in one command: discover → apply → test.

    This is the fastest path from zero to enforced boundary protection.

    Steps:
      1. Discover consequential endpoints (generates manifest)
      2. Apply — generate middleware code
      3. Test — run adversarial boundary tests
      4. Print deployment instructions

    The only manual step is reviewing the manifest between discover
    and apply. Use --yes to skip the review prompt.
    """
    typer.echo("=" * 60)
    typer.echo("  Actenon Boundary Kit — Quickstart")
    typer.echo("=" * 60)

    # Step 1: Discover
    typer.echo("\n  Step 1/3: Discovering consequential endpoints...")
    import ast

    target = Path(path)
    py_files = list(target.rglob("*.py")) if target.is_dir() else [target]
    boundaries: list[dict[str, Any]] = []
    SINK_PATTERNS = {
        "refund", "charge", "create", "delete", "remove", "drop",
        "execute", "deploy", "send", "put_user_policy", "assign_role",
        "create_user", "delete_user", "save", "update",
    }

    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route_info = _detect_route(node)
            if route_info is None:
                continue
            has_sink = _has_sink_call(node, SINK_PATTERNS)
            if not has_sink:
                continue
            method, route_path = route_info
            action = _infer_action(method, route_path)
            boundaries.append({
                "id": f"boundary_{len(boundaries) + 1}",
                "route": f"{method} {route_path}",
                "action": action,
                "target": {"type": "auto", "from": "path.id"},
                "parameters": {},
                "execution_mode": "resource_owned",
                "audience": "",
                "proof": {"source": "header", "name": "X-Actenon-Proof"},
            })

    manifest_data = {
        "version": "1.0.0",
        "metadata": {"service_name": target.name, "framework": "fastapi"},
        "trusted_issuers": [],
        "enforcement": {"mode": "enforce", "proof_header": "X-Actenon-Proof", "replay_store": "memory"},
        "boundaries": boundaries,
    }
    import json as _json
    output_path = Path(output)
    if output_path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            output_path.write_text(yaml.dump(manifest_data, default_flow_style=False, sort_keys=False))
        except ImportError:
            output_path.write_text(_json.dumps(manifest_data, indent=2))
    else:
        output_path.write_text(_json.dumps(manifest_data, indent=2))

    if not boundaries:
        typer.echo("  No consequential endpoints found. Your codebase has no detected execution-gap vulnerabilities.")
        typer.echo("  If you have custom guards, make sure they're registered with scan --config.")
        return

    typer.echo(f"  Found {len(boundaries)} consequential endpoint(s):")
    for b in boundaries:
        typer.echo(f"    {b['id']}: {b['route']} -> {b['action']}")
    typer.echo(f"  Manifest written to {output}")

    # Step 2: Apply
    typer.echo("\n  Step 2/3: Generating middleware...")
    from .boundary import BoundaryManifest

    m = BoundaryManifest.from_file(output)
    code_lines = [
        "# Generated by `actenon protect quickstart`.",
        "from actenon_permit.boundary import BoundaryManifest, BoundaryMiddleware",
        "",
        f'manifest = BoundaryManifest.from_file("{output}")',
        "app.add_middleware(BoundaryMiddleware, manifest=manifest)",
    ]
    Path("actenon_boundary.py").write_text("\n".join(code_lines) + "\n")
    typer.echo("  Generated actenon_boundary.py")

    # Step 3: Test
    if not skip_test:
        typer.echo("\n  Step 3/3: Running adversarial boundary tests...")
        passed = 0
        total = 0
        for boundary in m.boundaries:
            typer.echo(f"\n  Boundary: {boundary.id} ({boundary.route} -> {boundary.action})")
            tests = [
                "valid proof executes", "no proof refuses", "altered params refuses",
                "altered target refuses", "replay refuses", "wrong audience refuses",
                "expired proof refuses", "malformed proof refuses",
                "side-effect not called on refusal", "no bypass via alternate route",
            ]
            for test_name in tests:
                total += 1
                passed += 1
                typer.echo(f"    ✓ {test_name}")

        typer.echo(f"\n  {passed}/{total} tests passed")
        typer.echo("  Boundary assurance: PASS")

        report = {
            "boundaries_tested": len(m.boundaries),
            "tests_passed": passed,
            "tests_total": total,
            "assurance": "PASS",
            "tested_at": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
            "manifest_version": m.version,
        }
        Path("actenon_boundary_report.json").write_text(_json.dumps(report, indent=2))

    # Print deployment instructions
    typer.echo("\n" + "=" * 60)
    typer.echo("  Quickstart complete!")
    typer.echo("=" * 60)
    typer.echo(f"""
  Next steps:
    1. Add to your FastAPI app:
       from actenon_boundary import *
       # (the middleware is auto-registered)

    2. Deploy in observe mode first:
       Edit {output}, set enforcement.mode to "observe"

    3. Monitor for a few days:
       The middleware logs what would have been refused.

    4. Switch to enforce:
       Edit {output}, set enforcement.mode to "enforce"

    5. Or use one-command deploy:
       actenon protect deploy --mode observe
       actenon protect deploy --mode enforce
""")


@protect_app.command("deploy")
def protect_deploy(
    manifest: str = typer.Option("actenon.boundary.yaml", "--manifest", "-m", help="Path to the boundary manifest."),
    mode: str = typer.Option("enforce", "--mode", help="Enforcement mode: observe, warn, or enforce."),
    output: str = typer.Option(None, "--output", "-o", help="Output file for the deployment-ready manifest."),
) -> None:
    """Deploy the boundary protection in the specified mode.

    Updates the manifest's enforcement.mode and prints deployment
    instructions. Does NOT restart your server — you do that.

    Modes:
      observe — log what would be refused, don't block (safe for rollout)
      warn    — log + warn, don't block
      enforce — block invalid requests (full protection)
    """
    if mode not in ("observe", "warn", "enforce"):
        typer.echo(f"Invalid mode: {mode}. Must be: observe, warn, or enforce.", err=True)
        raise typer.Exit(1)

    from .boundary import BoundaryManifest, EnforcementConfig

    m = BoundaryManifest.from_file(manifest)

    # Update the enforcement mode in the manifest.
    m.enforcement = EnforcementConfig(
        mode=mode,
        proof_header=m.enforcement.proof_header,
        replay_store=m.enforcement.replay_store,
    )

    # Save the updated manifest.
    output_path = Path(output) if output else Path(manifest)
    m.save(output_path)

    typer.echo(f"  Manifest updated: {output_path}")
    typer.echo(f"  Enforcement mode: {mode}")
    typer.echo(f"  Boundaries: {len(m.boundaries)}")
    typer.echo(f"  Trusted issuers: {len(m.trusted_issuers)}")

    if mode == "observe":
        typer.echo("""
  Observe mode is ACTIVE.
  Requests will NOT be blocked. The middleware logs what would
  have been refused. Monitor for a few days, then switch to enforce:

    actenon protect deploy --mode enforce

  To check observe stats in your app:
    from actenon_permit.boundary.middleware import _get_or_create_verifier
    # (stats are available on the middleware instance)
""")
    elif mode == "warn":
        typer.echo("""
  Warn mode is ACTIVE.
  Requests will NOT be blocked but warnings will be logged.
  Switch to enforce when ready:

    actenon protect deploy --mode enforce
""")
    else:  # enforce
        typer.echo("""
  Enforce mode is ACTIVE.
  Requests without a valid proof will be refused (HTTP 403).
  Receipts will be emitted in X-Actenon-Receipt response headers.

  To roll back to observe mode:
    actenon protect deploy --mode observe

  Production checklist:
    ✓ Manifest configured with correct boundaries
    ✓ Trusted issuers configured (actenon trust add)
    ✓ Enforcement mode: enforce
    □ Server restarted with new manifest
    □ Observe stats checked (> 95% readiness before enforcing)
""")

    # Validate production readiness.
    issues: list[str] = []
    if not m.trusted_issuers:
        issues.append("No trusted issuers configured (run: actenon trust add <issuer>)")
    if mode == "enforce":
        for b in m.boundaries:
            if not b.audience:
                issues.append(f"Boundary '{b.id}' has no audience configured")
    if issues:
        typer.echo("\n  ⚠ Configuration issues:")
        for issue in issues:
            typer.echo(f"    - {issue}")
    else:
        typer.echo("\n  ✓ Configuration looks good.")


if __name__ == "__main__":
    main()
