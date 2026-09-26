"""Boundary self-test: run real adversarial requests through BoundaryMiddleware.

``actenon protect test`` and ``actenon protect quickstart`` use this. For each
boundary in the manifest it builds a throwaway app with the same route, puts
``BoundaryMiddleware`` in front of it (enforce mode) with a throwaway Ed25519
issuer key as the trust root, mints genuine proofs with that key, and sends
real requests: a valid proof, no proof, altered parameters and target, a
replay, the wrong audience, an expired proof, a malformed proof, a proof
signed by a different key, and alternate spellings of the route. Every result
is what the middleware actually did.

This proves the enforcement mechanism for each mapped route. It does not
exercise your production trust configuration (the issuer's real keys), which
is reported separately as ``configuration_issues``.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from .manifest import BoundaryEntry, BoundaryManifest, EnforcementConfig
from .proofs import Ed25519PublicKeyVerifier, mint_boundary_proof, proof_headers

CHECKS = (
    "valid proof executes",
    "no proof refuses",
    "altered params refuses",
    "altered target refuses",
    "replay refuses",
    "wrong audience refuses",
    "expired proof refuses",
    "malformed proof refuses",
    "forged proof refuses",
    "side-effect not called on refusal",
    "no bypass via alternate route",
)

_TEST_AUDIENCE = "service:actenon-protect-test"


def _sample(name: str, type_hint: str) -> Any:
    if type_hint in ("integer", "int"):
        return 7
    if type_hint in ("number", "float"):
        return 7.5
    if type_hint in ("boolean", "bool"):
        return True
    return f"probe-{name}"


def _altered(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value * 1000 + 1
    return f"{value}-altered"


def _build_request(boundary: BoundaryEntry, values: dict[str, Any], target: Any):
    """(path, json_body, headers, query) carrying ``values`` and ``target``."""
    body: dict[str, Any] = {}
    headers: dict[str, str] = {}
    query: dict[str, str] = {}
    path_values: dict[str, str] = {}
    mappings = [(m.from_expr, values[n]) for n, m in boundary.parameters.items()]
    if boundary.target.from_expr:
        mappings.append((boundary.target.from_expr, target))
    for expr, value in mappings:
        source, _, field = expr.partition(".")
        if source == "body":
            body[field] = value
        elif source == "header":
            headers[field] = str(value)
        elif source == "query":
            query[field] = str(value)
        elif source == "path":
            path_values[field] = str(value)
    path = re.sub(
        r"\{([^}]+)\}", lambda m: path_values.get(m.group(1), f"probe-{m.group(1)}"), boundary.path
    )
    return path, body, headers, query


def configuration_issues(manifest: BoundaryManifest) -> list[str]:
    issues: list[str] = []
    if not any(i.public_keys for i in manifest.trusted_issuers):
        issues.append(
            "no trusted issuer lists public_keys: the middleware has no trust root "
            "and will refuse every request (add the issuer's Ed25519 JWK under "
            "trusted_issuers[].public_keys, or pass pccb_verifier=)"
        )
    for b in manifest.boundaries:
        if not b.audience:
            issues.append(f"boundary '{b.id}' has no audience: every request to it will be refused")
    return issues


def _check_boundary(boundary: BoundaryEntry) -> list[dict[str, Any]]:
    import warnings

    from actenon.proof.service import PCCBVerifier
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # starlette's httpx -> httpx2 notice
        from starlette.testclient import TestClient

    from ..ed25519_signer import build_ed25519_signer, generate_ed25519_keypair
    from .middleware import BoundaryMiddleware

    keypair = generate_ed25519_keypair(key_id="actenon-protect-test")
    signer = build_ed25519_signer(keypair)
    audience = boundary.audience or _TEST_AUDIENCE
    probe = replace(boundary, audience=audience)
    manifest = BoundaryManifest(
        version="1.0.0",
        enforcement=EnforcementConfig(mode="enforce"),
        boundaries=[probe],
    )

    calls: list[int] = []

    async def handler(request):  # noqa: ARG001
        calls.append(1)
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route(probe.path, handler, methods=[probe.method])])
    app.add_middleware(
        BoundaryMiddleware,
        manifest=manifest,
        pccb_verifier=PCCBVerifier(signer=Ed25519PublicKeyVerifier([keypair.public_key_jwk])),
    )
    client = TestClient(app)

    values = {n: _sample(n, m.type) for n, m in probe.parameters.items()}
    target = f"probe-{probe.target.type or 'target'}" if probe.target.from_expr else None
    # A parameter mapped from the same request field as the target carries
    # the target's value; the request has only one value for that field.
    shared = [n for n, m in probe.parameters.items() if m.from_expr == probe.target.from_expr]
    for n in shared:
        values[n] = target
    alterable = [n for n in values if n not in shared]
    minted_target = str(target) if target is not None else probe.id

    def mint(*, sign_with=signer, aud=audience, now=None, params=values):
        return mint_boundary_proof(
            sign_with,
            action=probe.action,
            target=minted_target,
            parameters=params,
            audience=aud,
            now=now,
            ttl_seconds=120,
        )

    def send(proof: dict[str, str] | None, *, vals=values, tgt=target, path=None) -> int:
        req_path, body, headers, query = _build_request(probe, vals, tgt)
        headers.update(proof or {})
        resp = client.request(
            probe.method,
            path or req_path,
            json=body or None,
            headers=headers,
            params=query or None,
        )
        return resp.status_code

    results: list[dict[str, Any]] = []

    def record(name: str, ok: bool | None, detail: str = "") -> None:
        status = "not_run" if ok is None else ("pass" if ok else "fail")
        results.append({"boundary": probe.id, "name": name, "status": status, "detail": detail})

    valid = proof_headers(*mint(), proof_header=probe.proof.name)
    status = send(valid)
    record("valid proof executes", status < 400 and len(calls) == 1, f"HTTP {status}")
    status = send(None)
    record("no proof refuses", status == 403, f"HTTP {status}")

    if alterable:
        name = alterable[0]
        status = send(
            proof_headers(*mint(), proof_header=probe.proof.name),
            vals={**values, name: _altered(values[name])},
        )
        record("altered params refuses", status == 403, f"{name} altered: HTTP {status}")
    else:
        record(
            "altered params refuses",
            None,
            "no parameter other than the target (covered by 'altered target refuses')",
        )

    if target is not None:
        status = send(proof_headers(*mint(), proof_header=probe.proof.name), tgt=_altered(target))
        record("altered target refuses", status == 403, f"HTTP {status}")
    else:
        record("altered target refuses", None, "boundary maps no target")

    status = send(valid)
    record("replay refuses", status == 403, f"HTTP {status}")
    status = send(proof_headers(*mint(aud=audience + "-other"), proof_header=probe.proof.name))
    record("wrong audience refuses", status == 403, f"HTTP {status}")
    expired = mint(now=datetime.now(UTC) - timedelta(hours=1))
    status = send(proof_headers(*expired, proof_header=probe.proof.name))
    record("expired proof refuses", status == 403, f"HTTP {status}")
    malformed = {**proof_headers(*mint(), proof_header=probe.proof.name), probe.proof.name: "x"}
    status = send(malformed)
    record("malformed proof refuses", status == 403, f"HTTP {status}")
    attacker = build_ed25519_signer(generate_ed25519_keypair(key_id="actenon-protect-test"))
    status = send(proof_headers(*mint(sign_with=attacker), proof_header=probe.proof.name))
    record("forged proof refuses", status == 403, f"same key id, different key: HTTP {status}")
    record(
        "side-effect not called on refusal", len(calls) == 1, f"handler ran {len(calls)} time(s)"
    )

    req_path = _build_request(probe, values, target)[0]
    before = len(calls)
    for variant in (req_path + "/", "/" + req_path, req_path.upper()):
        if variant != req_path:
            send(None, path=variant)
    record(
        "no bypass via alternate route",
        len(calls) == before,
        "trailing slash, double slash, upper case without a proof",
    )
    return results


def run_boundary_checks(manifest: BoundaryManifest) -> dict[str, Any]:
    """Run every check for every boundary; return the report dict."""
    results: list[dict[str, Any]] = []
    for boundary in manifest.boundaries:
        try:
            results.extend(_check_boundary(boundary))
        except Exception as e:  # noqa: BLE001 - a crash is a failure, not a pass
            results.append(
                {
                    "boundary": boundary.id,
                    "name": "self-test harness",
                    "status": "fail",
                    "detail": f"{type(e).__name__}: {e}",
                }
            )
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    not_run = sum(1 for r in results if r["status"] == "not_run")
    issues = configuration_issues(manifest)
    return {
        "boundaries_tested": len(manifest.boundaries),
        "tests_passed": passed,
        "tests_failed": failed,
        "tests_not_run": not_run,
        "tests_total": len(results),
        "assurance": "FAIL" if failed or not results else "PASS",
        "production_ready": not failed and not issues and bool(results),
        "configuration_issues": issues,
        "results": results,
        "note": (
            "Checks send real requests through BoundaryMiddleware with a throwaway "
            "issuer key. They prove the enforcement mechanism per route, not your "
            "production trust configuration (see configuration_issues)."
        ),
        "tested_at": datetime.now(UTC).isoformat(),
        "manifest_version": manifest.version,
    }


def print_report(report: dict[str, Any], echo) -> None:
    current = None
    marks = {"pass": "✓", "fail": "✗", "not_run": "-"}
    for r in report["results"]:
        if r["boundary"] != current:
            current = r["boundary"]
            echo(f"\n  Boundary: {current}")
        suffix = f"  ({r['detail']})" if r["detail"] and r["status"] != "pass" else ""
        echo(f"    {marks[r['status']]} {r['name']}{suffix}")
    echo(
        f"\n  {report['tests_passed']}/{report['tests_total']} checks passed, "
        f"{report['tests_failed']} failed, {report['tests_not_run']} not applicable"
    )
    echo(f"  Enforcement self-test: {report['assurance']}")
    if report["configuration_issues"]:
        echo("  Production readiness: NOT READY")
        for issue in report["configuration_issues"]:
            echo(f"    - {issue}")
    else:
        echo("  Production readiness: ready (trust root and audiences configured)")


__all__ = ["CHECKS", "configuration_issues", "print_report", "run_boundary_checks"]
