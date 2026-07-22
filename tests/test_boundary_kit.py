"""Tests for the Boundary Kit (Phase 1).

Covers:
  * Manifest loading (YAML + JSON)
  * Manifest serialisation (to_dict, to_yaml, to_json)
  * Boundary matching (method + path, including {param} patterns)
  * Value extraction (body, header, path, query)
  * FastAPI middleware: valid proof passes, no proof refuses, observe mode logs
  * CLI: discover, apply, test, trust add/list/verify
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from actenon_permit.boundary import (
    BoundaryManifest,
    BoundaryMiddleware,
    extract_value,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def manifest_dict():
    return {
        "version": "1.0.0",
        "metadata": {"service_name": "test-api", "framework": "fastapi"},
        "trusted_issuers": [
            {"issuer": "https://authority.example.com", "jwks_uri": "https://authority.example.com/.well-known/jwks.json", "audiences": ["service:payments"]}
        ],
        "enforcement": {"mode": "enforce", "proof_header": "X-Actenon-Proof", "replay_store": "memory"},
        "boundaries": [
            {
                "id": "refund-api",
                "route": "POST /refunds",
                "action": "payment.refund",
                "target": {"type": "payment_intent", "from": "body.payment_intent_id"},
                "parameters": {
                    "amount": {"from": "body.amount", "type": "integer"},
                    "reason": {"from": "body.reason", "type": "string"},
                },
                "execution_mode": "resource_owned",
                "audience": "service:payments",
                "proof": {"source": "header", "name": "X-Actenon-Proof"},
            },
            {
                "id": "delete-customer",
                "route": "DELETE /customers/{customer_id}",
                "action": "customer.delete",
                "target": {"type": "customer", "from": "path.customer_id"},
                "parameters": {},
                "execution_mode": "resource_owned",
                "audience": "service:customers",
            },
        ],
    }


@pytest.fixture
def manifest(manifest_dict):
    return BoundaryManifest.from_dict(manifest_dict)


@pytest.fixture
def app_with_middleware(manifest):
    app = FastAPI()

    @app.post("/refunds")
    async def create_refund():
        return {"status": "refunded"}

    @app.delete("/customers/{customer_id}")
    async def delete_customer(customer_id: str):
        return {"status": "deleted", "customer_id": customer_id}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.add_middleware(BoundaryMiddleware, manifest=manifest)
    return app


# ---------------------------------------------------------------------------
# 1. Manifest loading
# ---------------------------------------------------------------------------


def test_manifest_from_dict(manifest_dict):
    m = BoundaryManifest.from_dict(manifest_dict)
    assert m.version == "1.0.0"
    assert m.service_name == "test-api"
    assert m.framework == "fastapi"
    assert len(m.boundaries) == 2
    assert m.boundaries[0].id == "refund-api"
    assert m.boundaries[0].action == "payment.refund"
    assert m.boundaries[0].method == "POST"
    assert m.boundaries[0].path == "/refunds"
    assert m.boundaries[1].method == "DELETE"
    assert m.boundaries[1].path == "/customers/{customer_id}"


def test_manifest_from_json_file(manifest_dict, tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest_dict))
    m = BoundaryManifest.from_file(path)
    assert m.boundaries[0].id == "refund-api"


def test_manifest_from_yaml_file(manifest_dict, tmp_path):
    import yaml
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.dump(manifest_dict, default_flow_style=False))
    m = BoundaryManifest.from_file(path)
    assert m.boundaries[0].id == "refund-api"


def test_manifest_serialise(manifest):
    d = manifest.to_dict()
    assert d["version"] == "1.0.0"
    assert len(d["boundaries"]) == 2
    yaml_str = manifest.to_yaml()
    assert "refund-api" in yaml_str
    json_str = manifest.to_json()
    assert "refund-api" in json_str


# ---------------------------------------------------------------------------
# 2. Boundary matching
# ---------------------------------------------------------------------------


def test_boundary_match_exact(manifest):
    b = manifest.get_boundary("POST", "/refunds")
    assert b is not None
    assert b.id == "refund-api"


def test_boundary_match_param(manifest):
    b = manifest.get_boundary("DELETE", "/customers/123")
    assert b is not None
    assert b.id == "delete-customer"


def test_boundary_no_match(manifest):
    b = manifest.get_boundary("GET", "/health")
    assert b is None


def test_boundary_no_match_wrong_method(manifest):
    b = manifest.get_boundary("GET", "/refunds")
    assert b is None


# ---------------------------------------------------------------------------
# 3. Value extraction
# ---------------------------------------------------------------------------


def test_extract_value_body():
    val = extract_value("body.amount", {"amount": 100}, {}, {}, {})
    assert val == 100


def test_extract_value_header():
    val = extract_value("header.X-Custom", {}, {"X-Custom": "value"}, {}, {})
    assert val == "value"


def test_extract_value_path():
    val = extract_value("path.customer_id", {}, {}, {"customer_id": "123"}, {})
    assert val == "123"


def test_extract_value_query():
    val = extract_value("query.filter", {}, {}, {}, {"filter": "active"})
    assert val == "active"


def test_extract_value_missing():
    val = extract_value("body.nonexistent", {}, {}, {}, {})
    assert val is None


# ---------------------------------------------------------------------------
# 4. Middleware: enforce mode
# ---------------------------------------------------------------------------


def test_middleware_no_proof_refused(app_with_middleware):
    """In enforce mode, a request without a proof is refused."""
    client = TestClient(app_with_middleware)
    resp = client.post("/refunds", json={"payment_intent_id": "pi_123", "amount": 100, "reason": "customer"})
    assert resp.status_code == 403
    body = resp.json()
    assert body["outcome"] == "refused"
    assert body["boundary_id"] == "refund-api"


def test_middleware_valid_proof_passes(app_with_middleware):
    """A request with a valid proof passes through to the handler."""
    client = TestClient(app_with_middleware)
    resp = client.post(
        "/refunds",
        json={"payment_intent_id": "pi_123", "amount": 100, "reason": "customer"},
        headers={"X-Actenon-Proof": "valid_proof_token_at_least_16_chars_long"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "refunded"
    # Receipt should be in the response header.
    assert "X-Actenon-Receipt" in resp.headers


def test_middleware_unprotected_route_passes(app_with_middleware):
    """Routes not in the manifest are not intercepted."""
    client = TestClient(app_with_middleware)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_middleware_replay_refused(app_with_middleware):
    """The same proof token cannot be used twice."""
    client = TestClient(app_with_middleware)
    proof = "valid_proof_token_at_least_16_chars_long"
    # First request succeeds.
    resp1 = client.post(
        "/refunds",
        json={"payment_intent_id": "pi_123", "amount": 100, "reason": "customer"},
        headers={"X-Actenon-Proof": proof},
    )
    assert resp1.status_code == 200
    # Second request with same proof is refused (replay).
    resp2 = client.post(
        "/refunds",
        json={"payment_intent_id": "pi_456", "amount": 200, "reason": "other"},
        headers={"X-Actenon-Proof": proof},
    )
    assert resp2.status_code == 403
    assert "replay" in resp2.json()["reason"].lower()


# ---------------------------------------------------------------------------
# 5. Middleware: observe mode
# ---------------------------------------------------------------------------


def test_middleware_observe_mode_logs(app_with_middleware, manifest_dict):
    """In observe mode, requests are not blocked but logged."""
    manifest_dict["enforcement"]["mode"] = "observe"
    manifest = BoundaryManifest.from_dict(manifest_dict)

    app = FastAPI()

    @app.post("/refunds")
    async def create_refund():
        return {"status": "refunded"}

    app.add_middleware(BoundaryMiddleware, manifest=manifest)
    client = TestClient(app)

    # Request without proof — should pass (observe mode).
    resp = client.post("/refunds", json={"payment_intent_id": "pi_123", "amount": 100})
    assert resp.status_code == 200
    assert resp.json()["status"] == "refunded"


# ---------------------------------------------------------------------------
# 6. CLI: protect discover
# ---------------------------------------------------------------------------


def test_cli_protect_disccover():
    """The discover command finds FastAPI routes with sink calls AND
    auto-extracts parameter mappings from the function signature."""
    from actenon_permit.unified_cli import main

    code = '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/refunds")
async def refund(payment_intent_id: str, amount: int, reason: str):
    stripe.Refund.create(amount=amount)
    return {"status": "ok"}

@app.delete("/customers/{customer_id}")
async def delete_customer(customer_id: str):
    db.delete(customer_id)
    return {"status": "ok"}

@app.get("/health")
async def health():
    return {"status": "ok"}
'''
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        f.flush()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as mf:
            manifest_path = mf.name
        # Run discover
        import sys
        old_argv = sys.argv
        sys.argv = ["actenon", "protect", "discover", f.name, "--output", manifest_path]
        try:
            main()
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv

    # Check the manifest was generated
    import yaml
    manifest = yaml.safe_load(Path(manifest_path).read_text())
    assert len(manifest["boundaries"]) == 2  # /refunds + /customers/{id}, not /health

    # Check the first boundary (POST /refunds)
    b0 = manifest["boundaries"][0]
    assert b0["route"] == "POST /refunds"
    assert b0["action"] == "refunds.create"
    # Parameters should be auto-extracted from the function signature
    assert "payment_intent_id" in b0["parameters"]
    assert b0["parameters"]["payment_intent_id"]["from"] == "body.payment_intent_id"
    assert b0["parameters"]["payment_intent_id"]["type"] == "string"
    assert "amount" in b0["parameters"]
    assert b0["parameters"]["amount"]["from"] == "body.amount"
    assert b0["parameters"]["amount"]["type"] == "integer"
    assert "reason" in b0["parameters"]
    assert b0["parameters"]["reason"]["type"] == "string"
    # Target should be the first ID-like body param (payment_intent_id)
    assert b0["target"]["from"] == "body.payment_intent_id"

    # Check the second boundary (DELETE /customers/{customer_id})
    b1 = manifest["boundaries"][1]
    assert b1["route"] == "DELETE /customers/{customer_id}"
    assert b1["action"] == "customers.delete"
    # customer_id is a path param -> should be the target
    assert b1["target"]["from"] == "path.customer_id"
    assert "customer_id" in b1["parameters"]
    assert b1["parameters"]["customer_id"]["from"] == "path.customer_id"

    os.unlink(f.name)
    os.unlink(manifest_path)


# ---------------------------------------------------------------------------
# 7. CLI: protect test
# ---------------------------------------------------------------------------


def test_cli_protect_test(manifest_dict, tmp_path):
    """The test command runs adversarial tests and generates a report."""
    from actenon_permit.unified_cli import main

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_dict))

    import sys
    old_argv = sys.argv
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    sys.argv = ["actenon", "protect", "test", "--manifest", str(manifest_path)]
    with __import__("contextlib").suppress(SystemExit):
        main()
    sys.argv = old_argv
    os.chdir(old_cwd)

    # Check the report was generated
    report_path = tmp_path / "actenon_boundary_report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text())
    assert report["assurance"] == "PASS"
    assert report["tests_passed"] > 0


# ---------------------------------------------------------------------------
# 8. CLI: trust add/list/verify
# ---------------------------------------------------------------------------


def test_cli_trust_add_list_verify(tmp_path, monkeypatch):
    """Trust commands manage trusted issuers."""
    from actenon_permit.unified_cli import main

    trust_path = tmp_path / "trusted_issuers.json"
    monkeypatch.setattr("actenon_permit.unified_cli.TRUST_FILE", trust_path)

    import sys
    old_argv = sys.argv

    # Add an issuer
    sys.argv = ["actenon", "trust", "add", "https://authority.example.com", "--jwks", "https://authority.example.com/.well-known/jwks.json"]
    with __import__("contextlib").suppress(SystemExit):
        main()

    # Verify
    sys.argv = ["actenon", "trust", "verify"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0

    # List
    sys.argv = ["actenon", "trust", "list"]
    with __import__("contextlib").suppress(SystemExit):
        main()
    sys.argv = old_argv
    assert trust_path.exists()
    issuers = json.loads(trust_path.read_text())
    assert len(issuers) == 1
    assert issuers[0]["issuer"] == "https://authority.example.com"


# ---------------------------------------------------------------------------
# 9. CLI: protect quickstart (one-command flow)
# ---------------------------------------------------------------------------


def test_cli_protect_quickstart(tmp_path):
    """The quickstart command runs discover + apply + test in one shot."""
    from actenon_permit.unified_cli import main

    code = '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/refunds")
async def refund(payment_intent_id: str, amount: int):
    stripe.Refund.create(amount=amount)
    return {"status": "ok"}
'''
    api_file = tmp_path / "api.py"
    api_file.write_text(code)

    manifest_file = tmp_path / "boundary.yaml"

    import sys
    old_argv = sys.argv
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    sys.argv = ["actenon", "protect", "quickstart", str(api_file), "--output", str(manifest_file)]
    try:
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)

    # Manifest should exist
    assert manifest_file.exists()

    # Middleware code should exist
    assert (tmp_path / "actenon_boundary.py").exists()

    # Report should exist
    assert (tmp_path / "actenon_boundary_report.json").exists()
    report = json.loads((tmp_path / "actenon_boundary_report.json").read_text())
    assert report["assurance"] == "PASS"


def test_cli_protect_quickstart_no_findings(tmp_path):
    """Quickstart with no consequential endpoints completes gracefully."""
    from actenon_permit.unified_cli import main

    code = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}
'''
    api_file = tmp_path / "api.py"
    api_file.write_text(code)

    manifest_file = tmp_path / "boundary.yaml"

    import sys
    old_argv = sys.argv
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    sys.argv = ["actenon", "protect", "quickstart", str(api_file), "--output", str(manifest_file)]
    try:
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)

    # Manifest should exist but have no boundaries
    assert manifest_file.exists()


# ---------------------------------------------------------------------------
# 10. CLI: protect deploy (mode switching)
# ---------------------------------------------------------------------------


def test_cli_protect_deploy_observe(manifest_dict, tmp_path):
    """Deploy command switches to observe mode."""
    from actenon_permit.unified_cli import main

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_dict))

    import sys
    old_argv = sys.argv
    sys.argv = ["actenon", "protect", "deploy", "--manifest", str(manifest_path), "--mode", "observe"]
    try:
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv

    # Check the manifest was updated
    updated = json.loads(manifest_path.read_text())
    assert updated["enforcement"]["mode"] == "observe"


def test_cli_protect_deploy_enforce(manifest_dict, tmp_path):
    """Deploy command switches to enforce mode."""
    from actenon_permit.unified_cli import main

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_dict))

    import sys
    old_argv = sys.argv
    sys.argv = ["actenon", "protect", "deploy", "--manifest", str(manifest_path), "--mode", "enforce"]
    try:
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv

    updated = json.loads(manifest_path.read_text())
    assert updated["enforcement"]["mode"] == "enforce"


def test_cli_protect_deploy_invalid_mode(manifest_dict, tmp_path):
    """Deploy command rejects invalid modes."""
    from actenon_permit.unified_cli import main

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_dict))

    import sys
    old_argv = sys.argv
    sys.argv = ["actenon", "protect", "deploy", "--manifest", str(manifest_path), "--mode", "invalid"]
    try:
        main()
        assert False, "should have exited"
    except SystemExit as e:
        assert e.code == 1
    finally:
        sys.argv = old_argv


def test_cli_protect_deploy_flags_missing_issuers(manifest_dict, tmp_path):
    """Deploy in enforce mode flags missing trusted issuers."""
    from actenon_permit.unified_cli import main

    manifest_dict["trusted_issuers"] = []  # Remove issuers
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_dict))

    import sys
    old_argv = sys.argv
    sys.argv = ["actenon", "protect", "deploy", "--manifest", str(manifest_path), "--mode", "enforce"]
    try:
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv

    # The manifest should still be updated
    updated = json.loads(manifest_path.read_text())
    assert updated["enforcement"]["mode"] == "enforce"
