"""The declared boundary type must survive ordinary handler validation.

These are local FastAPI/Pydantic handlers behind real Ed25519 proofs, not
provider mutations. A matching signed JSON value can still change type in
a handler unless the manifest's declared type is enforced first.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import create_model

from actenon_permit.boundary import (
    BoundaryManifest,
    BoundaryMiddleware,
    mint_boundary_proof,
    proof_headers,
)
from actenon_permit.ed25519_signer import build_ed25519_signer, generate_ed25519_keypair


def dispatch_to_typed_handler(declared_type, python_type, value):
    key = generate_ed25519_keypair(key_id="declared-types-test")
    signer = build_ed25519_signer(key)
    manifest = BoundaryManifest.from_dict(
        {
            "version": "1.0.0",
            "metadata": {"service_name": "typed-handler", "framework": "fastapi"},
            "enforcement": {"mode": "enforce", "replay_store": "memory"},
            "trusted_issuers": [{"issuer": "review", "public_keys": [key.public_key_jwk]}],
            "boundaries": [
                {
                    "id": "typed",
                    "route": "POST /typed",
                    "action": "test.typed",
                    "target": {"type": "fixture", "from": "body.target"},
                    "parameters": {"value": {"from": "body.value", "type": declared_type}},
                    "execution_mode": "resource_owned",
                    "audience": "service:typed",
                    "proof": {"source": "header", "name": "X-Actenon-Proof"},
                }
            ],
        }
    )
    app, dispatched = FastAPI(), []
    model = create_model("TypedBody", target=(str, ...), value=(python_type, ...))

    @app.post("/typed")
    async def handler(body: model):
        dispatched.append({"value": body.value, "python_type": type(body.value).__name__})
        return {"reached": True}

    app.add_middleware(BoundaryMiddleware, manifest=manifest)
    headers = proof_headers(
        *mint_boundary_proof(
            signer,
            action="test.typed",
            target="review",
            parameters={"value": value},
            audience="service:typed",
        )
    )
    response = TestClient(app).post(
        "/typed", json={"target": "review", "value": value}, headers=headers
    )
    return response, dispatched


@pytest.mark.parametrize(
    "declared,handler_type,value",
    [
        ("integer", int, True),
        ("integer", int, "100"),
        ("boolean", bool, 1),
        ("boolean", bool, "true"),
        ("string", str, 100),
        ("array", list, {"x": 1}),
        ("object", dict, [1]),
    ],
)
def test_signed_value_of_wrong_declared_type_never_reaches_handler(declared, handler_type, value):
    response, dispatched = dispatch_to_typed_handler(declared, handler_type, value)
    assert response.status_code == 403 and dispatched == [], {
        "signed_value": value,
        "status": response.status_code,
        "dispatched": dispatched,
    }


@pytest.mark.parametrize("declared", ["float", "number", "unknown"])
def test_unsupported_declared_type_is_not_silently_ignored(declared):
    response, dispatched = dispatch_to_typed_handler(declared, float, 1)
    assert response.status_code == 403 and dispatched == [], {
        "declared": declared,
        "signed_value": 1,
        "status": response.status_code,
        "dispatched": dispatched,
    }


@pytest.mark.parametrize(
    "declared,handler_type,value",
    [
        ("integer", int, 100),
        ("boolean", bool, True),
        ("string", str, "雪"),
        ("array", list, [1, "雪", True]),
        ("object", dict, {"x": [1, "雪", True]}),
    ],
)
def test_supported_declared_value_reaches_handler_unchanged(declared, handler_type, value):
    response, dispatched = dispatch_to_typed_handler(declared, handler_type, value)
    assert response.status_code == 200, response.text
    assert dispatched == [{"value": value, "python_type": handler_type.__name__}]
