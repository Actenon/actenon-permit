"""Actual ASGI chunks must be bounded without changing valid handler bytes.

The middleware bounds its retained input; ASGI server allocation of each
individual incoming chunk remains the server's responsibility.
"""

import asyncio
import json

import pytest
from fastapi import FastAPI, Request

from actenon_permit.boundary import (
    BoundaryManifest,
    BoundaryMiddleware,
    mint_boundary_proof,
    proof_headers,
)
from actenon_permit.ed25519_signer import build_ed25519_signer, generate_ed25519_keypair


async def asgi_request(chunks, *, mode="enforce"):
    key = generate_ed25519_keypair(key_id="bounded-body-test")
    signer = build_ed25519_signer(key)
    manifest = BoundaryManifest.from_dict(
        {
            "version": "1.0.0",
            "metadata": {"service_name": "bounded-body", "framework": "fastapi"},
            "enforcement": {"mode": mode, "replay_store": "memory"},
            "trusted_issuers": [{"issuer": "review", "public_keys": [key.public_key_jwk]}],
            "boundaries": [
                {
                    "id": "typed",
                    "route": "POST /typed",
                    "action": "test.typed",
                    "target": {"type": "fixture", "from": "body.target"},
                    "parameters": {"value": {"from": "body.value", "type": "string"}},
                    "execution_mode": "resource_owned",
                    "audience": "service:typed",
                    "proof": {"source": "header", "name": "X-Actenon-Proof"},
                }
            ],
        }
    )
    app, dispatched, response, read_count = FastAPI(), [], [], 0

    @app.post("/typed")
    async def handler(request: Request):
        dispatched.append(await request.body())
        return {"received": len(dispatched[-1])}

    app.add_middleware(BoundaryMiddleware, manifest=manifest)
    headers = proof_headers(
        *mint_boundary_proof(
            signer,
            action="test.typed",
            target="review",
            parameters={"value": "a雪"},
            audience="service:typed",
        )
    )
    finished = asyncio.Event()

    async def receive():
        nonlocal read_count
        if read_count < len(chunks):
            chunk = chunks[read_count]
            read_count += 1
            return {"type": "http.request", "body": chunk, "more_body": read_count < len(chunks)}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        response.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            finished.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/typed",
        "raw_path": b"/typed",
        "query_string": b"",
        "root_path": "",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "headers": [(name.lower().encode(), value.encode()) for name, value in headers.items()],
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in response if m["type"] == "http.response.start")
    return status, dispatched, read_count


@pytest.mark.parametrize("mode", ["enforce", "observe", "warn"])
async def test_oversized_body_stops_consumption_without_forwarding_prefix_or_tail(mode):
    chunks = [b"x" * 65536] * 32
    status, dispatched, count = await asgi_request(chunks, mode=mode)
    assert status in (403, 413)
    assert dispatched == []
    assert count == 17, "must stop on first chunk beyond 1 MiB, not buffer the entire body"


@pytest.mark.parametrize("mode", ["enforce", "observe", "warn"])
async def test_valid_chunked_body_reaches_handler_byte_identically(mode):
    raw = json.dumps({"target": "review", "value": "a雪"}, ensure_ascii=False).encode()
    snow = raw.index("雪".encode())
    chunks = [raw[:1], raw[1 : snow + 1], raw[snow + 1 : snow + 2], raw[snow + 2 :]]
    status, dispatched, count = await asgi_request(chunks, mode=mode)
    assert status == 200
    assert dispatched == [raw]
    assert count == 4
