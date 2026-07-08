"""Actenon-Permit v1 HTTP proxy route definitions.

This module is deliberately separate from ``gateway.py`` because it MUST NOT
use ``from __future__ import annotations``. FastAPI's Request-type detection
happens at runtime via isinstance checks on the parameter annotation, and
stringified annotations (which the future import produces) cause the
``request: Request`` parameter to be treated as a required query param,
returning 422 for every request.

Everything else in the package uses the future import for forward-reference
convenience; this file is the one place we can't.
"""

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from .gateway import Gateway


def mount(app, gateway: Gateway) -> None:
    """Mount /proxy/* endpoints on the given FastAPI app."""

    @app.get("/proxy/tools")
    def list_tools() -> dict[str, Any]:
        return {"tools": [t.name for t in gateway.tools.list()]}

    @app.post("/proxy/{tool_name}")
    async def call_tool_http(tool_name: str, request: Request) -> JSONResponse:
        grant_token = request.headers.get("x-actenon-grant")
        if not grant_token:
            return JSONResponse(
                status_code=401,
                content={"outcome": "DENY", "reason": "missing X-Actenon-Grant header"},
            )
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=400,
                content={"outcome": "DENY", "reason": "request body must be a JSON object"},
            )
        result = gateway.call_tool(tool_name, body, grant_token)
        status = {"ALLOW": 200, "DENY": 403, "REQUIRE_APPROVAL": 202}.get(result["outcome"], 500)
        return JSONResponse(content=result, status_code=status)
