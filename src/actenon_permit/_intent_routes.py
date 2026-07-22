"""Actenon-Permit v1.3 HTTP routes for the AEI developer surface (Prompt 10).

This module is deliberately separate from ``gateway.py`` for the same
reason ``_proxy_routes.py`` is: it MUST NOT use
``from __future__ import annotations``. FastAPI's Request-type
detection happens at runtime via isinstance checks on the parameter
annotation, and stringified annotations break it.

Endpoints:

  POST /intents                    create a new AEI
  GET  /intents                    list intents (optional ?requester_subject=)
  GET  /intents/{intent_id}        get a single intent
  POST /intents/{intent_id}/execute   execute an intent (requires X-Actenon-Grant header)

The execute endpoint is brokered-only via HTTP. Resource-owned
submission requires a ``ResourceOwnedSubmissionClient`` configured
with the resource's signing key, which is deployment-specific and
not exposed via the generic HTTP surface. HTTP callers should use
``submit_to_resource`` directly (in-process) or wire their own
endpoint.
"""

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from .gateway import Gateway


def mount(app, gateway: Gateway) -> None:
    """Mount /intents/* endpoints on the given FastAPI app."""

    @app.post("/intents")
    async def create_intent(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"error": "request body must be valid JSON"},
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=400,
                content={"error": "request body must be a JSON object"},
            )

        # Required fields.
        required = (
            "action_type",
            "action_params",
            "target_type",
            "target_id",
            "requested_execution_mode",
            "requester_subject",
            "requester_agent_id",
        )
        for field in required:
            if field not in body:
                return JSONResponse(
                    status_code=422,
                    content={"error": f"missing required field: {field}"},
                )

        try:
            intent = gateway.create_intent(
                action_type=body["action_type"],
                action_params=body["action_params"],
                target_type=body["target_type"],
                target_id=body["target_id"],
                requested_execution_mode=body["requested_execution_mode"],
                requester_subject=body["requester_subject"],
                requester_agent_id=body["requester_agent_id"],
                requester_tenant_id=body.get("requester_tenant_id"),
                idempotency_key=body.get("idempotency_key"),
                expiry_seconds=body.get("expiry_seconds", 3600),
                metadata=body.get("metadata"),
            )
        except ValueError as e:
            return JSONResponse(status_code=422, content={"error": str(e)})
        except Exception as e:  # noqa: BLE001 - surface as 400
            return JSONResponse(
                status_code=400,
                content={"error": f"{type(e).__name__}: {e}"},
            )
        return JSONResponse(status_code=201, content=intent)

    @app.get("/intents")
    def list_intents(requester_subject: str | None = None) -> dict[str, Any]:
        intents = gateway.list_intents(requester_subject=requester_subject)
        return {"intents": intents, "count": len(intents)}

    @app.get("/intents/{intent_id}")
    def get_intent(intent_id: str) -> JSONResponse:
        intent = gateway.get_intent(intent_id)
        if intent is None:
            return JSONResponse(
                status_code=404,
                content={"error": f"intent not found: {intent_id}"},
            )
        return JSONResponse(status_code=200, content=intent)

    @app.post("/intents/{intent_id}/execute")
    async def execute_intent(intent_id: str, request: Request) -> JSONResponse:
        grant_token = request.headers.get("x-actenon-grant")
        if not grant_token:
            return JSONResponse(
                status_code=401,
                content={
                    "outcome": "DENY",
                    "reason": "missing X-Actenon-Grant header",
                },
            )
        # Optional body overrides (e.g. idempotency_key). Currently unused
        # but reserved for future use.
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}

        result = gateway.execute_intent(intent_id, grant_token=grant_token)
        outcome = result.get("outcome", "DENY")
        status = {"ALLOW": 200, "DENY": 403, "REQUIRE_APPROVAL": 202}.get(outcome, 500)
        return JSONResponse(content=result, status_code=status)
