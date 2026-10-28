"""Bounded request framing; Protocol owns JSON value/canonical semantics.

Reject ambiguity before gateway policy or execution. Empty bytes are accepted
only where the route explicitly permits an absent body; malformed JSON never
becomes an empty object. JSON member names remain case-sensitive: route schemas
must reject unknown fields, rather than globally folding application data.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from actenon_protocol.canonicalisation import MAX_CANONICAL_OUTPUT_BYTES, parse_strict

MAX_REQUEST_BYTES = MAX_CANONICAL_OUTPUT_BYTES


class InvalidRequestJSON(ValueError):
    """The raw request is outside the supported JSON object profile."""


def decode_request_object(raw: bytes | str, *, allow_empty: bool = False) -> dict[str, Any]:
    try:
        if isinstance(raw, str):
            # Bound codepoints before allocating their UTF-8 representation.
            if len(raw) > MAX_REQUEST_BYTES:
                raise InvalidRequestJSON("request JSON too large")
            raw = raw.encode("utf-8", errors="strict")
        if not isinstance(raw, bytes) or len(raw) > MAX_REQUEST_BYTES:
            raise InvalidRequestJSON("unsupported request size or representation")
        if not raw and allow_empty:
            return {}
        value = parse_strict(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, dict):
            raise InvalidRequestJSON("request body must be a JSON object")
        return value
    except (ValueError, RecursionError) as exc:
        # Do not reflect raw values (which may contain credentials) in errors.
        raise InvalidRequestJSON("unsupported request JSON object") from exc


async def read_request_object(request: Any, *, allow_empty: bool = False) -> dict[str, Any]:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            raise InvalidRequestJSON("request JSON too large")
        body.extend(chunk)
    return decode_request_object(bytes(body), allow_empty=allow_empty)


def request_lines(stream: Any) -> Iterator[bytes | str | None]:
    """Read bounded MCP frames; drain an oversized frame before resuming.

    None represents one refused oversized frame. Never parse a suffix of a
    refused frame as a fresh command. Text streams are supported for embedders;
    normal stdin is read as bytes so malformed UTF-8 is explicitly refused.
    """
    while True:
        line = stream.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return
        newline = b"\n" if isinstance(line, bytes) else "\n"
        if len(line) > MAX_REQUEST_BYTES:
            while not line.endswith(newline):
                line = stream.readline(MAX_REQUEST_BYTES + 1)
                if not line:
                    break
            yield None
        else:
            yield line
