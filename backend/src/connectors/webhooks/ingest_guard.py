"""Shared request guards for inbound webhook receiver routes.

Receiver routes are unauthenticated until the per-provider signature check
passes, so an anonymous caller can force work simply by POSTing. These
guards bound that work *before* the body is buffered or any HMAC is
computed: a per-IP request rate limit and a hard body-size ceiling.
"""
from __future__ import annotations

import json

from fastapi import HTTPException, Request

from src.shared.rate_limit import rate_limit_by_ip

# Provider deliveries are small; anything larger is rejected unread so a
# large body can't be buffered or HMAC'd by an unauthenticated caller.
MAX_WEBHOOK_BODY_BYTES = 2 * 1024 * 1024

_RATE_LIMIT_MAX_REQUESTS = 60
_RATE_LIMIT_WINDOW_SECONDS = 60


async def read_guarded_body(request: Request) -> bytes:
    """Rate-limit by IP and read the body under a hard size ceiling.

    Raises 429 when the caller exceeds the per-IP rate, or 413 when the
    body exceeds :data:`MAX_WEBHOOK_BODY_BYTES` — both before any signature
    verification runs. Returns the raw body bytes on success.
    """
    rate_limit_by_ip(request, _RATE_LIMIT_MAX_REQUESTS, _RATE_LIMIT_WINDOW_SECONDS)

    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_len = int(declared)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
        if declared_len > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Payload too large")

    # Content-Length can be absent or understate the real size under chunked
    # transfer encoding, so enforce the ceiling again while streaming.
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Payload too large")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_json_object(body: bytes) -> dict:
    """Parse a webhook body as a JSON object, raising 400 on anything else.

    A valid-JSON non-object (array, number, string, ``null``) parses fine but
    then breaks the receivers' ``payload.get(...)`` access, so reject it up
    front instead of letting an ``AttributeError`` surface as a 500.
    """
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    return parsed
