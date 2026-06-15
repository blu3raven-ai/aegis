"""Generic inbound webhook handler — uniform parse → verify → normalize → publish.

The handler is algorithm-agnostic; each ingester picks its own signature
primitive in `verify_signature()`. This means GitLab's token-compare and
GitHub's HMAC-SHA256 share the same handler.
"""
from __future__ import annotations

import json
import logging
from typing import Awaitable, Callable

from fastapi import HTTPException, Request

from src.connectors.base import BaseIngester

logger = logging.getLogger(__name__)


async def webhook_handler(
    request: Request,
    ingester: BaseIngester,
    *,
    publish: Callable[[object], Awaitable[None]],
) -> dict:
    """Run the standard inbound-webhook pipeline.

    1. Read raw request body
    2. Pull the signature header named by `ingester.signature_header()`
    3. Ask the ingester to verify — 401 on failure
    4. Normalize the body — 400 on JSON / value errors
    5. Publish the normalized event via the caller-supplied async function
    6. Return {"status": "accepted"}
    """
    body = await request.body()
    header_name = ingester.signature_header()
    header_value = request.headers.get(header_name, "")

    if not ingester.verify_signature(body, header_value):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        event = ingester.normalize(body)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("webhook %s rejected bad payload: %s", ingester.id, exc)
        raise HTTPException(status_code=400, detail="Invalid payload") from exc

    await publish(event)
    return {"status": "accepted"}
