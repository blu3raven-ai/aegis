"""GitHub webhook receiver.

Accepts push and pull_request events signed with HMAC-SHA256.
Signature is verified before the body is parsed — 401 on failure.
Accepted events are normalized to internal code events and published
to the durable bus for downstream workers to consume.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from src.shared.event_publisher import get_event_publisher
from src.integrations.normalizer import normalize_github_pr, normalize_github_push
from src.integrations.signature import verify_github_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/github", tags=["github-webhook"])


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(...),
    x_hub_signature_256: str = Header(...),
):
    """Receive a signed webhook event from GitHub."""
    body = await request.body()

    if not verify_github_signature(body, x_hub_signature_256):
        logger.warning("github.webhook: signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error("github.webhook: malformed JSON body: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    if x_github_event == "ping":
        return {"status": "pong"}

    if x_github_event == "push":
        event = normalize_github_push(payload)
    elif x_github_event == "pull_request":
        action = payload.get("action")
        if action in ("opened", "reopened"):
            event = normalize_github_pr(payload, opened=True)
        elif action in ("synchronize", "edited"):
            event = normalize_github_pr(payload, opened=False)
        else:
            logger.info("github.webhook: ignoring pull_request action=%s", action)
            return {"status": "ignored", "reason": f"pull_request action {action}"}
    else:
        logger.info("github.webhook: ignoring event type=%s", x_github_event)
        return {"status": "ignored", "reason": f"event type {x_github_event}"}

    get_event_publisher().publish(event)
    logger.info("github.webhook: published event_type=%s event_id=%s", event.event_type, event.event_id)
    return {"status": "accepted", "event_id": event.event_id}
