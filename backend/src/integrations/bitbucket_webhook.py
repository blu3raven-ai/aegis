"""Bitbucket Cloud webhook receiver.

Accepts repo:push and pullrequest:created / pullrequest:updated events
signed with HMAC-SHA256 in the X-Hub-Signature header.
Accepted events are normalized to internal code events and published to
the durable bus for downstream workers to consume.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, Header, HTTPException, Request

from src.connectors.base import BaseIngester, TestResult
from src.connectors.registry import register_connector
from src.connectors.webhooks.signature import verify_hmac_sha256
from src.shared.event_publisher import get_event_publisher
from src.integrations.normalizer import normalize_bitbucket_pr, normalize_bitbucket_push


@register_connector
class BitbucketIngester(BaseIngester):
    """Inbound Bitbucket Cloud webhook ingester — repo:push and pullrequest:* events."""

    id = "bitbucket-webhook"
    name = "Bitbucket Webhook"
    category = "ci"
    description = "Receive repo:push and pull-request events from Bitbucket Cloud"
    version = "v1.0"
    status = "stable"
    icon_slug = "bitbucket"

    def signature_header(self) -> str:
        return "X-Hub-Signature"

    def verify_signature(self, body: bytes, header: str) -> bool:
        return verify_hmac_sha256(body, header, os.getenv("BITBUCKET_WEBHOOK_SECRET", ""))

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route — see bitbucket_webhook() below."""
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        if not os.getenv("BITBUCKET_WEBHOOK_SECRET"):
            return TestResult(ok=False, message="BITBUCKET_WEBHOOK_SECRET is not configured")
        return TestResult(ok=True)


_INGESTER = BitbucketIngester()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/bitbucket", tags=["bitbucket-webhook"])


@router.post("/webhook")
async def bitbucket_webhook(
    request: Request,
    x_event_key: str = Header(...),
    x_hub_signature: str = Header(...),
):
    """Receive a signed webhook event from Bitbucket Cloud."""
    body = await request.body()

    if not _INGESTER.verify_signature(body, x_hub_signature):
        logger.warning("bitbucket.webhook: signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error("bitbucket.webhook: malformed JSON body: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    if x_event_key == "repo:push":
        event = normalize_bitbucket_push(payload)
    elif x_event_key == "pullrequest:created":
        event = normalize_bitbucket_pr(payload, opened=True)
    elif x_event_key == "pullrequest:updated":
        event = normalize_bitbucket_pr(payload, opened=False)
    else:
        logger.info("bitbucket.webhook: ignoring event key=%s", x_event_key)
        return {"status": "ignored", "reason": f"event {x_event_key}"}

    get_event_publisher().publish(event)
    logger.info("bitbucket.webhook: published event_type=%s event_id=%s", event.event_type, event.event_id)
    return {"status": "accepted", "event_id": event.event_id}
