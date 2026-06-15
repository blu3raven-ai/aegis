"""GitHub webhook receiver.

Accepts push and pull_request events signed with HMAC-SHA256.
Signature is verified before the body is parsed — 401 on failure.
Accepted events are normalized to internal code events and published
to the durable bus for downstream workers to consume.
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
from src.integrations.normalizer import normalize_github_pr, normalize_github_push


@register_connector
class GitHubIngester(BaseIngester):
    """Inbound GitHub webhook ingester — push and pull_request events."""

    id = "github-webhook"
    name = "GitHub Webhook"
    category = "ci"
    description = "Receive push and pull_request events from GitHub repositories"
    version = "v1.0"
    status = "stable"
    icon_slug = "github"

    def signature_header(self) -> str:
        return "X-Hub-Signature-256"

    def verify_signature(self, body: bytes, header: str) -> bool:
        return verify_hmac_sha256(body, header, os.getenv("GITHUB_WEBHOOK_SECRET", ""))

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route, not here — see github_webhook() below."""
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        """Reports OK if the webhook secret is configured. A real liveness
        check would require sending a ping through GitHub, which we don't."""
        if not os.getenv("GITHUB_WEBHOOK_SECRET"):
            return TestResult(ok=False, message="GITHUB_WEBHOOK_SECRET is not configured")
        return TestResult(ok=True)


_INGESTER = GitHubIngester()

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

    if not _INGESTER.verify_signature(body, x_hub_signature_256):
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
