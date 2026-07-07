"""GitHub webhook receiver.

Accepts push and pull_request events signed with HMAC-SHA256.
Signature is verified before the body is parsed — 401 on failure.
Accepted events are normalized to internal code events and published
to the durable bus for downstream workers to consume.

Secret resolution is DB-first via :func:`match_webhook_secret`; if no
``webhook_endpoints`` row matches, the receiver falls back to the
``GITHUB_WEBHOOK_SECRET`` env-var so bootstrap deployments keep working.
"""
from __future__ import annotations

import hashlib
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from src.connectors.base import BaseIngester, TestResult
from src.connectors.registry import register_connector
from src.settings.webhooks.service import match_webhook_secret
from src.connectors.webhooks.healthcheck import webhook_test_result
from src.connectors.webhooks.dedupe import register_delivery
from src.connectors.webhooks.ingest_guard import parse_json_object, read_guarded_body
from src.connectors.webhooks.secret_resolver import verify_with_stored_secret
from src.connectors.webhooks.signature import verify_hmac_sha256
from src.db.engine import get_session
from src.shared.event_publisher import get_event_publisher
from src.connectors.webhooks.normalizer import normalize_github_pr, normalize_github_push


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
        """Standalone caller; the FastAPI route uses ``match_webhook_secret``
        directly to avoid a double DB lookup."""
        return verify_with_stored_secret(
            provider="github",
            verify=lambda secret: verify_hmac_sha256(body, header, secret),
        )

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route, not here — see github_webhook() below."""
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        """Reports OK if the webhook secret is configured. A real liveness
        check would require sending a ping through GitHub, which we don't.

        Mirrors the receiver path: DB-backed rows take precedence over the
        env-var so a rotated secret doesn't look like "not configured"."""
        return webhook_test_result(provider="github", env_var="GITHUB_WEBHOOK_SECRET")


_INGESTER = GitHubIngester()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/github", tags=["integrations"], include_in_schema=False)


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(...),
    x_hub_signature_256: str = Header(...),
    x_github_delivery: str | None = Header(default=None),
):
    """Receive a signed webhook event from GitHub."""
    body = await read_guarded_body(request)

    def _verify(secret: str) -> bool:
        return verify_hmac_sha256(body, x_hub_signature_256, secret)

    async with get_session() as session:
        matched = await match_webhook_secret(session, provider="github", verify=_verify)
    if matched is None:
        logger.warning("github.webhook: signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = parse_json_object(body)

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

    # A well-formed JSON object can still be missing required fields (an
    # unexpected event variant); the normalizer returns None for those.
    if event is None:
        logger.info("github.webhook: ignoring %s with missing required fields", x_github_event)
        return {"status": "ignored", "reason": "missing required fields"}

    delivery_id = x_github_delivery or hashlib.sha256(body).hexdigest()
    if register_delivery("github", delivery_id):
        logger.info("github.webhook: dropping replayed delivery id=%s", delivery_id)
        return {"status": "duplicate", "event_id": None}

    if matched.org_id is not None:
        event = event.model_copy(update={"org_id": matched.org_id})
    get_event_publisher().publish(event)
    logger.info(
        "github.webhook: published event_type=%s event_id=%s authed_org=%s",
        event.event_type,
        event.event_id,
        matched.org_id,
    )
    return {"status": "accepted", "event_id": event.event_id}
