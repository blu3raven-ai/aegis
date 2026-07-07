"""Bitbucket Cloud webhook receiver.

Accepts repo:push and pullrequest:created / pullrequest:updated events
signed with HMAC-SHA256 in the X-Hub-Signature header.
Accepted events are normalized to internal code events and published to
the durable bus for downstream workers to consume.

Secret resolution is DB-first via :func:`match_webhook_secret`; if no
``webhook_endpoints`` row matches, the receiver falls back to the
``BITBUCKET_WEBHOOK_SECRET`` env-var so bootstrap deployments keep
working.
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
from src.connectors.webhooks.normalizer import normalize_bitbucket_pr, normalize_bitbucket_push


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
        """Standalone caller; the FastAPI route uses ``match_webhook_secret``
        directly to avoid a double DB lookup."""
        return verify_with_stored_secret(
            provider="bitbucket",
            verify=lambda secret: verify_hmac_sha256(body, header, secret),
        )

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route — see bitbucket_webhook() below."""
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        return webhook_test_result(provider="bitbucket", env_var="BITBUCKET_WEBHOOK_SECRET")


_INGESTER = BitbucketIngester()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/bitbucket", tags=["integrations"], include_in_schema=False)


@router.post("/webhook")
async def bitbucket_webhook(
    request: Request,
    x_event_key: str = Header(...),
    x_hub_signature: str = Header(...),
    x_request_uuid: str | None = Header(default=None, alias="X-Request-UUID"),
):
    """Receive a signed webhook event from Bitbucket Cloud."""
    body = await read_guarded_body(request)

    def _verify(secret: str) -> bool:
        return verify_hmac_sha256(body, x_hub_signature, secret)

    async with get_session() as session:
        matched = await match_webhook_secret(session, provider="bitbucket", verify=_verify)
    if matched is None:
        logger.warning("bitbucket.webhook: signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = parse_json_object(body)

    if x_event_key == "repo:push":
        event = normalize_bitbucket_push(payload)
    elif x_event_key == "pullrequest:created":
        event = normalize_bitbucket_pr(payload, opened=True)
    elif x_event_key == "pullrequest:updated":
        event = normalize_bitbucket_pr(payload, opened=False)
    else:
        logger.info("bitbucket.webhook: ignoring event key=%s", x_event_key)
        return {"status": "ignored", "reason": f"event {x_event_key}"}

    delivery_id = x_request_uuid or hashlib.sha256(body).hexdigest()
    if register_delivery("bitbucket", delivery_id):
        logger.info("bitbucket.webhook: dropping replayed delivery id=%s", delivery_id)
        return {"status": "duplicate", "event_id": None}

    if matched.org_id is not None:
        event = event.model_copy(update={"org_id": matched.org_id})
    get_event_publisher().publish(event)
    logger.info(
        "bitbucket.webhook: published event_type=%s event_id=%s authed_org=%s",
        event.event_type,
        event.event_id,
        matched.org_id,
    )
    return {"status": "accepted", "event_id": event.event_id}
