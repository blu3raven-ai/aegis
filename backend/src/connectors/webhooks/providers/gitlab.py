"""GitLab webhook receiver.

Accepts Push Hook and Merge Request Hook events authenticated via the
X-Gitlab-Token header (raw token comparison — GitLab does not use HMAC).
Accepted events are normalized to internal code events and published to
the durable bus for downstream workers to consume.

Secret resolution is DB-first via :func:`match_webhook_secret`; if no
``webhook_endpoints`` row matches, the receiver falls back to the
``GITLAB_WEBHOOK_SECRET`` env-var so bootstrap deployments keep working.
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
from src.connectors.webhooks.signature import verify_token_eq
from src.db.engine import get_session
from src.shared.event_publisher import get_event_publisher
from src.connectors.webhooks.normalizer import normalize_gitlab_mr, normalize_gitlab_push


@register_connector
class GitLabIngester(BaseIngester):
    """Inbound GitLab webhook ingester — Push Hook and Merge Request Hook events."""

    id = "gitlab-webhook"
    name = "GitLab Webhook"
    category = "ci"
    description = "Receive Push Hook and Merge Request Hook events from GitLab"
    version = "v1.0"
    status = "stable"
    icon_slug = "gitlab"

    def signature_header(self) -> str:
        return "X-Gitlab-Token"

    def verify_signature(self, body: bytes, header: str) -> bool:
        """Standalone caller; the FastAPI route uses ``match_webhook_secret``
        directly to avoid a double DB lookup. ``body`` is accepted for
        interface parity with HMAC providers and ignored — GitLab passes a
        raw shared token in the header."""
        del body
        return verify_with_stored_secret(
            provider="gitlab",
            verify=lambda secret: verify_token_eq(secret, header),
        )

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route — see gitlab_webhook() below."""
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        return webhook_test_result(provider="gitlab", env_var="GITLAB_WEBHOOK_SECRET")


_INGESTER = GitLabIngester()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/gitlab", tags=["integrations"], include_in_schema=False)

# GitLab object_kind values for merge requests that represent "opened"
_MR_OPENED_STATES = frozenset({"opened", "reopened"})


@router.post("/webhook")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: str = Header(...),
    x_gitlab_event: str = Header(...),
    x_gitlab_event_uuid: str | None = Header(default=None, alias="X-Gitlab-Event-UUID"),
):
    """Receive a webhook event from GitLab."""
    body = await read_guarded_body(request)

    def _verify(secret: str) -> bool:
        return verify_token_eq(secret, x_gitlab_token)

    async with get_session() as session:
        matched = await match_webhook_secret(session, provider="gitlab", verify=_verify)
    if matched is None:
        logger.warning("gitlab.webhook: token verification failed")
        raise HTTPException(status_code=401, detail="Invalid token")

    payload = parse_json_object(body)

    object_kind = payload.get("object_kind", "")

    if object_kind == "push" or x_gitlab_event == "Push Hook":
        event = normalize_gitlab_push(payload)
    elif object_kind == "merge_request" or x_gitlab_event == "Merge Request Hook":
        attrs = payload.get("object_attributes", {})
        state = attrs.get("state", "")
        action = attrs.get("action", "")
        # "open" / "reopen" actions map to opened; everything else (update) maps to updated
        opened = action in ("open", "reopen") or (state in _MR_OPENED_STATES and action not in ("update",))
        event = normalize_gitlab_mr(payload, opened=opened)
    else:
        logger.info("gitlab.webhook: ignoring event kind=%s header=%s", object_kind, x_gitlab_event)
        return {"status": "ignored", "reason": f"event {x_gitlab_event}"}

    delivery_id = x_gitlab_event_uuid or hashlib.sha256(body).hexdigest()
    if register_delivery("gitlab", delivery_id):
        logger.info("gitlab.webhook: dropping replayed delivery id=%s", delivery_id)
        return {"status": "duplicate", "event_id": None}

    if matched.org_id is not None:
        event = event.model_copy(update={"org_id": matched.org_id})
    get_event_publisher().publish(event)
    logger.info(
        "gitlab.webhook: published event_type=%s event_id=%s authed_org=%s",
        event.event_type,
        event.event_id,
        matched.org_id,
    )
    return {"status": "accepted", "event_id": event.event_id}
