"""GitLab webhook receiver.

Accepts Push Hook and Merge Request Hook events authenticated via the
X-Gitlab-Token header (raw token comparison — GitLab does not use HMAC).
Accepted events are normalized to internal code events and published to
the durable bus for downstream workers to consume.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from src.shared.event_publisher import get_event_publisher
from src.integrations.normalizer import normalize_gitlab_mr, normalize_gitlab_push
from src.integrations.signature import verify_gitlab_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/gitlab", tags=["gitlab-webhook"])

# GitLab object_kind values for merge requests that represent "opened"
_MR_OPENED_STATES = frozenset({"opened", "reopened"})


@router.post("/webhook")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: str = Header(...),
    x_gitlab_event: str = Header(...),
):
    """Receive a webhook event from GitLab."""
    body = await request.body()

    if not verify_gitlab_signature(body, x_gitlab_token):
        logger.warning("gitlab.webhook: token verification failed")
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error("gitlab.webhook: malformed JSON body: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    object_kind = payload.get("object_kind", "")

    if object_kind == "push" or x_gitlab_event == "Push Hook":
        event = normalize_gitlab_push(payload)
    elif object_kind == "merge_request" or x_gitlab_event == "Merge Request Hook":
        attrs = payload.get("object_attributes", {})
        state = attrs.get("state", "")
        action = attrs.get("action", "")
        # "open" / "reopen" actions map to opened; everything else (update) maps to updated
        opened = action in ("open", "reopen") or state in _MR_OPENED_STATES and action not in ("update",)
        event = normalize_gitlab_mr(payload, opened=opened)
    else:
        logger.info("gitlab.webhook: ignoring event kind=%s header=%s", object_kind, x_gitlab_event)
        return {"status": "ignored", "reason": f"event {x_gitlab_event}"}

    get_event_publisher().publish(event)
    logger.info("gitlab.webhook: published event_type=%s event_id=%s", event.event_type, event.event_id)
    return {"status": "accepted", "event_id": event.event_id}
