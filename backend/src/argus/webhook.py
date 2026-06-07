"""Argus → Aegis webhook receiver.

Accepts signed POST payloads from Argus and translates them into internal
intel events on the durable event bus. This keeps Aegis internals decoupled
from Argus payload schemas — downstream consumers read from the bus.

Signature verification uses HMAC-SHA256 over the raw request body with the
shared secret from ARGUS_WEBHOOK_SECRET. Requests without a valid signature
are rejected with 401 before the body is parsed.

Event type mapping (Argus → internal):
  cve_published              → intel.cve_published
  epss_changed               → intel.epss_changed
  exploit_availability_changed → intel.exploit_availability_changed
  rule_pack_updated          → intel.rule_pack_updated
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from src.shared.event_publisher import get_event_publisher
from src.shared.event_types.intel import (
    CvePublishedEvent,
    EpssChangedEvent,
    ExploitAvailabilityChangedEvent,
    RulePackUpdatedEvent,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/argus", tags=["argus"])

# Argus event types we handle; unknown types are logged and ignored.
_HANDLED_EVENT_TYPES = frozenset({
    "cve_published",
    "epss_changed",
    "exploit_availability_changed",
    "rule_pack_updated",
})


@router.post("/webhook")
async def argus_webhook(request: Request):
    """Receive an intel push event from Argus.

    Validates the HMAC-SHA256 signature before processing. Unknown event
    types are acknowledged (200) but not acted upon — this avoids Argus
    retrying on webhook expansion without crashing older Aegis instances.
    """
    body = await request.body()
    signature = request.headers.get("X-Argus-Signature", "")
    secret = os.getenv("ARGUS_WEBHOOK_SECRET", "")

    if not verify_signature(body, signature, secret):
        logger.warning("argus.webhook: signature verification failed; rejecting request")
        raise HTTPException(status_code=401, detail="Invalid or missing signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error("argus.webhook: malformed JSON body: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    event_type = payload.get("event_type", "")
    org_id = payload.get("org_id", "")
    data = payload.get("data", {})

    if event_type not in _HANDLED_EVENT_TYPES:
        logger.info("argus.webhook: received unknown event_type=%s; ignoring", event_type)
        return {"status": "ok", "handled": False}

    _publish_intel_event(event_type, org_id, data)
    logger.info("argus.webhook: published intel event type=%s org=%s", event_type, org_id)
    return {"status": "ok", "handled": True}


def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature of the raw request body.

    The expected format is "sha256=<hex-digest>". Returns False on any
    mismatch or when the secret is not configured — callers must treat
    an unconfigured secret as a verification failure.
    """
    if not secret:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")


# ── internal helpers ──────────────────────────────────────────────────────────

def _publish_intel_event(event_type: str, org_id: str, data: dict) -> None:
    """Translate an Argus event into the corresponding internal intel event."""
    publisher = get_event_publisher()

    if event_type == "cve_published":
        publisher.publish(CvePublishedEvent(
            org_id=org_id,
            source_component="argus.webhook",
            payload=data,
        ))
    elif event_type == "epss_changed":
        publisher.publish(EpssChangedEvent(
            org_id=org_id,
            source_component="argus.webhook",
            payload=data,
        ))
    elif event_type == "exploit_availability_changed":
        publisher.publish(ExploitAvailabilityChangedEvent(
            org_id=org_id,
            source_component="argus.webhook",
            payload=data,
        ))
    elif event_type == "rule_pack_updated":
        publisher.publish(RulePackUpdatedEvent(
            org_id=org_id,
            source_component="argus.webhook",
            payload=data,
        ))
