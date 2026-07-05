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

import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from src.connectors.base import BaseIngester, TestResult
from src.connectors.registry import register_connector
from src.connectors.webhooks.ingest_guard import parse_json_object, read_guarded_body
from src.connectors.webhooks.signature import verify_hmac_sha256
from src.shared.event_publisher import get_event_publisher
from src.shared.event_types.intel import (
    CvePublishedEvent,
    EpssChangedEvent,
    ExploitAvailabilityChangedEvent,
    RulePackUpdatedEvent,
)


_ARGUS_SIGNATURE_HEADER = "X-Argus-Signature"
_ARGUS_SECRET_ENV = "ARGUS_WEBHOOK_SECRET"


@register_connector
class ArgusIngester(BaseIngester):
    """Inbound Argus intel webhook ingester.

    Categorised as "intel" rather than "ci": Argus pushes CVE / EPSS / exploit
    intel into Aegis, it doesn't trigger scans. Unlike the SCM webhook
    receivers there's no per-installation DB-rotated secret today — the
    shared secret lives in ARGUS_WEBHOOK_SECRET and is validated inline
    via the kernel's verify_hmac_sha256 primitive.
    """

    id = "argus-webhook"
    name = "Argus Webhook"
    category = "intel"
    description = "Receive CVE, EPSS, and exploit-availability intel pushes from Argus"
    version = "v1.0"
    status = "stable"
    icon_slug = "argus"

    def signature_header(self) -> str:
        return _ARGUS_SIGNATURE_HEADER

    def verify_signature(self, body: bytes, header: str) -> bool:
        secret = os.getenv(_ARGUS_SECRET_ENV, "")
        return verify_hmac_sha256(body, header, secret)

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Event-type dispatch happens in
        the FastAPI route (and from there to the intel event bus) — see
        argus_webhook() below."""
        return json.loads(body)

    def test(self) -> TestResult:
        if os.getenv(_ARGUS_SECRET_ENV):
            return TestResult(ok=True, message=f"env-var {_ARGUS_SECRET_ENV}")
        return TestResult(ok=False, message=f"{_ARGUS_SECRET_ENV} is not configured")

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/argus", tags=["integrations"], include_in_schema=False)

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
    body = await read_guarded_body(request)
    signature = request.headers.get(_ARGUS_SIGNATURE_HEADER, "")
    secret = os.getenv(_ARGUS_SECRET_ENV, "")

    if not verify_hmac_sha256(body, signature, secret):
        logger.warning("argus.webhook: signature verification failed; rejecting request")
        raise HTTPException(status_code=401, detail="Invalid or missing signature")

    payload = parse_json_object(body)

    event_type = payload.get("event_type", "")
    org_id = payload.get("org_id", "")
    data = payload.get("data", {})

    if event_type not in _HANDLED_EVENT_TYPES:
        logger.info("argus.webhook: received unknown event_type=%s; ignoring", event_type)
        return {"status": "ok", "handled": False}

    _publish_intel_event(event_type, org_id, data)
    logger.info("argus.webhook: published intel event type=%s org=%s", event_type, org_id)
    return {"status": "ok", "handled": True}



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
