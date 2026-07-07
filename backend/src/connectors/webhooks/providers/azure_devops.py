"""Azure DevOps Services webhook receiver.

Accepts ``git.push``, ``git.pullrequest.created`` and ``git.pullrequest.updated``
events from Azure DevOps Services subscriptions. Authentication uses the
Basic-auth credentials configured on the service-hook subscription —
ADO sends them as ``Authorization: Basic <base64(user:password)>`` on
every POST and the body is plain JSON, with the event-type carried in
the ``eventType`` field of the body (not a header). Verified before the
body is parsed — 401 on failure.

Secret resolution is DB-first via :func:`match_webhook_secret`; if no
``webhook_endpoints`` row matches, the receiver falls back to the
``AZURE_DEVOPS_WEBHOOK_SECRET`` env-var so bootstrap deployments keep
working.

This receiver targets Azure DevOps Services (cloud); on-prem ADO Server
divergence is intentionally not handled here.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Header, HTTPException, Request

from src.connectors.base import BaseIngester, TestResult
from src.connectors.registry import register_connector
from src.settings.webhooks.service import match_webhook_secret
from src.connectors.webhooks.healthcheck import webhook_test_result
from src.connectors.webhooks.ingest_guard import parse_json_object, read_guarded_body
from src.connectors.webhooks.secret_resolver import verify_with_stored_secret
from src.connectors.webhooks.signature import verify_basic_auth
from src.db.engine import get_session
from src.shared.event_publisher import get_event_publisher
from src.connectors.webhooks.normalizer import normalize_azure_pr, normalize_azure_push


@register_connector
class AzureDevOpsIngester(BaseIngester):
    """Inbound Azure DevOps Services webhook ingester — git.push and git.pullrequest.* events."""

    id = "azure-devops-webhook"
    name = "Azure DevOps Webhook"
    category = "ci"
    description = "Receive git.push and git.pullrequest events from Azure DevOps Services"
    version = "v1.0"
    status = "stable"
    icon_slug = "azuredevops"

    def signature_header(self) -> str:
        return "Authorization"

    def verify_signature(self, body: bytes, header: str) -> bool:
        """Standalone caller; the FastAPI route uses ``match_webhook_secret``
        directly to avoid a double DB lookup. ``body`` is accepted for
        interface parity with the HMAC providers and ignored — Azure DevOps
        authenticates the subscription via Basic auth on the header."""
        del body
        return verify_with_stored_secret(
            provider="azure_devops",
            verify=lambda secret: verify_basic_auth(secret, header),
        )

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route — see azure_devops_webhook() below."""
        import json
        return json.loads(body)

    def test(self) -> TestResult:
        return webhook_test_result(
            provider="azure_devops", env_var="AZURE_DEVOPS_WEBHOOK_SECRET"
        )


_INGESTER = AzureDevOpsIngester()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/azure-devops", tags=["integrations"], include_in_schema=False)


@router.post("/webhook")
async def azure_devops_webhook(
    request: Request,
    authorization: str = Header(...),
):
    """Receive an authenticated webhook event from Azure DevOps Services."""
    # No reliable per-delivery id header is sent, so no replay dedup here.
    body = await read_guarded_body(request)

    def _verify(secret: str) -> bool:
        return verify_basic_auth(secret, authorization)

    async with get_session() as session:
        matched = await match_webhook_secret(session, provider="azure_devops", verify=_verify)
    if matched is None:
        logger.warning("azure_devops.webhook: basic auth verification failed")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = parse_json_object(body)

    event_type = payload.get("eventType", "")

    if event_type == "git.push":
        event = normalize_azure_push(payload)
    elif event_type == "git.pullrequest.created":
        event = normalize_azure_pr(payload, opened=True)
    elif event_type == "git.pullrequest.updated":
        event = normalize_azure_pr(payload, opened=False)
    else:
        logger.info("azure_devops.webhook: ignoring event type=%s", event_type)
        return {"status": "ignored", "reason": f"event type {event_type}"}

    if matched.org_id is not None:
        event = event.model_copy(update={"org_id": matched.org_id})
    get_event_publisher().publish(event)
    logger.info(
        "azure_devops.webhook: published event_type=%s event_id=%s authed_org=%s",
        event.event_type,
        event.event_id,
        matched.org_id,
    )
    return {"status": "accepted", "event_id": event.event_id}
