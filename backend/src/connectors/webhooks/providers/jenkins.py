"""Jenkins webhook receiver.

Accepts notifications from the Jenkins Notification Plugin — a build ran
on commit X of repo Y, so Aegis should scan that commit. Jenkins does not
sign the body; the subscription is authenticated via a shared bearer token
on the ``Authorization: Bearer <token>`` header (matching the Generic
Webhook Trigger plugin convention). Verified before the body is parsed —
401 on failure.

Secret resolution is DB-first via :func:`match_webhook_secret`; if no
``webhook_endpoints`` row matches, the receiver falls back to the
``JENKINS_WEBHOOK_SECRET`` env-var so bootstrap deployments keep working.

Only the ``STARTED`` and ``FINALIZED + status=SUCCESS`` phases trigger a
scan. ``COMPLETED``, ``ABORTED`` and ``FAILURE`` payloads are accepted
quietly (200 ignored) so misconfigured subscriptions surface as visible
no-ops rather than 4xx noise.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from src.connectors.base import BaseIngester, TestResult
from src.connectors.registry import register_connector
from src.settings.webhooks.service import match_webhook_secret
from src.connectors.webhooks.healthcheck import webhook_test_result
from src.connectors.webhooks.secret_resolver import verify_with_stored_secret
from src.connectors.webhooks.signature import verify_bearer_token
from src.db.engine import get_session
from src.shared.event_publisher import get_event_publisher
from src.connectors.webhooks.normalizer import normalize_jenkins_build


@register_connector
class JenkinsIngester(BaseIngester):
    """Inbound Jenkins webhook ingester — Notification Plugin build events."""

    id = "jenkins-webhook"
    name = "Jenkins Webhook"
    category = "ci"
    description = "Receive build notifications from the Jenkins Notification Plugin"
    version = "v1.0"
    status = "stable"
    icon_slug = "jenkins"

    def signature_header(self) -> str:
        return "Authorization"

    def verify_signature(self, body: bytes, header: str) -> bool:
        """Standalone caller; the FastAPI route uses ``match_webhook_secret``
        directly to avoid a double DB lookup. ``body`` is accepted for
        interface parity with the HMAC providers and ignored — Jenkins
        authenticates with a shared bearer token on the header."""
        del body
        return verify_with_stored_secret(
            provider="jenkins",
            verify=lambda secret: verify_bearer_token(secret, header),
        )

    def normalize(self, body: bytes) -> object:
        """Return the parsed JSON payload. Provider-specific event dispatch
        happens in the FastAPI route — see jenkins_webhook() below."""
        return json.loads(body)

    def test(self) -> TestResult:
        return webhook_test_result(provider="jenkins", env_var="JENKINS_WEBHOOK_SECRET")


_INGESTER = JenkinsIngester()

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/jenkins", tags=["integrations"], include_in_schema=False)


def _should_dispatch(build: dict) -> bool:
    """A Jenkins build payload triggers a scan only when the commit is fully
    available and the build state is stable enough that a scan would be
    meaningful. STARTED carries the commit and a clean working tree; the
    FINALIZED + SUCCESS pair re-affirms the same commit after the build
    passed. Other phase/status combinations are accepted as no-ops."""
    phase = (build or {}).get("phase")
    if phase == "STARTED":
        return True
    if phase == "FINALIZED" and (build or {}).get("status") == "SUCCESS":
        return True
    return False


@router.post("/webhook")
async def jenkins_webhook(
    request: Request,
    authorization: str = Header(...),
):
    """Receive an authenticated webhook event from Jenkins."""
    body = await request.body()

    def _verify(secret: str) -> bool:
        return verify_bearer_token(secret, authorization)

    async with get_session() as session:
        matched = await match_webhook_secret(session, provider="jenkins", verify=_verify)
    if matched is None:
        logger.warning("jenkins.webhook: bearer token verification failed")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error("jenkins.webhook: malformed JSON body: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    build = payload.get("build") or {}
    if not _should_dispatch(build):
        logger.info(
            "jenkins.webhook: ignoring phase=%s status=%s",
            build.get("phase"),
            build.get("status"),
        )
        return {"status": "ignored", "reason": f"phase {build.get('phase')!s}"}

    scm = build.get("scm") or {}
    if not scm.get("commit"):
        logger.info("jenkins.webhook: ignoring payload with no scm.commit")
        return {"status": "ignored", "reason": "missing scm.commit"}

    event = normalize_jenkins_build(payload)
    get_event_publisher().publish(event)
    logger.info(
        "jenkins.webhook: published event_type=%s event_id=%s",
        event.event_type,
        event.event_id,
    )
    return {"status": "accepted", "event_id": event.event_id}
