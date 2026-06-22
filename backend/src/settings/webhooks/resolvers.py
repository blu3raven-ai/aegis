"""GraphQL resolver for the webhook endpoints admin list view.

Mirrors GET /api/v1/settings/webhooks. Gated on MANAGE_SETTINGS.
"""
from __future__ import annotations

from typing import Optional

import strawberry

from src.settings.webhooks.service import PROVIDERS, list_endpoints
from src.db.helpers import run_db


@strawberry.type
class WebhookEndpointEntry:
    id: str
    provider: str
    masked_secret: str
    created_at: Optional[str]
    updated_at: Optional[str]
    rotated_at: Optional[str]


@strawberry.type
class WebhookEndpointListResponse:
    endpoints: list[WebhookEndpointEntry]
    providers: list[str]


_DEFAULT_ORG_ID = "default"


def webhook_endpoints() -> WebhookEndpointListResponse:
    async def _q(session):
        return {
            "endpoints": await list_endpoints(session, org_id=_DEFAULT_ORG_ID),
            "providers": list(PROVIDERS),
        }

    payload = run_db(_q)
    return WebhookEndpointListResponse(
        endpoints=[
            WebhookEndpointEntry(
                id=str(e.get("id", "")),
                provider=str(e.get("provider", "")),
                masked_secret=str(e.get("last4") or ""),
                created_at=e.get("createdAt"),
                updated_at=e.get("updatedAt"),
                rotated_at=e.get("rotatedAt"),
            )
            for e in payload["endpoints"]
        ],
        providers=list(payload["providers"]),
    )
