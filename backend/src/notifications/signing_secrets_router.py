"""CRUD endpoints for per-channel webhook signing secrets (Phase 44).

All endpoints sit under /api/v1/notification-channels/{id}/signing-secret and
require the manage_settings permission — the same gate used for destination
management in admin_router.py.

Raw secrets are returned exactly once on creation.  Subsequent GET calls
return only metadata (version, status, created_at, revoked_at).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from src.notifications.destination import get_destination
from src.notifications.webhook_signing import (
    create_signing_secret,
    list_signing_secrets,
    persist_raw_secret_to_channel,
    revoke_raw_secret_in_channel,
    revoke_signing_secret_version,
)
from src.settings.router import require_permission

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/notification-channels",
    tags=["webhook-signing"],
)


def _assert_webhook_dest(dest_id: int, request: Request) -> dict[str, Any]:
    """Load the destination and verify it's a webhook type, or 404/422."""
    dest = get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    if dest["destination_type"] != "webhook":
        raise HTTPException(
            status_code=422, detail="signing secrets are only supported for webhook destinations"
        )
    return dest


# ── GET /api/v1/notification-channels/{id}/signing-secret ─────────────────────

@router.get("/{dest_id}/signing-secret")
async def list_secret_versions(dest_id: int, request: Request):
    """List all secret versions for a webhook destination (no raw secrets)."""
    require_permission(request, "manage_settings")
    _assert_webhook_dest(dest_id, request)
    secrets = list_signing_secrets(dest_id)
    return {"secrets": secrets}


# ── POST /api/v1/notification-channels/{id}/signing-secret ────────────────────

@router.post("/{dest_id}/signing-secret", status_code=201)
async def rotate_secret(dest_id: int, request: Request):
    """Generate a new signing secret (rotation).

    Any existing active secret is demoted to 'rotating' and remains valid for
    the configured tolerance window so receivers can upgrade at their own pace.

    The raw secret is returned ONCE in this response and never again.
    """
    require_permission(request, "manage_settings")
    _assert_webhook_dest(dest_id, request)

    meta, raw = create_signing_secret(dest_id)
    # Persist raw value into channel config for outbound signing
    persist_raw_secret_to_channel(dest_id, meta["version"], raw)

    return {
        "secret": {
            **meta,
            "raw": raw,  # shown once only
        },
        "signing_secret_version": meta["version"],
        "notice": (
            "Save this secret — it will not be shown again. "
            "The previous secret (if any) remains valid during the rotation window."
        ),
    }


# ── DELETE /api/v1/notification-channels/{id}/signing-secret/{version} ────────

@router.delete("/{dest_id}/signing-secret/{version}", status_code=200)
async def revoke_version(dest_id: int, version: int, request: Request):
    """Immediately revoke a specific secret version.

    After revocation the key is no longer used for signing and any receiver
    that has not yet rotated will start seeing verification failures.
    """
    require_permission(request, "manage_settings")
    _assert_webhook_dest(dest_id, request)

    meta = revoke_signing_secret_version(dest_id, version)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"version {version} not found for this destination")

    # Also remove from channel config raw entries
    revoke_raw_secret_in_channel(dest_id, version)

    return {"ok": True, "revoked": meta}
