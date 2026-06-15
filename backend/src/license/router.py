"""License management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.license.keys import EMBEDDED_PUBLIC_KEY, LicenseError, decode_license
from src.license.store import read_license_key, remove_license_key, write_license_key
from src.license.types import TIER_LIMITS, Tier
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/license", tags=["license"])


class ActivateRequest(BaseModel):
    key: str


@router.get("/status")
async def get_license_status(request: Request):
    tier = getattr(request.state, "tier", Tier.COMMUNITY)
    claims = getattr(request.state, "license_claims", None)
    limits = TIER_LIMITS[tier]

    # Collect current usage counts
    from src.settings.users_router import list_users_internal
    from src.settings.sources_store import list_connections
    from src.settings.organisations_store import list_teams
    from src.settings.roles_store import list_roles
    from src.runner.registry import list_runners_with_status

    users = list_users_internal()
    active_users = sum(1 for u in users if u.get("status") != "disabled")
    source_connections = len(list_connections())
    teams = len(list_teams())
    custom_roles = sum(1 for r in list_roles() if not r.get("isSystem"))
    remote_runners = sum(1 for r in list_runners_with_status() if r.get("status") == "approved")

    addons = list(claims.addons) if claims else []

    return {
        "tier": tier.value,
        "addons": addons,
        "limits": limits,
        "usage": {
            "users": active_users,
            "source_connections": source_connections,
            "teams": teams,
            "custom_roles": custom_roles,
            "remote_runners": remote_runners,
        },
        "license": {
            "org": claims.org,
            "expiresAt": claims.expires_at,
            "licenseId": claims.license_id,
        } if claims else None,
    }


@router.post("/activate")
async def activate_license(body: ActivateRequest, request: Request):
    require_permission(request, "manage_settings")

    try:
        claims = decode_license(body.key, EMBEDDED_PUBLIC_KEY)
    except LicenseError:
        raise HTTPException(status_code=400, detail="Invalid or expired license key.")

    write_license_key(body.key)

    tier = claims.tier
    limits = TIER_LIMITS[tier]
    return {
        "tier": tier.value,
        "limits": limits,
        "license": {
            "org": claims.org,
            "expiresAt": claims.expires_at,
            "licenseId": claims.license_id,
        },
    }


@router.delete("/remove")
async def remove_license(request: Request):
    require_permission(request, "manage_settings")
    remove_license_key()
    tier = Tier.COMMUNITY
    limits = TIER_LIMITS[tier]
    return {
        "tier": tier.value,
        "limits": limits,
    }
