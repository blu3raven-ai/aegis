"""License management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS, VIEW_SETTINGS
from src.license.keys import EMBEDDED_PUBLIC_KEY, LicenseError, decode_license
from src.license.store import remove_license_key, write_license_key
from src.license.types import TIER_LIMITS, Tier

router = APIRouter(prefix="/api/v1/license", tags=["license"])


class ActivateRequest(BaseModel):
    key: str


@router.get("/status")
async def get_license_status(
    request: Request,
    _: None = Depends(Permission(VIEW_SETTINGS)),
):
    """View the license tier, addon set, usage counts, and license claims.

    Gated on VIEW_SETTINGS (least-privilege — admins implicitly have it
    via manage_settings → view_settings). The data is low-sensitivity but
    informative (user/team/runner counts plus org name from the claim),
    so we don't leave it open to a base viewer.
    """
    tier = getattr(request.state, "tier", Tier.COMMUNITY)
    claims = getattr(request.state, "license_claims", None)
    limits = TIER_LIMITS[tier]

    # Collect current usage counts
    from src.auth.workspace.users_router import list_users_internal
    from src.sources.store import list_connections
    from src.authz.teams.service import list_teams
    from src.authz.roles.service import list_roles
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
async def activate_license(
    body: ActivateRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
):
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
async def remove_license(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
):
    remove_license_key()
    tier = Tier.COMMUNITY
    limits = TIER_LIMITS[tier]
    return {
        "tier": tier.value,
        "limits": limits,
    }
