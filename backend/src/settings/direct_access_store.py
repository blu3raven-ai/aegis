from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Literal

from sqlalchemy import select, func

from src.db.helpers import run_db
from src.db.models import DirectGrant
from src.shared.paths import now_iso as _now_iso


def _grant_to_dict(grant: DirectGrant) -> dict[str, Any]:
    return {
        "userId": grant.user_id,
        "resourceType": grant.resource_type,
        "resourceKey": f"{grant.org}/{grant.resource_name}" if grant.org else grant.resource_name,
        "source": grant.source or "manual-direct",
        "createdAt": (
            grant.granted_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if grant.granted_at else _now_iso()
        ),
    }


def user_has_direct_repository_access(grants: list[dict[str, Any]], user_id: str, org: str, repo: str) -> bool:
    key = f"{org}/{repo}".lower()
    for grant in grants:
        if (
            grant.get("userId") == user_id
            and grant.get("resourceType") == "repository"
            and grant.get("resourceKey", "").lower() == key
        ):
            return True
    return False


def list_direct_grants() -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(select(DirectGrant))
        return [_grant_to_dict(g) for g in result.scalars().all()]

    return run_db(_query)


def add_direct_grant(
    user_id: str,
    resource_type: Literal["repository", "containerImage"],
    resource_key: str,
    source: Literal["github-direct", "manual-direct"],
) -> None:
    # Parse org/resource from resource_key
    parts = resource_key.split("/", 1)
    org = parts[0] if len(parts) > 1 else ""
    resource_name = parts[1] if len(parts) > 1 else parts[0]

    async def _query(session):
        # Check for existing grant (dedup)
        result = await session.execute(
            select(DirectGrant).where(
                DirectGrant.user_id == user_id,
                DirectGrant.resource_type == resource_type,
                func.lower(DirectGrant.org) == org.lower(),
                func.lower(DirectGrant.resource_name) == resource_name.lower(),
            )
        )
        existing = result.scalars().first()
        if existing:
            existing.source = source
        else:
            session.add(DirectGrant(
                id=f"dg_{secrets.token_hex(8)}",
                user_id=user_id,
                org=org,
                resource_type=resource_type,
                resource_name=resource_name,
                source=source,
                granted_at=datetime.now(timezone.utc),
            ))

    run_db(_query)


def remove_direct_grant(user_id: str, resource_type: str, resource_key: str) -> None:
    parts = resource_key.split("/", 1)
    org = parts[0] if len(parts) > 1 else ""
    resource_name = parts[1] if len(parts) > 1 else parts[0]

    async def _query(session):
        result = await session.execute(
            select(DirectGrant).where(
                DirectGrant.user_id == user_id,
                DirectGrant.resource_type == resource_type,
                func.lower(DirectGrant.org) == org.lower(),
                func.lower(DirectGrant.resource_name) == resource_name.lower(),
            )
        )
        for grant in result.scalars().all():
            await session.delete(grant)

    run_db(_query)
