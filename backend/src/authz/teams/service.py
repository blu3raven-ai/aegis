from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import selectinload

from src.db.helpers import run_db
from src.db.models import Asset, Grant, Team, TeamMember
from src.shared.paths import dt_to_iso as _dt_to_iso, now_iso as _now_iso

_AssetDict = dict[str, Any]

TEAM_SOURCES = {"manual", "github"}
ATTACHMENT_SOURCES = {"manual", "github"}
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class OrganisationValidationError(ValueError):
    pass


class OrganisationNotFoundError(OrganisationValidationError):
    pass


class OrganisationStoreError(RuntimeError):
    pass


def _team_to_dict(team: Team, assets: list[_AssetDict] | None = None) -> dict[str, Any]:
    now = _now_iso()
    return {
        "id": team.id,
        "name": team.name,
        "description": team.description or "",
        "source": team.source or "manual",
        "members": [
            {"userId": m.user_id, "source": m.source or "manual"}
            for m in sorted(team.members, key=lambda m: m.user_id)
        ],
        "assets": assets or [],
        "createdAt": _dt_to_iso(team.created_at) or now,
        "updatedAt": _dt_to_iso(team.updated_at) or now,
    }


def _eager_team_query():
    return select(Team).options(selectinload(Team.members))


async def _load_team_assets(session, team_ids: list[str]) -> dict[str, list[_AssetDict]]:
    """Return assetId-enriched dicts keyed by team_id, sourced from the grants table."""
    if not team_ids:
        return {}
    rows = (await session.execute(
        select(Grant, Asset)
        .join(Asset, Grant.asset_id == Asset.id)
        .where(Grant.subject_type == "team", Grant.subject_id.in_(team_ids))
    )).all()
    result: dict[str, list[_AssetDict]] = {}
    for grant, asset in rows:
        result.setdefault(grant.subject_id, []).append({
            "assetId": str(asset.id),
            "type": asset.type,
            "displayName": asset.display_name,
            "externalRef": asset.external_ref,
            "source": grant.source or "manual",
        })
    return result


def normalize_team_name(name: str) -> str:
    value = name.strip()
    if not value:
        raise OrganisationValidationError("Team name is required.")
    return value


def normalize_repository(value: str) -> dict[str, str]:
    normalized = value.strip()
    if not _REPO_RE.match(normalized):
        raise OrganisationValidationError("Repository must use org/repo format.")
    org, repo = normalized.split("/", 1)
    return {"org": org, "repo": repo}


def normalize_container_image(value: str) -> dict[str, str]:
    normalized = value.strip()
    parts = normalized.split("/")
    if len(parts) < 3 or parts[0].lower() != "ghcr.io" or not all(parts):
        raise OrganisationValidationError("Container image must use ghcr.io/org/image format.")
    return {"image": normalized}


def _team_name_key(name: str) -> str:
    return name.strip().lower()


async def _upsert_team_grant(session, team_id: str, asset_id: str, source: str) -> None:
    stmt = pg_insert(Grant).values(
        subject_type="team", subject_id=team_id, asset_id=asset_id, source=source,
    ).on_conflict_do_update(
        index_elements=["subject_type", "subject_id", "asset_id"],
        set_={"source": source},
    )
    await session.execute(stmt)


async def _resolve_or_create_asset(
    session,
    *,
    external_ref: str,
    asset_type: str,
    display_name: str,
    source: str = "source_connection",
) -> str:
    """Return the asset_id for the given external_ref, upserting if needed."""
    from src.assets.service import upsert_asset
    from src.assets.service import AssetSource
    return await upsert_asset(
        session,
        type=cast(Any, asset_type),
        source=cast(AssetSource, source),
        external_ref=external_ref,
        display_name=display_name,
    )


def create_team(input_data: dict[str, Any], actor_user_id: str | None = None) -> dict[str, Any]:
    raw_name = input_data.get("name")
    if not isinstance(raw_name, str):
        raise OrganisationValidationError("Team name is required.")
    name = normalize_team_name(raw_name)
    description = str(input_data.get("description") or "").strip()
    source = input_data.get("source", "manual")
    if source not in TEAM_SOURCES:
        raise OrganisationValidationError(f"Invalid team source: {source}")

    async def _query(session):
        result = await session.execute(_eager_team_query())
        existing = result.scalars().all()
        if any(_team_name_key(t.name) == _team_name_key(name) for t in existing):
            raise OrganisationValidationError("Team already exists.")

        now = datetime.now(timezone.utc)
        team = Team(
            id=f"team_{secrets.token_hex(8)}",
            name=name,
            description=description,
            source=source,
            created_at=now,
            updated_at=now,
        )
        session.add(team)
        await session.flush()
        result = await session.execute(_eager_team_query().where(Team.id == team.id))
        team = result.scalars().first()
        team_assets = await _load_team_assets(session, [team.id])
        return _team_to_dict(team, team_assets.get(team.id))

    return run_db(_query)


def list_teams() -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(_eager_team_query())
        teams = result.scalars().all()
        team_assets = await _load_team_assets(session, [t.id for t in teams])
        return [_team_to_dict(t, team_assets.get(t.id)) for t in teams]

    return run_db(_query)


def list_admin_team_ids(user_id: str) -> list[str]:
    async def _query(session):
        result = await session.execute(_eager_team_query())
        return [
            t.id for t in result.scalars().all()
            if any(m.user_id == user_id for m in t.members)
        ]

    return run_db(_query)


def build_sharing_index(user_id: str) -> dict[str, bool]:
    async def _query(session):
        result = await session.execute(_eager_team_query())
        return {
            t.id: any(m.user_id == user_id for m in t.members)
            for t in result.scalars().all()
        }

    return run_db(_query)


def update_team(team_id: str, input_data: dict[str, Any]) -> dict[str, Any]:
    raw_name = input_data.get("name")
    if not isinstance(raw_name, str):
        raise OrganisationValidationError("Team name is required.")
    name = normalize_team_name(raw_name)
    description = str(input_data.get("description") or "").strip()

    async def _query(session):
        result = await session.execute(_eager_team_query())
        teams = result.scalars().all()
        team = next((t for t in teams if t.id == team_id), None)
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        if any(t.id != team_id and _team_name_key(t.name) == _team_name_key(name) for t in teams):
            raise OrganisationValidationError("Team already exists.")
        team.name = name
        team.description = description
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        team_assets = await _load_team_assets(session, [team_id])
        return _team_to_dict(team, team_assets.get(team_id))

    return run_db(_query)


def delete_team(team_id: str) -> None:
    async def _query(session):
        team = await session.get(Team, team_id)
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        # Remove grants before deletion (no DB-level FK cascade on subject_id)
        await session.execute(
            delete(Grant).where(Grant.subject_type == "team", Grant.subject_id == team_id)
        )
        await session.delete(team)

    run_db(_query)


def upsert_member(team_id: str, user_id: str, source: str = "manual") -> dict[str, Any]:
    user_id = user_id.strip()
    if not user_id:
        raise OrganisationValidationError("User is required.")
    if source not in ATTACHMENT_SOURCES:
        raise OrganisationValidationError(f"Invalid member source: {source}")

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        existing = next((m for m in team.members if m.user_id == user_id), None)
        if existing:
            existing.source = source
        else:
            team.members.append(TeamMember(team_id=team_id, user_id=user_id, source=source))
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        team_assets = await _load_team_assets(session, [team_id])
        return _team_to_dict(team, team_assets.get(team_id))

    return run_db(_query)


def remove_member(team_id: str, user_id: str) -> dict[str, Any]:
    user_id = user_id.strip()
    if not user_id:
        raise OrganisationValidationError("User is required.")

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        member = next((m for m in team.members if m.user_id == user_id), None)
        if not member:
            raise OrganisationValidationError("User is not a member of this team.")
        team.members.remove(member)
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        team_assets = await _load_team_assets(session, [team_id])
        return _team_to_dict(team, team_assets.get(team_id))

    return run_db(_query)
