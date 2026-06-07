from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Literal, cast

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import selectinload

from src.db.helpers import run_db
from src.db.models import Asset, Team, TeamAsset, TeamMember
from src.shared.paths import dt_to_iso as _dt_to_iso, now_iso as _now_iso

TEAM_SOURCES = {"manual", "github"}
ATTACHMENT_SOURCES = {"manual", "github"}
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class OrganisationValidationError(ValueError):
    pass


class OrganisationNotFoundError(OrganisationValidationError):
    pass


class OrganisationStoreError(RuntimeError):
    pass


def _asset_to_dict(ta: TeamAsset) -> dict[str, Any]:
    asset = ta.asset
    return {
        "assetId": asset.id,
        "type": asset.type,
        "displayName": asset.display_name,
        "externalRef": asset.external_ref,
        "source": ta.source or "manual",
    }


def _team_to_dict(team: Team) -> dict[str, Any]:
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
        "assets": [_asset_to_dict(ta) for ta in team.assets],
        "createdAt": _dt_to_iso(team.created_at) or now,
        "updatedAt": _dt_to_iso(team.updated_at) or now,
    }


def _eager_team_query():
    return select(Team).options(
        selectinload(Team.members),
        selectinload(Team.assets).selectinload(TeamAsset.asset),
    )


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


async def _upsert_team_asset(session, team_id: str, asset_id: str, source: str) -> None:
    """Insert a TeamAsset row, ignoring conflicts on (team_id, asset_id)."""
    stmt = pg_insert(TeamAsset).values(
        team_id=team_id, asset_id=asset_id, source=source,
    ).on_conflict_do_nothing(index_elements=["team_id", "asset_id"])
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
        # Re-fetch with eager loading
        result = await session.execute(_eager_team_query().where(Team.id == team.id))
        team = result.scalars().first()
        return _team_to_dict(team)

    return run_db(_query)


def list_teams() -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(_eager_team_query())
        return [_team_to_dict(t) for t in result.scalars().all()]

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
        return _team_to_dict(team)

    return run_db(_query)


def delete_team(team_id: str) -> None:
    async def _query(session):
        team = await session.get(Team, team_id)
        if not team:
            raise OrganisationNotFoundError("Team not found.")
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
        return _team_to_dict(team)

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
        return _team_to_dict(team)

    return run_db(_query)


def add_repository(team_id: str, repository: str, source: str = "manual") -> dict[str, Any]:
    repo = normalize_repository(repository)
    if source not in ATTACHMENT_SOURCES:
        raise OrganisationValidationError(f"Invalid repository source: {source}")

    from src.assets.refs import repo_ref

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")

        external_ref = repo_ref("github", repo["org"], repo["repo"])
        asset_id = await _resolve_or_create_asset(
            session,
            external_ref=external_ref,
            asset_type="repo",
            display_name=f"{repo['org']}/{repo['repo']}",
            source="manual_upload",
        )
        await _upsert_team_asset(session, team_id=team_id, asset_id=asset_id, source=source)

        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        # Re-fetch to pick up the new TeamAsset row and its loaded asset
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        return _team_to_dict(team)

    return run_db(_query)


def remove_repository(team_id: str, org: str, repo: str) -> dict[str, Any]:
    repo_value = normalize_repository(f"{org}/{repo}")

    from src.assets.refs import repo_ref

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")

        external_ref = repo_ref("github", repo_value["org"], repo_value["repo"])
        asset_row = (await session.execute(
            select(Asset).where(Asset.external_ref == external_ref)
        )).scalar_one_or_none()

        if asset_row is not None:
            ta = next((a for a in team.assets if a.asset_id == asset_row.id), None)
            if ta is not None:
                team.assets.remove(ta)

        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        return _team_to_dict(team)

    return run_db(_query)


def add_container_image(team_id: str, image: str) -> dict[str, Any]:
    normalized = normalize_container_image(image)

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")

        external_ref = _image_to_external_ref(normalized["image"])
        asset_id = await _resolve_or_create_asset(
            session,
            external_ref=external_ref,
            asset_type="image",
            display_name=normalized["image"],
            source="manual_upload",
        )
        await _upsert_team_asset(session, team_id=team_id, asset_id=asset_id, source="manual")

        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        return _team_to_dict(team)

    return run_db(_query)


def remove_container_image(team_id: str, image: str) -> dict[str, Any]:
    normalized = normalize_container_image(image)

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")

        external_ref = _image_to_external_ref(normalized["image"])
        asset_row = (await session.execute(
            select(Asset).where(Asset.external_ref == external_ref)
        )).scalar_one_or_none()

        if asset_row is not None:
            ta = next((a for a in team.assets if a.asset_id == asset_row.id), None)
            if ta is not None:
                team.assets.remove(ta)

        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        return _team_to_dict(team)

    return run_db(_query)


def _image_to_external_ref(image: str) -> str:
    """Convert a ghcr.io/org/name image string to a canonical external_ref.

    ghcr.io/<org>/<name> → ghcr:<org>/<name>:latest
    Tag extraction is not supported here; assets ingested via this path default to latest.
    """
    from src.assets.refs import image_ref
    # Strip ghcr.io/ prefix
    without_registry = image.removeprefix("ghcr.io/")
    # No tag embedded in the string coming from manual input
    return image_ref("ghcr", without_registry, "latest")


def can_act_on_repository(user_id: str, global_role: str | None, permission: str, org: str, repo: str) -> bool:
    from src.assets.refs import repo_ref
    from src.settings.router import has_role_permission
    if has_role_permission(global_role, None, "manage_access_scope"):
        return True

    external_ref = repo_ref("github", org, repo)

    async def _query(session):
        asset_row = (await session.execute(
            select(Asset).where(Asset.external_ref == external_ref)
        )).scalar_one_or_none()
        if asset_row is None:
            return False
        result = await session.execute(_eager_team_query())
        return any(
            any(m.user_id == user_id for m in team.members)
            for team in result.scalars().all()
            if any(ta.asset_id == asset_row.id for ta in team.assets)
        )

    return run_db(_query)


def can_act_on_container_image(user_id: str, global_role: str | None, permission: str, image: str) -> bool:
    from src.settings.router import has_role_permission
    if has_role_permission(global_role, None, "manage_access_scope"):
        return True

    external_ref = _image_to_external_ref(image.strip())

    async def _query(session):
        asset_row = (await session.execute(
            select(Asset).where(Asset.external_ref == external_ref)
        )).scalar_one_or_none()
        if asset_row is None:
            return False
        result = await session.execute(_eager_team_query())
        return any(
            any(m.user_id == user_id for m in team.members)
            for team in result.scalars().all()
            if any(ta.asset_id == asset_row.id for ta in team.assets)
        )

    return run_db(_query)


def apply_github_sync_preview(preview: dict[str, Any], actor_user_id: str | None = None) -> None:
    from src.assets.refs import image_ref, repo_ref

    async def _query(session):
        now = datetime.now(timezone.utc)

        # 1. Handle teams to create
        for t_create in preview.get("teamsToCreate", []):
            new_team = Team(
                id=f"team_{secrets.token_hex(8)}",
                name=t_create["name"],
                description=t_create.get("description", ""),
                source="github",
                created_at=now,
                updated_at=now,
            )
            session.add(new_team)
            await session.flush()

            seen_members: set[str] = set()
            for m in t_create.get("membersToAdd", []):
                uid = m["userId"]
                if uid not in seen_members:
                    seen_members.add(uid)
                    session.add(TeamMember(team_id=new_team.id, user_id=uid, source="github"))

            seen_asset_refs: set[str] = set()
            for r in t_create.get("repositoriesToAdd", []):
                external_ref = repo_ref("github", r["org"], r["repo"])
                if external_ref not in seen_asset_refs:
                    seen_asset_refs.add(external_ref)
                    asset_id = await _resolve_or_create_asset(
                        session,
                        external_ref=external_ref,
                        asset_type="repo",
                        display_name=f"{r['org']}/{r['repo']}",
                        source="source_connection",
                    )
                    await _upsert_team_asset(session, team_id=new_team.id, asset_id=asset_id, source="github")

            for i in t_create.get("containerImagesToAdd", []):
                external_ref = _image_to_external_ref(i["image"])
                if external_ref not in seen_asset_refs:
                    seen_asset_refs.add(external_ref)
                    asset_id = await _resolve_or_create_asset(
                        session,
                        external_ref=external_ref,
                        asset_type="image",
                        display_name=i["image"],
                        source="source_connection",
                    )
                    await _upsert_team_asset(session, team_id=new_team.id, asset_id=asset_id, source="github")

        # 2. Handle teams to update
        for t_update in preview.get("teamsToUpdate", []):
            result = await session.execute(_eager_team_query().where(Team.id == t_update["id"]))
            team = result.scalars().first()
            if not team:
                continue

            team.name = t_update["name"]
            team.description = t_update.get("description", team.description)
            team.source = "github"
            team.updated_at = now

            # Remove members
            remove_user_ids = {m["userId"] for m in t_update.get("membersToRemove", [])}
            team.members = [m for m in team.members if m.user_id not in remove_user_ids]

            # Add members
            existing_user_ids = {m.user_id for m in team.members}
            for m in t_update.get("membersToAdd", []):
                if m["userId"] not in existing_user_ids:
                    team.members.append(TeamMember(team_id=team.id, user_id=m["userId"], source="github"))

            # Remove assets by repo external_ref
            for r in t_update.get("repositoriesToRemove", []):
                external_ref = repo_ref("github", r["org"], r["repo"])
                asset_row = (await session.execute(
                    select(Asset).where(Asset.external_ref == external_ref)
                )).scalar_one_or_none()
                if asset_row is not None:
                    team.assets = [ta for ta in team.assets if ta.asset_id != asset_row.id]

            # Add assets by repo external_ref
            existing_asset_ids = {ta.asset_id for ta in team.assets}
            for r in t_update.get("repositoriesToAdd", []):
                external_ref = repo_ref("github", r["org"], r["repo"])
                asset_id = await _resolve_or_create_asset(
                    session,
                    external_ref=external_ref,
                    asset_type="repo",
                    display_name=f"{r['org']}/{r['repo']}",
                    source="source_connection",
                )
                if asset_id not in existing_asset_ids:
                    existing_asset_ids.add(asset_id)
                    await _upsert_team_asset(session, team_id=team.id, asset_id=asset_id, source="github")

            # Remove assets by image external_ref
            for i in t_update.get("containerImagesToRemove", []):
                external_ref = _image_to_external_ref(i["image"])
                asset_row = (await session.execute(
                    select(Asset).where(Asset.external_ref == external_ref)
                )).scalar_one_or_none()
                if asset_row is not None:
                    team.assets = [ta for ta in team.assets if ta.asset_id != asset_row.id]

            # Add assets by image external_ref
            for i in t_update.get("containerImagesToAdd", []):
                external_ref = _image_to_external_ref(i["image"])
                asset_id = await _resolve_or_create_asset(
                    session,
                    external_ref=external_ref,
                    asset_type="image",
                    display_name=i["image"],
                    source="source_connection",
                )
                if asset_id not in existing_asset_ids:
                    existing_asset_ids.add(asset_id)
                    await _upsert_team_asset(session, team_id=team.id, asset_id=asset_id, source="github")

        await session.flush()

    run_db(_query)
