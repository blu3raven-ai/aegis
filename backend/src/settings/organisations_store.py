from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Literal, cast

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from src.db.helpers import run_db
from src.db.models import Team, TeamMember, TeamRepository, TeamContainerImage
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
        "repositories": [
            {"org": r.org, "repo": r.repo, "source": r.source or "manual"}
            for r in team.repositories
        ],
        "containerImages": [
            {"image": ci.image, "source": ci.source or "manual"}
            for ci in team.container_images
        ],
        "createdAt": _dt_to_iso(team.created_at) or now,
        "updatedAt": _dt_to_iso(team.updated_at) or now,
    }


def _eager_team_query():
    return select(Team).options(
        selectinload(Team.members),
        selectinload(Team.repositories),
        selectinload(Team.container_images),
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


def _repo_key(repo: dict[str, str]) -> tuple[str, str]:
    return (repo["org"].lower(), repo["repo"].lower())


def _repo_key_model(repo: TeamRepository) -> tuple[str, str]:
    return (repo.org.lower(), repo.repo.lower())


def _image_key(image: dict[str, str]) -> str:
    return image["image"].lower()


def add_repository(team_id: str, repository: str, source: str = "manual") -> dict[str, Any]:
    repo = normalize_repository(repository)
    if source not in ATTACHMENT_SOURCES:
        raise OrganisationValidationError(f"Invalid repository source: {source}")

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        key = (repo["org"].lower(), repo["repo"].lower())
        if key not in {_repo_key_model(r) for r in team.repositories}:
            team.repositories.append(TeamRepository(team_id=team_id, org=repo["org"], repo=repo["repo"], source=source))
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _team_to_dict(team)

    return run_db(_query)


def remove_repository(team_id: str, org: str, repo: str) -> dict[str, Any]:
    repo_value = normalize_repository(f"{org}/{repo}")
    target = (repo_value["org"].lower(), repo_value["repo"].lower())

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        team.repositories = [r for r in team.repositories if _repo_key_model(r) != target]
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _team_to_dict(team)

    return run_db(_query)


def add_container_image(team_id: str, image: str) -> dict[str, Any]:
    normalized = normalize_container_image(image)

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        if normalized["image"].lower() not in {ci.image.lower() for ci in team.container_images}:
            team.container_images.append(TeamContainerImage(team_id=team_id, image=normalized["image"]))
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _team_to_dict(team)

    return run_db(_query)


def remove_container_image(team_id: str, image: str) -> dict[str, Any]:
    normalized = normalize_container_image(image)
    target = normalized["image"].lower()

    async def _query(session):
        result = await session.execute(_eager_team_query().where(Team.id == team_id))
        team = result.scalars().first()
        if not team:
            raise OrganisationNotFoundError("Team not found.")
        team.container_images = [ci for ci in team.container_images if ci.image.lower() != target]
        team.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _team_to_dict(team)

    return run_db(_query)


def can_act_on_repository(user_id: str, global_role: str | None, permission: str, org: str, repo: str) -> bool:
    from src.settings.router import has_role_permission
    if has_role_permission(global_role, None, "manage_access_scope"):
        return True

    async def _query(session):
        result = await session.execute(_eager_team_query())
        return any(
            any(m.user_id == user_id for m in team.members)
            for team in result.scalars().all()
            if (org.lower(), repo.lower()) in {_repo_key_model(r) for r in team.repositories}
        )

    return run_db(_query)


def can_act_on_container_image(user_id: str, global_role: str | None, permission: str, image: str) -> bool:
    from src.settings.router import has_role_permission
    if has_role_permission(global_role, None, "manage_access_scope"):
        return True

    async def _query(session):
        result = await session.execute(_eager_team_query())
        return any(
            any(m.user_id == user_id for m in team.members)
            for team in result.scalars().all()
            if image.strip().lower() in {ci.image.lower() for ci in team.container_images}
        )

    return run_db(_query)


def apply_github_sync_preview(preview: dict[str, Any], actor_user_id: str | None = None) -> None:
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

            seen_repos: set[tuple[str, str]] = set()
            for r in t_create.get("repositoriesToAdd", []):
                key = (r["org"].lower(), r["repo"].lower())
                if key not in seen_repos:
                    seen_repos.add(key)
                    session.add(TeamRepository(team_id=new_team.id, org=r["org"], repo=r["repo"], source="github"))

            seen_images: set[str] = set()
            for i in t_create.get("containerImagesToAdd", []):
                img = i["image"].lower()
                if img not in seen_images:
                    seen_images.add(img)
                    session.add(TeamContainerImage(team_id=new_team.id, image=i["image"], source="github"))

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

            # Remove repositories
            remove_repos = {(r["org"].lower(), r["repo"].lower()) for r in t_update.get("repositoriesToRemove", [])}
            team.repositories = [r for r in team.repositories if _repo_key_model(r) not in remove_repos]

            # Add repositories
            existing_repos = {_repo_key_model(r) for r in team.repositories}
            for r in t_update.get("repositoriesToAdd", []):
                key = (r["org"].lower(), r["repo"].lower())
                if key not in existing_repos:
                    team.repositories.append(TeamRepository(team_id=team.id, org=r["org"], repo=r["repo"], source="github"))

            # Remove container images
            remove_images = {i["image"].lower() for i in t_update.get("containerImagesToRemove", [])}
            team.container_images = [ci for ci in team.container_images if ci.image.lower() not in remove_images]

            # Add container images
            existing_images = {ci.image.lower() for ci in team.container_images}
            for i in t_update.get("containerImagesToAdd", []):
                if i["image"].lower() not in existing_images:
                    team.container_images.append(TeamContainerImage(team_id=team.id, image=i["image"], source="github"))

        await session.flush()

    run_db(_query)
