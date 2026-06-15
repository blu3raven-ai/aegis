from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.settings.organisations_store import (
    OrganisationStoreError,
    OrganisationNotFoundError,
    OrganisationValidationError,
    add_container_image,
    add_repository,
    build_sharing_index,
    create_team,
    delete_team,
    list_teams,
    remove_container_image,
    remove_member,
    remove_repository,
    update_team,
    upsert_member,
)
from src.settings.direct_access_store import (
    list_direct_grants as store_list_direct_grants,
    add_direct_grant as store_add_direct_grant,
    remove_direct_grant as store_remove_direct_grant,
)
from src.settings.router import require_permission
from src.settings.audit import record_event
from src.settings.schemas import DirectGrantRequest
from src.shared.config import get_token_for_org, read_app_config
from src.shared.github import fetch_org_repos, github_fetch, check_token_permissions

organisations_router = APIRouter(prefix="/api/v1/settings", tags=["organisations"])


class TeamRequest(BaseModel):
    name: str
    description: str = ""


class MemberRequest(BaseModel):
    userId: str


class RepositoryRequest(BaseModel):
    repository: str


class ImageRequest(BaseModel):
    image: str


def _json_error(error: Exception, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=status_code)


def _actor_id(request: Request) -> str | None:
    value = getattr(request.state, "user_sub", None)
    return str(value) if value else None


def _require_team_management(request: Request, team_id: str) -> None:
    require_permission(request, "manage_organisations")


def _matches_query(value: str, q: str) -> bool:
    return not q or q.lower() in value.lower()


@organisations_router.get("/organisations")
def get_organisations(request: Request) -> JSONResponse:
    require_permission(request, "view_settings")
    try:
        user_id = _actor_id(request)
        sharing_index = build_sharing_index(user_id) if user_id else {}
        teams = list_teams()

        enriched_teams = []
        for team in teams:
            is_member = sharing_index.get(team["id"], False)
            enriched_teams.append({
                **team,
                "isShared": is_member,
            })

        return JSONResponse({"teams": enriched_teams})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)


@organisations_router.post("/organisations")
def post_organisation(body: TeamRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_organisations")
    # License: teams feature gate
    from src.license.limits import check_feature
    check_feature(request, "teams")
    try:
        actor_id = _actor_id(request)
        team = create_team(body.model_dump(), actor_user_id=actor_id)
        record_event(
            action="team.created",
            actor_user_id=actor_id,
            target=team["id"],
            metadata={"name": team["name"]},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.patch("/organisations/{team_id}")
def patch_organisation(team_id: str, body: TeamRequest, request: Request) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = update_team(team_id, body.model_dump())
        record_event(
            action="team.updated",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"name": team["name"]},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.delete("/organisations/{team_id}")
def delete_organisation(team_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_organisations")
    try:
        actor_id = _actor_id(request)
        delete_team(team_id)
        record_event(
            action="team.deleted",
            actor_user_id=actor_id,
            target=team_id,
        )
        return JSONResponse({"ok": True})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.post("/organisations/{team_id}/members")
def post_member(team_id: str, body: MemberRequest, request: Request) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = upsert_member(team_id, body.userId)
        record_event(
            action="team.member.added",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"userId": body.userId},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.delete("/organisations/{team_id}/members/{user_id}")
def delete_member(team_id: str, user_id: str, request: Request) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = remove_member(team_id, user_id)
        record_event(
            action="team.member.removed",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"userId": user_id},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.post("/organisations/{team_id}/repositories")
def post_repository(team_id: str, body: RepositoryRequest, request: Request) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = add_repository(team_id, body.repository)
        record_event(
            action="team.repository.added",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"repository": body.repository},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.delete("/organisations/{team_id}/repositories/{org}/{repo}")
def delete_repository(team_id: str, org: str, repo: str, request: Request) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = remove_repository(team_id, org, repo)
        record_event(
            action="team.repository.removed",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"org": org, "repo": repo},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.post("/organisations/{team_id}/container-images")
def post_container_image(team_id: str, body: ImageRequest, request: Request) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = add_container_image(team_id, body.image)
        record_event(
            action="team.image.added",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"image": body.image},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.delete("/organisations/{team_id}/container-images")
def delete_container_image(team_id: str, request: Request, image: str = Query(...)) -> JSONResponse:
    try:
        _require_team_management(request, team_id)
        actor_id = _actor_id(request)
        team = remove_container_image(team_id, image)
        record_event(
            action="team.image.removed",
            actor_user_id=actor_id,
            target=team_id,
            metadata={"image": image},
        )
        return JSONResponse({"ok": True, "team": team})
    except OrganisationStoreError as exc:
        return _json_error(exc, status_code=500)
    except OrganisationNotFoundError as exc:
        return _json_error(exc, status_code=404)
    except OrganisationValidationError as exc:
        return _json_error(exc)


@organisations_router.get("/resources/repositories")
async def search_repositories(request: Request, org: str | None = None, q: str = "") -> JSONResponse:
    require_permission(request, "view_settings")

    config = read_app_config()
    org_entries = config.get("github", {}).get("orgs") or []
    orgs = [str(entry.get("name") or "") for entry in org_entries if entry.get("name")]

    if org:
        if org not in orgs:
            return JSONResponse({"repositories": [], "error": f"Organization {org} is not configured."})
        token = get_token_for_org(org)
        if not token:
            return JSONResponse({"repositories": [], "error": f"No GitHub token configured for {org}."})
        search_targets = [org]
    else:
        search_targets = orgs

    if not search_targets:
        return JSONResponse({"repositories": [], "error": "No valid organizations found for search."})

    import asyncio

    async def fetch_one(target_org: str):
        token = get_token_for_org(target_org)
        if not token:
            return []
        try:
            repos = await fetch_org_repos(target_org, token)
            return [
                {"org": target_org, "repo": str(repo.get("name") or ""), "fullName": str(repo.get("full_name") or f"{target_org}/{repo.get('name')}")}
                for repo in repos
                if repo.get("name") and not repo.get("archived") and not repo.get("disabled") and _matches_query(str(repo.get("full_name") or ""), q)
            ]
        except Exception:
            return []

    results = await asyncio.gather(*(fetch_one(target) for target in search_targets))

    all_suggestions = []
    for r in results:
        all_suggestions.extend(r)

    return JSONResponse({"repositories": all_suggestions[:50]})


@organisations_router.get("/resources/container-images")
async def search_container_images(request: Request, org: str | None = None, q: str = "") -> JSONResponse:
    require_permission(request, "view_settings")

    config = read_app_config()
    org_entries = config.get("github", {}).get("orgs") or []
    orgs = [str(entry.get("name") or "") for entry in org_entries if entry.get("name")]

    if org:
        if org not in orgs:
            return JSONResponse({"images": [], "error": f"Organization {org} is not configured."})
        token = get_token_for_org(org)
        if not token:
            return JSONResponse({"images": [], "error": f"No GitHub token configured for {org}."})
        search_targets = [org]
    else:
        search_targets = orgs

    if not search_targets:
        return JSONResponse({"images": [], "error": "No valid organizations found for search."})

    import asyncio

    async def fetch_one(target_org: str):
        token = get_token_for_org(target_org)
        if not token:
            return []
        try:
            packages, _ = await github_fetch(
                f"/orgs/{target_org}/packages",
                token,
                {"package_type": "container", "per_page": "100"},
            )
            results = []
            for package in packages if isinstance(packages, list) else []:
                name = str(package.get("name") or "")
                image = f"ghcr.io/{target_org}/{name}" if name else ""
                if image and _matches_query(image, q):
                    results.append({"image": image, "name": name})
            return results
        except Exception:
            return []

    results = await asyncio.gather(*(fetch_one(target) for target in search_targets))

    all_images = []
    for r in results:
        all_images.extend(r)

    return JSONResponse({"images": all_images[:50]})


@organisations_router.get("/direct-grants")
def get_direct_grants(request: Request) -> JSONResponse:
    require_permission(request, "manage_organisations")
    return JSONResponse({"grants": store_list_direct_grants()})


@organisations_router.post("/direct-grants")
def post_direct_grant(body: DirectGrantRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_organisations")
    actor_id = _actor_id(request)
    store_add_direct_grant(
        user_id=body.userId,
        asset_id=body.assetId,
        source="manual-direct",
    )

    record_event(
        action="direct_grant.added",
        actor_user_id=actor_id,
        target=body.userId,
        metadata={
            "assetId": body.assetId,
            "source": "manual-direct",
        }
    )

    return JSONResponse({"ok": True})


@organisations_router.delete("/direct-grants/{user_id}/{asset_id}")
def delete_direct_grant(user_id: str, asset_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_organisations")

    actor_id = _actor_id(request)
    store_remove_direct_grant(user_id, asset_id)

    record_event(
        action="direct_grant.removed",
        actor_user_id=actor_id,
        target=user_id,
        metadata={"assetId": asset_id}
    )

    return JSONResponse({"ok": True})
