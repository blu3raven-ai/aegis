"""Unified /api/v1/sources REST surface.

Hosts the remaining REST endpoints under /api/v1/sources after the read
surface migrated to GraphQL (see src/sources/resolvers.py). What
stays here:
  - external GitHub proxies (/repos/search, /images/search) — query-by-name
    lookups against the upstream GitHub API that don't fit GraphQL
  - manual asset registration (/manual) — the connection-less counterpart
    to repos/search and images/search
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.assets.grants import auto_grant_to_uploader
from src.assets.refs import image_ref, repo_ref
from src.assets.service import upsert_asset
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS, MANAGE_SOURCES, VIEW_SETTINGS
from src.db.engine import async_session_factory
from src.settings.general.schemas import RateLimitResponse
from src.shared.config import get_token_for_org, read_app_config
from src.shared.github import GitHubApiError, fetch_org_repos, fetch_rate_limit, github_fetch

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


async def _db():
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


def _user_id(request: Request) -> str:
    user_id = getattr(request.state, "user_sub", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user_id


class ManualRepoUploadRequest(BaseModel):
    type: Literal["repo"]
    source_type: str
    owner: str
    name: str


class ManualImageUploadRequest(BaseModel):
    type: Literal["image"]
    registry: str
    image: str
    tag: str = ""


class ManualUploadResponse(BaseModel):
    asset_id: str
    external_ref: str


@router.post("/manual", response_model=ManualUploadResponse)
async def manual_upload(
    request: Request,
    payload: ManualRepoUploadRequest | ManualImageUploadRequest,
    db: AsyncSession = Depends(_db),
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> ManualUploadResponse:
    user_id = _user_id(request)
    if payload.type == "repo":
        ref = repo_ref(payload.source_type, payload.owner, payload.name)
        display = f"{payload.owner}/{payload.name}"
    else:
        ref = image_ref(payload.registry, payload.image, payload.tag)
        display = f"{payload.image}:{payload.tag or 'latest'}"
    try:
        asset_id = await upsert_asset(
            db, type=payload.type, source="manual_upload",
            external_ref=ref, display_name=display,
            metadata={"uploaded_by": user_id},
        )
        await auto_grant_to_uploader(db, asset_id=asset_id, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ManualUploadResponse(asset_id=asset_id, external_ref=ref)


def _matches_query(value: str, q: str) -> bool:
    return not q or q.lower() in value.lower()


@router.get("/repos/search", summary="Search configured GitHub org repositories")
async def search_repositories(
    request: Request,
    org: str | None = None,
    q: str = "",
    _: None = Depends(Permission(VIEW_SETTINGS)),
) -> JSONResponse:
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


@router.get("/images/search", summary="Search configured GitHub org container images")
async def search_container_images(
    request: Request,
    org: str | None = None,
    q: str = "",
    _: None = Depends(Permission(VIEW_SETTINGS)),
) -> JSONResponse:
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


@router.get("/github/{org}/rate-limit", response_model=RateLimitResponse)
async def get_github_rate_limit(
    request: Request,
    org: str,
    pat: str | None = None,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> RateLimitResponse:
    token = (pat or "").strip() or get_token_for_org(org)
    if not token:
        raise HTTPException(status_code=404, detail=f"No PAT saved for {org}. Enter a token first.")

    try:
        core = await fetch_rate_limit(token)
    except GitHubApiError as e:
        if e.status == 401:
            raise HTTPException(status_code=400, detail="PAT is invalid or expired.")
        if e.status == 403:
            raise HTTPException(status_code=400, detail="GitHub denied the rate limit check for this PAT.")
        raise HTTPException(status_code=502, detail=f"GitHub rate limit check failed ({e.status}).")

    reset_ts = core.get("reset") or 0
    used = core.get("used")
    limit = core.get("limit") or 0
    remaining = core.get("remaining") or 0
    if used is None:
        used = max(0, limit - remaining)

    return RateLimitResponse(
        remaining=remaining,
        limit=limit,
        reset_at=datetime.fromtimestamp(reset_ts, tz=timezone.utc).isoformat(),
        used=used,
    )
