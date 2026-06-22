"""REST endpoints for SBOM export — Phase 18.

SBOMs are read directly from MinIO using the runner-owned prefixes documented below.

Runner MinIO paths
------------------
Dependency SBOMs:  dependencies/{org}/{run_id}/{repo}/sbom.cdx.json
Container SBOMs:   stored in the sboms bucket at {org}/{safe_ref}/sbom.cdx.json,
                   located via the Sbom.s3_key index column.

Endpoints
---------
GET /api/v1/sboms/export?repo=owner/name&format=cyclonedx-json
    Export the latest SBOM for a repository.

GET /api/v1/sboms/export?image=sha256:…&format=cyclonedx-json
    Export the SBOM for a container image digest.

All export endpoints return the SBOM as a plain-text or JSON response whose
Content-Type mirrors the format:
  cyclonedx-json   → application/vnd.cyclonedx+json
  cyclonedx-xml    → application/xml
  spdx-json        → application/spdx+json
  spdx-tag-value   → text/plain

History and diff are served via GraphQL (Query.sbomHistory / Query.sbomDiff).

Authentication is enforced by the main.py JWT middleware. Each endpoint
additionally gates on `view_findings` and scopes the lookup to assets the
caller's team can access — out-of-scope repos/digests return 404 to avoid
leaking existence.

Path-param aliases:
  GET /api/v1/sboms/repo/{repo_id}       → equivalent to ?repo=
  GET /api/v1/sboms/image/{image_digest} → equivalent to ?image=
"""
from __future__ import annotations

import json
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Asset, Sbom
from src.sbom.exporter import SbomExporter, UnsupportedFormatError, SUPPORTED_FORMATS
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import VIEW_FINDINGS
from src.license.limits import check_feature
from src.shared.object_store import list_objects, download_json
from src.sbom.storage import download_from_minio, safe_s3_segment
from src.authz.enforcement.scope import resolve_asset_ids_from_request


router = APIRouter(prefix="/api/v1/sboms", tags=["sboms"])

_exporter = SbomExporter()

# Maps export format → HTTP Content-Type
_FORMAT_CONTENT_TYPE: dict[str, str] = {
    "cyclonedx-json": "application/vnd.cyclonedx+json",
    "cyclonedx-xml": "application/xml",
    "spdx-json": "application/spdx+json",
    "spdx-tag-value": "text/plain",
}

_FORMAT_EXT: dict[str, str] = {
    "cyclonedx-json": "cdx.json",
    "cyclonedx-xml": "cdx.xml",
    "spdx-json": "spdx.json",
    "spdx-tag-value": "spdx.tv",
}


def _resolve_format(fmt: str) -> str:
    """Normalise + validate the requested format string."""
    normalised = fmt.lower().strip()
    if normalised not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown format '{fmt}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_FORMATS))}"
            ),
        )
    return normalised


def _safe_filename(base: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", base)


def _parse_repo_id(repo_id: str) -> tuple[str, str]:
    """Split 'owner/name' into (owner, name).

    Raises HTTPException(400) if the string has no slash.
    """
    parts = repo_id.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=400,
            detail=f"repo must be in 'owner/name' format, got '{repo_id}'.",
        )
    return parts[0], parts[1]


# Query-param routes (primary — no path ambiguity)

@router.get("/export")
async def export_sbom(
    request: Request,
    repo: Annotated[str | None, Query()] = None,
    image: Annotated[str | None, Query()] = None,
    format: Annotated[str, Query()] = "cyclonedx-json",
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    """Export the latest SBOM.

    Pass exactly one of ``?repo=owner/name`` or ``?image=sha256:…``.
    """
    if repo is None and image is None:
        raise HTTPException(
            status_code=400,
            detail="Provide either ?repo=owner/name or ?image=sha256:…",
        )
    if repo is not None and image is not None:
        raise HTTPException(
            status_code=400,
            detail="?repo and ?image are mutually exclusive.",
        )

    fmt = _resolve_format(format)
    asset_ids = await resolve_asset_ids_from_request(request)

    if repo is not None:
        return _export_repo_sbom(repo, fmt, asset_ids)
    return _export_image_sbom(image, fmt, asset_ids)  # type: ignore[arg-type]


@router.get("/repo/{repo_id:path}")
async def export_repo_sbom_path(
    request: Request,
    repo_id: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    """Export the latest SBOM for a repository (path-param alias)."""
    asset_ids = await resolve_asset_ids_from_request(request)
    fmt = _resolve_format(format)
    return _export_repo_sbom(repo_id, fmt, asset_ids)


@router.get("/image/{image_digest:path}")
async def export_image_sbom_path(
    request: Request,
    image_digest: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    """Export the SBOM for a container image digest (path-param alias)."""
    asset_ids = await resolve_asset_ids_from_request(request)
    fmt = _resolve_format(format)
    return _export_image_sbom(image_digest, fmt, asset_ids)


@router.get("/download")
async def download_sbom(
    request: Request,
    org: str,
    repo: str,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    """Download a CycloneDX SBOM JSON for a specific org/repo.

    Authorization: VIEW_FINDINGS plus asset-scope intersection on the
    ``{org}/{repo}`` Asset row. Out-of-scope repos return 404 to avoid
    leaking existence. Matches the scoping model used by the sibling
    ``/export``, ``/repo/{repo_id}``, and ``/image/{image_digest}`` routes
    — the legacy query-param-only "Organization not accessible" gate that
    used to live here was replaced because it never intersected with the
    user's actual team grants.
    """
    check_feature(request, "sbom_export")

    asset_ids = await resolve_asset_ids_from_request(request)
    repo_id = f"{org}/{repo}"
    if not _repo_in_scope(repo_id, asset_ids):
        return JSONResponse({"error": "SBOM not found for this repository"}, status_code=404)

    safe_org = safe_s3_segment(org)
    safe_repo = safe_s3_segment(repo)
    key = f"{safe_org}/{safe_repo}/sbom.cdx.json"

    data = download_from_minio(key)
    if data is None:
        return JSONResponse({"error": "SBOM not found for this repository"}, status_code=404)

    filename = f"{safe_org}_{safe_repo}_sbom.cdx.json"
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Internal helpers — shared by both route styles

def _repo_in_scope(repo_id: str, asset_ids: list[str]) -> bool:
    """Return True if `repo_id` (owner/name) names an Asset the caller can see.

    Matches the repo Asset by `display_name` (the canonical owner/name form
    used everywhere in the UI) and intersects with the viewer's scope. Empty
    scope is fail-closed.
    """
    if not asset_ids:
        return False

    async def _query(session):
        result = await session.execute(
            select(Asset.id)
            .where(Asset.display_name == repo_id)
            .where(Asset.type == "repo")
            .where(Asset.id.in_(asset_ids))
            .limit(1)
        )
        return result.scalar_one_or_none()

    return run_db(_query) is not None


def _latest_repo_sbom_key(org: str, repo: str) -> str | None:
    """Return the MinIO key for the latest SBOM of a repo, or None if absent.

    Mirrors the prefix written by the runner during upload (see backend
    src/runner/router.py::presign_uploads which keys on job["jobType"]).
    Key pattern: dependencies_scanning/{org}/{run_id}/{repo}/sbom.cdx.json
    run_id = auto-{epoch_ms} — lex sort is chronological.
    """
    prefix = f"dependencies_scanning/{org}/"
    suffix = f"/{repo}/sbom.cdx.json"
    keys = [k for k in list_objects(prefix) if k.endswith(suffix)]
    if not keys:
        return None
    return sorted(keys)[-1]


def _fetch_container_sbom_by_digest(image_digest: str) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Fetch a container SBOM by image digest via the Sbom index table.

    Mirrors the blob uploaded by backend/src/containers/sbom_store.py during ingest.

    Returns: (sbom, reason, asset_id)
      - (sbom_dict, None, asset_id) on success
      - (None, "no_row", None) if image_digest not in Sbom table
      - (None, "blob_missing", asset_id) if Sbom row exists but MinIO blob is absent
    """
    async def _query(session):
        result = await session.execute(
            select(Sbom).where(Sbom.commit_sha == image_digest).limit(1)
        )
        return result.scalars().first()

    row = run_db(_query)
    if row is None:
        return None, "no_row", None
    sbom = download_from_minio(row.s3_key)
    if sbom is None:
        return None, "blob_missing", row.asset_id
    return sbom, None, row.asset_id


def _export_repo_sbom(repo_id: str, fmt: str, asset_ids: list[str]) -> Response:
    """Fetch + export the latest SBOM for a repository."""
    # Strip a trailing /history suffix that could arrive via the path alias
    # if FastAPI routing resolves to this handler instead of the history one.
    # (Defensive — should not happen with correct route ordering.)
    if repo_id.endswith("/history"):
        repo_id = repo_id[: -len("/history")]

    if not _repo_in_scope(repo_id, asset_ids):
        raise HTTPException(
            status_code=404,
            detail=f"No SBOM found for repository '{repo_id}'.",
        )

    org, repo = _parse_repo_id(repo_id)
    key = _latest_repo_sbom_key(org, repo)

    if key is None:
        raise HTTPException(
            status_code=404,
            detail=f"No SBOM found for repository '{repo_id}'.",
        )

    sbom = download_json(key)
    if sbom is None:
        raise HTTPException(
            status_code=404,
            detail=f"SBOM blob not found for repository '{repo_id}'.",
        )

    return _render(sbom, fmt, repo_id)


def _export_image_sbom(image_digest: str, fmt: str, asset_ids: list[str]) -> Response:
    """Fetch + export the SBOM for a container image digest."""
    sbom, reason, asset_id = _fetch_container_sbom_by_digest(image_digest)

    # 404 (not 403) when the caller can't see the asset — avoids leaking existence.
    not_found_msg = f"No SBOM found for image digest '{image_digest}'."
    if asset_id is not None and asset_id not in asset_ids:
        raise HTTPException(status_code=404, detail=not_found_msg)

    if sbom is None:
        detail = (
            f"SBOM blob not found for image digest '{image_digest}'."
            if reason == "blob_missing"
            else not_found_msg
        )
        raise HTTPException(status_code=404, detail=detail)

    short_digest = image_digest.replace("sha256:", "sha256-")[:20]
    return _render(sbom, fmt, short_digest)


def _render(sbom: dict, fmt: str, name_hint: str) -> Response:
    """Convert sbom to the requested format and return an HTTP Response."""
    try:
        content = _exporter.export(sbom, fmt)
    except UnsupportedFormatError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc

    safe_name = _safe_filename(name_hint)
    ext = _FORMAT_EXT.get(fmt, "txt")
    filename = f"{safe_name}_sbom.{ext}"

    return Response(
        content=content.encode("utf-8"),
        media_type=_FORMAT_CONTENT_TYPE.get(fmt, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
