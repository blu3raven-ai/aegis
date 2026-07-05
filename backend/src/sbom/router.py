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
from src.db.models import Asset, Sbom, SbomRun
from src.sbom.exporter import SbomExporter, SUPPORTED_FORMATS
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import VIEW_FINDINGS
from src.shared.object_store import download_json
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
    run_id: Annotated[str | None, Query()] = None,
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
        return _export_repo_sbom(repo, fmt, asset_ids, run_id=run_id)
    return _export_image_sbom(image, fmt, asset_ids)  # type: ignore[arg-type]


@router.get("/repo/{repo_id:path}")
async def export_repo_sbom_path(
    request: Request,
    repo_id: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
    run_id: Annotated[str | None, Query()] = None,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    """Export a repository's SBOM (path-param alias).

    With ``?run_id=`` a specific historical snapshot is returned; otherwise
    the latest.
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    fmt = _resolve_format(format)
    return _export_repo_sbom(repo_id, fmt, asset_ids, run_id=run_id)


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
    asset_ids = await resolve_asset_ids_from_request(request)
    repo_id = f"{org}/{repo}"
    # Resolve the latest run from the scoped Sbom index. This enforces scope AND
    # binds the blob to this asset's own run: the legacy "{org}/{repo}/sbom.cdx.json"
    # canonical key has no asset qualifier and is shared (last-writer-wins) across
    # assets that collide on display_name, so reading it directly could serve a
    # colliding asset's SBOM. A real in-scope asset is required before org/repo
    # ever reach a key, so a traversal value short-circuits to 404 here.
    run_id = _latest_run_id_for_asset(repo_id, asset_ids)
    if run_id is None:
        return JSONResponse({"error": "SBOM not found for this repository"}, status_code=404)

    key = f"dependencies_scanning/{org}/{run_id}/{repo}/sbom.cdx.json"
    data = download_json(key)
    # download_json already returns None for a corrupt/unparseable blob; a valid
    # JSON value that isn't a CycloneDX object is likewise treated as missing.
    if not isinstance(data, dict):
        return JSONResponse({"error": "SBOM not found for this repository"}, status_code=404)

    filename = f"{safe_s3_segment(org)}_{safe_s3_segment(repo)}_sbom.cdx.json"
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


def _asset_owns_run(repo_id: str, asset_ids: list[str], run_id: str) -> bool:
    """True if ``run_id`` is a recorded ``SbomRun`` of the in-scope repo asset.

    The dependency-SBOM key is built from ``owner/run_id/name`` with no asset
    qualifier, so two assets sharing an owner/name (the same repo mirrored
    across two source connections) share a key prefix. Resolving the asset by
    display_name alone would let a caller scoped to one pass the other's run id
    and read its snapshot — so the supplied run id is bound back to this asset's
    own runs before it reaches the object store.
    """
    if not asset_ids:
        return False

    async def _query(session):
        result = await session.execute(
            select(SbomRun.id)
            .join(Asset, Asset.id == SbomRun.asset_id)
            .where(Asset.display_name == repo_id)
            .where(Asset.type == "repo")
            .where(Asset.id.in_(asset_ids))
            .where(SbomRun.run_id == run_id)
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    return run_db(_query)


def _latest_run_id_for_asset(repo_id: str, asset_ids: list[str]) -> str | None:
    """Latest dependency-scan run id for an in-scope repo, from the Sbom index.

    Lets the repo export build the snapshot key directly instead of an
    O(org-size) MinIO prefix listing to find the newest blob. Scope is enforced
    in the same query (display_name + type=repo intersected with the grant set).
    """
    if not asset_ids:
        return None

    async def _query(session):
        result = await session.execute(
            select(Sbom.run_id)
            .join(Asset, Asset.id == Sbom.asset_id)
            .where(Asset.display_name == repo_id)
            .where(Asset.type == "repo")
            .where(Asset.id.in_(asset_ids))
            .order_by(Sbom.scanned_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    return run_db(_query)


def _fetch_container_sbom_by_digest(
    image_digest: str, asset_ids: list[str]
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Fetch a container SBOM by image digest via the Sbom index table.

    Mirrors the blob uploaded by backend/src/containers/sbom_store.py during ingest.
    Scope is enforced at the SQL layer so a digest shared across tenants resolves
    to the caller's own row — never another tenant's, which would otherwise yield
    a spurious 404. Empty/absent scope returns no_row (fail-closed).

    Returns: (sbom, reason, asset_id)
      - (sbom_dict, None, asset_id) on success
      - (None, "no_row", None) if no in-scope row matches the digest
      - (None, "blob_missing", asset_id) if Sbom row exists but MinIO blob is absent
    """
    if not asset_ids:
        return None, "no_row", None

    async def _query(session):
        result = await session.execute(
            select(Sbom)
            .where(Sbom.commit_sha == image_digest)
            .where(Sbom.asset_id.in_(asset_ids))
            .limit(1)
        )
        return result.scalars().first()

    row = run_db(_query)
    if row is None:
        return None, "no_row", None
    sbom = download_from_minio(row.s3_key)
    if sbom is None:
        return None, "blob_missing", row.asset_id
    return sbom, None, row.asset_id


_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _safe_run_id(run_id: str) -> bool:
    """Allowlist a run id before it flows into a MinIO key prefix."""
    return ".." not in run_id and bool(_RUN_ID_PATTERN.match(run_id))


def _export_repo_sbom(
    repo_id: str, fmt: str, asset_ids: list[str], run_id: str | None = None
) -> Response:
    """Fetch + export a repository's SBOM — the ``run_id`` snapshot if given,
    else the latest."""
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
    if run_id is not None:
        # Specific historical snapshot. Allowlist the run id for path safety,
        # then bind it to this asset's own runs — the owner/run/name MinIO key
        # is shared across display_name-colliding assets, so the scope check
        # above is not sufficient on its own.
        if not _safe_run_id(run_id) or not _asset_owns_run(repo_id, asset_ids, run_id):
            raise HTTPException(
                status_code=404,
                detail=f"No SBOM found for repository '{repo_id}'.",
            )
    else:
        # Latest snapshot — resolve the run id from the scoped Sbom index. This
        # is also the only source of truth for "latest": there is no unscoped
        # MinIO-prefix fallback, which could otherwise serve a colliding asset's
        # blob.
        run_id = _latest_run_id_for_asset(repo_id, asset_ids)

    if run_id is None:
        raise HTTPException(
            status_code=404,
            detail=f"No SBOM found for repository '{repo_id}'.",
        )

    key = f"dependencies_scanning/{org}/{run_id}/{repo}/sbom.cdx.json"

    sbom = download_json(key)
    if not isinstance(sbom, dict):
        raise HTTPException(
            status_code=404,
            detail=f"SBOM blob not found for repository '{repo_id}'.",
        )

    return _render(sbom, fmt, repo_id)


def _export_image_sbom(image_digest: str, fmt: str, asset_ids: list[str]) -> Response:
    """Fetch + export the SBOM for a container image digest."""
    sbom, reason, asset_id = _fetch_container_sbom_by_digest(image_digest, asset_ids)

    # 404 (not 403) when the caller can't see the asset — avoids leaking existence.
    # The fetch already scopes at SQL; this stays as a defensive backstop.
    not_found_msg = f"No SBOM found for image digest '{image_digest}'."
    if asset_id is not None and asset_id not in asset_ids:
        raise HTTPException(status_code=404, detail=not_found_msg)

    if not isinstance(sbom, dict):
        detail = (
            f"SBOM blob not found for image digest '{image_digest}'."
            if reason == "blob_missing" or sbom is not None
            else not_found_msg
        )
        raise HTTPException(status_code=404, detail=detail)

    short_digest = image_digest.replace("sha256:", "sha256-")[:20]
    return _render(sbom, fmt, short_digest)


def _render(sbom: dict, fmt: str, name_hint: str) -> Response:
    """Convert sbom to the requested format and return an HTTP Response."""
    content = _exporter.export(sbom, fmt)

    safe_name = _safe_filename(name_hint)
    ext = _FORMAT_EXT.get(fmt, "txt")
    filename = f"{safe_name}_sbom.{ext}"

    return Response(
        content=content.encode("utf-8"),
        media_type=_FORMAT_CONTENT_TYPE.get(fmt, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
