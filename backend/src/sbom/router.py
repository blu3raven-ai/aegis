"""REST endpoints for SBOM export and diff — Phase 18 / Phase 37.

SBOMs are read directly from MinIO using the runner-owned prefixes documented below.

Runner MinIO paths
------------------
Dependency SBOMs:  dependencies/{org}/{run_id}/{repo}/sbom.cdx.json
Container SBOMs:   stored in the sboms bucket at {org}/{safe_ref}/sbom.cdx.json,
                   located via the Sbom.s3_key index column.

run_id format is ``auto-{epoch_ms}`` (e.g. ``auto-1748800000000``).  Because
the prefix is identical in length and epoch ms grows monotonically, lexicographic
sort of run_ids is equivalent to chronological sort.

Endpoints
---------
GET /api/v1/sboms/export?repo=owner/name&format=cyclonedx-json
    Export the latest SBOM for a repository.

GET /api/v1/sboms/export?image=sha256:…&format=cyclonedx-json
    Export the SBOM for a container image digest.

GET /api/v1/sboms/history?repo=owner/name&limit=10
    List historical SBOM runs for a repository.
    Response shape: [{run_id, created_at, key}, ...]

GET /api/v1/sboms/diff?repo_id=owner/name&from_run_id=…&to_run_id=…
    Compare two SBOM versions and return added / removed / version-changed components.

GET /api/v1/sboms/diff?image_digest_from=sha256:…&image_digest_to=sha256:…
    Compare two container image SBOMs.

Query-param design avoids the path-segment ambiguity that arises when the
repo identifier (owner/name) contains forward slashes.

All export endpoints return the SBOM as a plain-text or JSON response whose
Content-Type mirrors the format:
  cyclonedx-json   → application/vnd.cyclonedx+json
  cyclonedx-xml    → application/xml
  spdx-json        → application/spdx+json
  spdx-tag-value   → text/plain

Authentication is enforced by the main.py JWT middleware. Each endpoint
additionally gates on `view_findings` and scopes the lookup to assets the
caller's team can access — out-of-scope repos/digests return 404 to avoid
leaking existence.

Convenience path-param aliases (kept for backward compatibility with spec §18):
  GET /api/v1/sboms/repo/{repo_id}         → redirects to ?repo=
  GET /api/v1/sboms/image/{image_digest}   → redirects to ?image=
  GET /api/v1/sboms/repo/{repo_id}/history → redirects to ?repo= history
These are defined last so they don't shadow the query-param routes.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Asset, Sbom
from src.sbom.diff import diff_sboms
from src.sbom.exporter import SbomExporter, UnsupportedFormatError, SUPPORTED_FORMATS
from src.settings.router import require_permission
from src.shared.object_store import list_objects, download_json
from src.shared.sbom_storage import download_from_minio
from src.shared.scope import resolve_asset_ids_from_request


router = APIRouter(prefix="/api/v1/sboms", tags=["sbom-export"])

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


# ------------------------------------------------------------------
# Query-param routes (primary — no path ambiguity)
# ------------------------------------------------------------------

@router.get("/export")
async def export_sbom(
    request: Request,
    repo: Annotated[str | None, Query()] = None,
    image: Annotated[str | None, Query()] = None,
    format: Annotated[str, Query()] = "cyclonedx-json",
) -> Response:
    """Export the latest SBOM.

    Pass exactly one of ``?repo=owner/name`` or ``?image=sha256:…``.
    """
    require_permission(request, "view_findings")
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


@router.get("/diff")
async def sbom_diff(
    request: Request,
    repo_id: Annotated[str | None, Query(description="Repository id (owner/name)")] = None,
    from_run_id: Annotated[str | None, Query(description="Source run_id")] = None,
    to_run_id: Annotated[str | None, Query(description="Target run_id")] = None,
    image_digest_from: Annotated[str | None, Query(description="Source image digest")] = None,
    image_digest_to: Annotated[str | None, Query(description="Target image digest")] = None,
) -> dict:
    """Compare two SBOMs and return component-level changes.

    Supply either (repo_id + from_run_id + to_run_id) to compare two runs of
    the same repository, or (image_digest_from + image_digest_to) to compare
    two container image SBOMs.
    """
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)
    if repo_id:
        if not from_run_id or not to_run_id:
            raise HTTPException(
                status_code=400,
                detail="from_run_id and to_run_id are required when repo_id is provided.",
            )
        if not _repo_in_scope(repo_id, asset_ids):
            raise HTTPException(status_code=404, detail="One or both SBOMs not found.")
        org, repo = _parse_repo_id(repo_id)
        from_sbom = _fetch_sbom_by_run(org, from_run_id, repo)
        to_sbom = _fetch_sbom_by_run(org, to_run_id, repo)
    elif image_digest_from and image_digest_to:
        from_sbom, _, from_asset = _fetch_container_sbom_by_digest(image_digest_from)
        to_sbom, _, to_asset = _fetch_container_sbom_by_digest(image_digest_to)
        scope = set(asset_ids)
        if (from_asset and from_asset not in scope) or (to_asset and to_asset not in scope):
            raise HTTPException(status_code=404, detail="One or both SBOMs not found.")
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide (repo_id + from_run_id + to_run_id) or (image_digest_from + image_digest_to).",
        )

    if from_sbom is None or to_sbom is None:
        raise HTTPException(status_code=404, detail="One or both SBOMs not found.")

    diff = diff_sboms(from_sbom, to_sbom)
    return {
        "added": diff.added,
        "removed": diff.removed,
        "version_changed": diff.version_changed,
        "unchanged_count": diff.unchanged_count,
    }


@router.get("/history")
async def list_sbom_history(
    request: Request,
    repo: Annotated[str, Query()],
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> list[dict]:
    """List historical SBOM runs for a repository."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)
    if not _repo_in_scope(repo, asset_ids):
        return []
    return _list_repo_history(repo, limit)


# ------------------------------------------------------------------
# Path-param aliases — spec §18 URLs (repo_id may contain slashes)
# These are registered with :path so they capture the full slug.
# History MUST be registered before the bare export route because
# FastAPI matches routes in declaration order — the more specific
# /repo/{id}/history pattern must come first.
# ------------------------------------------------------------------

@router.get("/repo/{repo_id:path}/history")
async def list_repo_sbom_history_path(
    request: Request,
    repo_id: str,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> list[dict]:
    """List historical SBOM runs for a repository (path-param alias)."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)
    if not _repo_in_scope(repo_id, asset_ids):
        return []
    return _list_repo_history(repo_id, limit)


@router.get("/repo/{repo_id:path}")
async def export_repo_sbom_path(
    request: Request,
    repo_id: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
) -> Response:
    """Export the latest SBOM for a repository (path-param alias)."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)
    fmt = _resolve_format(format)
    return _export_repo_sbom(repo_id, fmt, asset_ids)


@router.get("/image/{image_digest:path}")
async def export_image_sbom_path(
    request: Request,
    image_digest: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
) -> Response:
    """Export the SBOM for a container image digest (path-param alias)."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)
    fmt = _resolve_format(format)
    return _export_image_sbom(image_digest, fmt, asset_ids)


# ------------------------------------------------------------------
# Internal helpers — shared by both route styles
# ------------------------------------------------------------------

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

    Mirrors the prefix written by backend/src/dependencies/scanner.py during ingest.
    Key pattern: dependencies/{org}/{run_id}/{repo}/sbom.cdx.json
    run_id = auto-{epoch_ms} — lex sort is chronological.
    """
    prefix = f"dependencies/{org}/"
    suffix = f"/{repo}/sbom.cdx.json"
    keys = [k for k in list_objects(prefix) if k.endswith(suffix)]
    if not keys:
        return None
    return sorted(keys)[-1]


def _fetch_sbom_by_run(org: str, run_id: str, repo: str) -> dict[str, Any] | None:
    """Fetch an SBOM from a specific run_id for a repo directly from MinIO."""
    key = f"dependencies/{org}/{run_id}/{repo}/sbom.cdx.json"
    return download_json(key)


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


def _list_repo_history(repo_id: str, limit: int) -> list[dict]:
    """Return run history entries for a repository.

    Each entry: {run_id, created_at, key}
    created_at is derived from the run_id (auto-{epoch_ms}).
    """
    org, repo = _parse_repo_id(repo_id)
    prefix = f"dependencies/{org}/"
    suffix = f"/{repo}/sbom.cdx.json"

    keys = sorted(
        [k for k in list_objects(prefix) if k.endswith(suffix)],
        reverse=True,
    )[:limit]

    entries = []
    for key in keys:
        # Key: dependencies/{org}/{run_id}/{repo}/sbom.cdx.json
        parts = key.split("/")
        run_id = parts[2] if len(parts) >= 4 else ""
        created_at = _run_id_to_iso(run_id)
        entries.append({"run_id": run_id, "created_at": created_at, "key": key})
    return entries


def _run_id_to_iso(run_id: str) -> str | None:
    """Parse an ``auto-{epoch_ms}`` run_id into an ISO-8601 timestamp string."""
    if run_id.startswith("auto-"):
        try:
            ms = int(run_id[5:])
            return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    return None


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
