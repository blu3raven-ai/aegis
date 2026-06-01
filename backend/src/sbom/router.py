"""REST endpoints for SBOM export and diff — Phase 18 / Phase 37.

Endpoints
---------
GET /api/v1/sboms/export?repo=owner/name&format=cyclonedx-json
    Export the latest cached SBOM for a repository.

GET /api/v1/sboms/export?image=sha256:…&format=cyclonedx-json
    Export the cached SBOM for a container image digest.

GET /api/v1/sboms/history?repo=owner/name&limit=10
    List historical SBOM versions (cache_entries rows) for a repository.

GET /api/v1/sboms/diff?repo_id=owner/name&from_hash=…&to_hash=…
    Compare two cached SBOMs and return added / removed / version-changed components.

Query-param design avoids the path-segment ambiguity that arises when the
repo identifier (owner/name) contains forward slashes.

All export endpoints return the SBOM as a plain-text or JSON response whose
Content-Type mirrors the format:
  cyclonedx-json   → application/vnd.cyclonedx+json
  cyclonedx-xml    → application/xml
  spdx-json        → application/spdx+json
  spdx-tag-value   → text/plain

Authentication is enforced by the main.py JWT middleware — no additional
auth layer needed here.

Convenience path-param aliases (kept for backward compatibility with spec §18):
  GET /api/v1/sboms/repo/{repo_id}         → redirects to ?repo=
  GET /api/v1/sboms/image/{image_digest}   → redirects to ?image=
  GET /api/v1/sboms/repo/{repo_id}/history → redirects to ?repo= history
These are defined last so they don't shadow the query-param routes.
"""
from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from src.dependencies.sbom_cache import SbomCache, ContainerSbomCache, _CACHE_TYPE
from src.sbom.diff import diff_sboms
from src.sbom.exporter import SbomExporter, UnsupportedFormatError, SUPPORTED_FORMATS
from src.db.helpers import run_db
from src.db.models import CacheEntry
from sqlalchemy import select, desc


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


# ------------------------------------------------------------------
# Query-param routes (primary — no path ambiguity)
# ------------------------------------------------------------------

@router.get("/export")
def export_sbom(
    repo: Annotated[str | None, Query()] = None,
    image: Annotated[str | None, Query()] = None,
    format: Annotated[str, Query()] = "cyclonedx-json",
) -> Response:
    """Export a cached SBOM.

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

    if repo is not None:
        return _export_repo_sbom(repo, fmt)
    return _export_image_sbom(image, fmt)  # type: ignore[arg-type]


@router.get("/diff")
def sbom_diff(
    repo_id: Annotated[str | None, Query(description="Repository id (owner/name)")] = None,
    from_hash: Annotated[str | None, Query(description="Source manifest_set_hash")] = None,
    to_hash: Annotated[str | None, Query(description="Target manifest_set_hash")] = None,
    image_digest_from: Annotated[str | None, Query(description="Source image digest")] = None,
    image_digest_to: Annotated[str | None, Query(description="Target image digest")] = None,
) -> dict:
    """Compare two cached SBOMs and return component-level changes.

    Supply either (repo_id + from_hash + to_hash) to compare two versions of
    the same repository, or (image_digest_from + image_digest_to) to compare
    two container image SBOMs.
    """
    if repo_id:
        if not from_hash or not to_hash:
            raise HTTPException(
                status_code=400,
                detail="from_hash and to_hash are required when repo_id is provided.",
            )
        cache = SbomCache()
        from_sbom = cache.get(repo_id, from_hash)
        to_sbom = cache.get(repo_id, to_hash)
    elif image_digest_from and image_digest_to:
        ccache = ContainerSbomCache()
        from_sbom = ccache.get_by_digest(image_digest_from)
        to_sbom = ccache.get_by_digest(image_digest_to)
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide (repo_id + from_hash + to_hash) or (image_digest_from + image_digest_to).",
        )

    if from_sbom is None or to_sbom is None:
        raise HTTPException(status_code=404, detail="One or both SBOMs not found in cache.")

    diff = diff_sboms(from_sbom, to_sbom)
    return {
        "added": diff.added,
        "removed": diff.removed,
        "version_changed": diff.version_changed,
        "unchanged_count": diff.unchanged_count,
    }


@router.get("/history")
def list_sbom_history(
    repo: Annotated[str, Query()],
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> list[dict]:
    """List historical SBOM cache entries for a repository."""
    return _list_repo_history(repo, limit)


# ------------------------------------------------------------------
# Path-param aliases — spec §18 URLs (repo_id may contain slashes)
# These are registered with :path so they capture the full slug.
# History MUST be registered before the bare export route because
# FastAPI matches routes in declaration order — the more specific
# /repo/{id}/history pattern must come first.
# ------------------------------------------------------------------

@router.get("/repo/{repo_id:path}/history")
def list_repo_sbom_history_path(
    repo_id: str,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> list[dict]:
    """List historical SBOM versions for a repository (path-param alias)."""
    return _list_repo_history(repo_id, limit)


@router.get("/repo/{repo_id:path}")
def export_repo_sbom_path(
    repo_id: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
) -> Response:
    """Export the latest cached SBOM for a repository (path-param alias)."""
    fmt = _resolve_format(format)
    return _export_repo_sbom(repo_id, fmt)


@router.get("/image/{image_digest:path}")
def export_image_sbom_path(
    image_digest: str,
    format: Annotated[str, Query(alias="format")] = "cyclonedx-json",
) -> Response:
    """Export the cached SBOM for a container image digest (path-param alias)."""
    fmt = _resolve_format(format)
    return _export_image_sbom(image_digest, fmt)


# ------------------------------------------------------------------
# Internal helpers — shared by both route styles
# ------------------------------------------------------------------

def _export_repo_sbom(repo_id: str, fmt: str) -> Response:
    """Fetch + export the latest cached SBOM for a repository."""
    # Strip a trailing /history suffix that could arrive via the path alias
    # if FastAPI routing resolves to this handler instead of the history one.
    # (Defensive — should not happen with correct route ordering.)
    if repo_id.endswith("/history"):
        repo_id = repo_id[: -len("/history")]

    async def _query(session):
        result = await session.execute(
            select(CacheEntry)
            .where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key.startswith(f"{repo_id}|"),
            )
            .order_by(desc(CacheEntry.created_at))
            .limit(1)
        )
        return result.scalars().first()

    entry: CacheEntry | None = run_db(_query)

    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"No cached SBOM found for repository '{repo_id}'.",
        )

    parts = entry.cache_key.split("|", 1)
    manifest_hash = parts[1] if len(parts) == 2 else ""

    cache = SbomCache()
    sbom = cache.get(repo_id, manifest_hash)
    if sbom is None:
        raise HTTPException(
            status_code=404,
            detail=f"SBOM blob not found for repository '{repo_id}'.",
        )

    return _render(sbom, fmt, repo_id)


def _export_image_sbom(image_digest: str, fmt: str) -> Response:
    """Fetch + export the cached SBOM for a container image digest."""
    container_cache = ContainerSbomCache()
    sbom = container_cache.get_by_digest(image_digest)

    if sbom is None:
        raise HTTPException(
            status_code=404,
            detail=f"No cached SBOM found for image digest '{image_digest}'.",
        )

    short_digest = image_digest.replace("sha256:", "sha256-")[:20]
    return _render(sbom, fmt, short_digest)


def _list_repo_history(repo_id: str, limit: int) -> list[dict]:
    """Return history entries for a repository."""
    async def _query(session):
        result = await session.execute(
            select(CacheEntry)
            .where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key.startswith(f"{repo_id}|"),
            )
            .order_by(desc(CacheEntry.created_at))
            .limit(limit)
        )
        return result.scalars().all()

    entries: list[CacheEntry] = run_db(_query)

    return [
        {
            "manifest_set_hash": e.cache_key.split("|", 1)[1] if "|" in e.cache_key else "",
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "blob_pointer": e.blob_pointer,
            "content_hash": e.content_hash,
            "tool_version": e.tool_version,
        }
        for e in entries
    ]


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
