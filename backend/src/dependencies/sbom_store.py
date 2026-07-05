"""SBOM storage — metadata in Postgres, blobs in MinIO (sboms bucket)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Sbom, SbomRun
from src.db.helpers import run_db
from src.sbom.storage import (
    safe_s3_segment,
    upload_to_minio,
    download_from_minio,
    populate_components,
)

logger = logging.getLogger(__name__)


def _strip_org_prefix(org: str, repo: str) -> str:
    """Strip org prefix from repo if present. 'acme-org/repo' -> 'repo'."""
    prefix = f"{org.lower()}/"
    if repo.lower().startswith(prefix):
        return repo[len(prefix):]
    return repo


def _sbom_s3_key(org: str, repo: str) -> str:
    return f"{safe_s3_segment(org.lower())}/{safe_s3_segment(_strip_org_prefix(org, repo))}/sbom.cdx.json"


def _manifests_s3_key(org: str, repo: str) -> str:
    return f"{safe_s3_segment(org.lower())}/{safe_s3_segment(_strip_org_prefix(org, repo))}/manifests.json"


def _sbom_to_dict(s: Sbom, include_blobs: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": s.id,
        "asset_id": s.asset_id,
        "commit_sha": s.commit_sha,
        "s3_key": s.s3_key,
        "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
        "run_id": s.run_id,
    }
    if include_blobs:
        sbom_data = download_from_minio(s.s3_key)
        result["sbom"] = sbom_data or {}
    return result


def _dependencies_source_tool_fn(comp: dict[str, Any]) -> str | None:
    """Extract source_tool from component properties (scanner:source)."""
    source_tool = None
    for prop in comp.get("properties", []):
        if prop.get("name") == "scanner:source":
            if source_tool is not None:
                source_tool = "both"
            else:
                source_tool = prop.get("value", "")
    return source_tool


def upsert_sbom(
    org: str,
    repo: str,
    commit_sha: str,
    sbom: dict[str, Any],
    manifests: dict[str, str],
    run_id: str,
    asset_id: str | None = None,
    html_url: str | None = None,
) -> None:
    """Store or replace the SBOM for a given org/repo. asset_id required after Plan D."""
    if not asset_id:
        logger.warning("[!] upsert_sbom called without asset_id for %s/%s — skipping DB write", org, repo)
        return

    sbom_key = _sbom_s3_key(org, repo)
    manifests_key = _manifests_s3_key(org, repo)

    upload_to_minio(sbom_key, sbom)
    upload_to_minio(manifests_key, manifests)

    async def _query(session: AsyncSession):
        now = datetime.now(timezone.utc)
        result = await session.execute(
            select(Sbom).where(Sbom.asset_id == asset_id)
        )
        existing = result.scalars().first()
        if existing:
            existing.commit_sha = commit_sha
            existing.html_url = html_url
            existing.s3_key = sbom_key
            existing.run_id = run_id
            existing.scanned_at = now
        else:
            session.add(Sbom(
                asset_id=asset_id,
                commit_sha=commit_sha,
                html_url=html_url,
                s3_key=sbom_key,
                run_id=run_id,
                scanned_at=now,
            ))

        # Append the immutable run-history row (idempotent per (asset, run)).
        run_row = (await session.execute(
            select(SbomRun).where(
                SbomRun.asset_id == asset_id, SbomRun.run_id == run_id
            )
        )).scalars().first()
        if run_row:
            run_row.commit_sha = commit_sha
            run_row.scanned_at = now
        else:
            session.add(SbomRun(
                asset_id=asset_id,
                run_id=run_id,
                commit_sha=commit_sha,
                scanned_at=now,
            ))

    run_db(_query)

    populate_components(org, repo, sbom, source_tool_fn=_dependencies_source_tool_fn, asset_id=asset_id)


def read_sbom(org: str, repo: str, asset_id: str | None = None) -> dict[str, Any] | None:
    """Read the latest SBOM for a given asset. asset_id required after Plan D."""
    if not asset_id:
        return None

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.asset_id == asset_id)
        )
        row = result.scalars().first()
        return _sbom_to_dict(row, include_blobs=True) if row else None

    return run_db(_query)


def any_sbom_for_asset_ids(asset_ids: list[str]) -> bool:
    """Return True if any SBOM exists for any of the given assets.

    Used by /latest endpoints to surface a `hasSboms` flag in the UI.
    Empty `asset_ids` returns False (fail-closed).
    """
    if not asset_ids:
        return False

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).limit(1)
        )
        return result.scalar_one_or_none() is not None

    return run_db(_query)


def populate_sbom_components(
    org: str, repo: str, sbom: dict[str, Any], asset_id: str | None = None,
    scanned_at: datetime | None = None,
) -> int:
    """Backward-compatible wrapper for populate_components."""
    return populate_components(
        org, repo, sbom, source_tool_fn=_dependencies_source_tool_fn,
        asset_id=asset_id, scanned_at=scanned_at,
    )
