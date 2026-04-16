"""SBOM storage — metadata in Postgres, blobs in MinIO (sboms bucket)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Sbom
from src.db.helpers import run_db
from src.shared.sbom_storage import (
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
        "org": s.org,
        "repo": s.repo,
        "commit_sha": s.commit_sha,
        "s3_key": s.s3_key,
        "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
        "run_id": s.run_id,
    }
    if include_blobs:
        sbom_data = download_from_minio(_sbom_s3_key(s.org, s.repo))
        if sbom_data is None:
            for legacy_key in [
                f"{safe_s3_segment(s.org.lower())}/{safe_s3_segment(s.repo)}/sbom.cdx.json",
                f"{safe_s3_segment(s.org.lower())}/{safe_s3_segment(s.repo)}/sbom.json",
            ]:
                sbom_data = download_from_minio(legacy_key)
                if sbom_data is not None:
                    break
        result["sbom"] = sbom_data or {}
        result["manifests"] = download_from_minio(_manifests_s3_key(s.org, s.repo)) or {}
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
) -> None:
    """Store or replace the SBOM for a given org/repo."""
    sbom_key = _sbom_s3_key(org, repo)
    manifests_key = _manifests_s3_key(org, repo)

    upload_to_minio(sbom_key, sbom)
    upload_to_minio(manifests_key, manifests)

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.org == org.lower(), Sbom.repo == repo)
        )
        existing = result.scalars().first()
        if existing:
            existing.commit_sha = commit_sha
            existing.s3_key = sbom_key
            existing.run_id = run_id
            existing.scanned_at = datetime.now(timezone.utc)
        else:
            session.add(Sbom(
                org=org.lower(),
                repo=repo,
                commit_sha=commit_sha,
                s3_key=sbom_key,
                run_id=run_id,
            ))

    run_db(_query)

    populate_components(org, repo, sbom, source_tool_fn=_dependencies_source_tool_fn)


def read_sbom(org: str, repo: str) -> dict[str, Any] | None:
    """Read the latest SBOM for a given org/repo (metadata + blobs from MinIO)."""
    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.org == org.lower(), Sbom.repo == repo)
        )
        row = result.scalars().first()
        return _sbom_to_dict(row, include_blobs=True) if row else None

    return run_db(_query)


def read_all_sboms_for_org(org: str) -> list[dict[str, Any]]:
    """Read all stored SBOMs for an organization (metadata + blobs from MinIO)."""
    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.org == org.lower())
        )
        return [_sbom_to_dict(s, include_blobs=True) for s in result.scalars().all()]

    return run_db(_query)


def populate_sbom_components(org: str, repo: str, sbom: dict[str, Any]) -> int:
    """Backward-compatible wrapper for populate_components."""
    return populate_components(org, repo, sbom, source_tool_fn=_dependencies_source_tool_fn)
