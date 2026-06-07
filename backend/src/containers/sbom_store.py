"""SBOM storage for container scanning — MinIO blobs + Postgres index."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Sbom
from src.shared.sbom_storage import (
    safe_s3_segment,
    upload_to_minio,
    download_from_minio,
    populate_components,
)

logger = logging.getLogger(__name__)


def _sbom_s3_key(org: str, image_ref: str) -> str:
    """S3 key for an image's CycloneDX SBOM."""
    safe_ref = image_ref.replace("/", "_").replace(":", "_")
    return f"{safe_s3_segment(org.lower())}/{safe_s3_segment(safe_ref)}/sbom.cdx.json"


def upsert_sbom(
    org: str,
    image_ref: str,
    image_digest: str | None,
    sbom: dict[str, Any],
    run_id: str,
    asset_id: str | None = None,
) -> None:
    """Store a CycloneDX SBOM: upload blob to MinIO, upsert Postgres metadata. asset_id required after Plan D."""
    if not asset_id:
        logger.warning("[!] upsert_sbom called without asset_id for %s/%s — skipping DB write", org, image_ref)
        return

    s3_key = _sbom_s3_key(org, image_ref)

    upload_to_minio(s3_key, sbom)
    logger.info("Uploaded SBOM to MinIO: %s", s3_key)

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.asset_id == asset_id)
        )
        existing = result.scalars().first()
        if existing:
            existing.commit_sha = image_digest
            existing.s3_key = s3_key
            existing.run_id = run_id
            existing.scanned_at = datetime.now(timezone.utc)
        else:
            session.add(Sbom(
                asset_id=asset_id,
                commit_sha=image_digest,
                s3_key=s3_key,
                run_id=run_id,
            ))

    run_db(_query)

    populate_components(org, image_ref, sbom, source_tool_fn=lambda _: "syft", asset_id=asset_id)


def read_sbom(org: str, image_ref: str, asset_id: str | None = None) -> dict[str, Any] | None:
    """Fetch stored SBOM metadata + blob from MinIO. asset_id required after Plan D."""
    if not asset_id:
        return None

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.asset_id == asset_id)
        )
        return result.scalars().first()

    row = run_db(_query)
    if not row:
        return None

    sbom_data = download_from_minio(row.s3_key)
    if sbom_data is None:
        logger.warning("Failed to fetch SBOM from MinIO: %s", row.s3_key)
        return None

    return {
        "metadata": {
            "asset_id": row.asset_id,
            "commit_sha": row.commit_sha,
            "s3_key": row.s3_key,
            "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
            "run_id": row.run_id,
        },
        "sbom": sbom_data,
    }


def list_stored_sboms(org: str) -> list[dict[str, Any]]:
    """List SBOMs for all image assets owned by `org` (e.g. "acme").

    Used by the container scanner's skip-unchanged optimization to look up
    the previously-scanned digest per image. The returned dicts include
    `repo` (Asset.display_name, e.g. "img:tag") so callers can key by it.
    """
    from src.db.models import Asset

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom, Asset)
            .join(Asset, Asset.id == Sbom.asset_id)
            .where(
                Asset.external_ref.like(f"%:{org}/%"),
                Asset.type == "image",
            )
        )
        return [
            {
                "asset_id": str(s.asset_id),
                "repo": a.display_name,
                "commit_sha": s.commit_sha,
                "s3_key": s.s3_key,
                "run_id": s.run_id,
            }
            for s, a in result.all()
        ]

    return run_db(_query)


def populate_sbom_components(org: str, image_ref: str, sbom: dict[str, Any], asset_id: str | None = None) -> int:
    """Backward-compatible wrapper for populate_components."""
    return populate_components(org, image_ref, sbom, source_tool_fn=lambda _: "syft", asset_id=asset_id)
