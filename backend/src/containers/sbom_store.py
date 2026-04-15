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
) -> None:
    """Store a CycloneDX SBOM: upload blob to MinIO, upsert Postgres metadata."""
    s3_key = _sbom_s3_key(org, image_ref)

    upload_to_minio(s3_key, sbom)
    logger.info("Uploaded SBOM to MinIO: %s", s3_key)

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.org == org.lower(), Sbom.repo == image_ref)
        )
        existing = result.scalars().first()
        if existing:
            existing.commit_sha = image_digest
            existing.s3_key = s3_key
            existing.run_id = run_id
            existing.scanned_at = datetime.now(timezone.utc)
        else:
            session.add(Sbom(
                org=org.lower(),
                repo=image_ref,
                commit_sha=image_digest,
                s3_key=s3_key,
                run_id=run_id,
            ))

    run_db(_query)

    populate_components(org, image_ref, sbom, source_tool_fn=lambda _: "syft")


def read_sbom(org: str, image_ref: str) -> dict[str, Any] | None:
    """Fetch stored SBOM metadata + blob from MinIO."""
    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.org == org.lower(), Sbom.repo == image_ref)
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
            "org": row.org,
            "repo": row.repo,
            "commit_sha": row.commit_sha,
            "s3_key": row.s3_key,
            "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
            "run_id": row.run_id,
        },
        "sbom": sbom_data,
    }


def list_stored_sboms(org: str) -> list[dict[str, Any]]:
    """List all stored SBOMs for an org (for advisories_only mode)."""
    async def _query(session: AsyncSession):
        result = await session.execute(
            select(Sbom).where(Sbom.org == org.lower())
        )
        return [
            {
                "repo": r.repo,
                "commit_sha": r.commit_sha,
                "s3_key": r.s3_key,
                "run_id": r.run_id,
            }
            for r in result.scalars().all()
        ]

    return run_db(_query)


def populate_sbom_components(org: str, image_ref: str, sbom: dict[str, Any]) -> int:
    """Backward-compatible wrapper for populate_components."""
    return populate_components(org, image_ref, sbom, source_tool_fn=lambda _: "syft")
