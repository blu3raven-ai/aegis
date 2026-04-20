"""Shared SBOM storage primitives — MinIO upload/download and component indexing."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import SbomComponent
from src.shared.object_store import get_s3_client

logger = logging.getLogger(__name__)

SBOM_BUCKET = "sboms"


def ensure_sbom_bucket() -> None:
    """Create the sboms bucket if it doesn't exist."""
    from botocore.exceptions import ClientError
    client = get_s3_client()
    try:
        client.head_bucket(Bucket=SBOM_BUCKET)
    except ClientError:
        client.create_bucket(Bucket=SBOM_BUCKET)
        logger.info("[+] Created S3 bucket: %s", SBOM_BUCKET)


def safe_s3_segment(value: str) -> str:
    """Sanitize a value for use in S3 keys — prevent path traversal."""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", value.strip())
    while ".." in safe:
        safe = safe.replace("..", "_")
    return safe.lower()


def upload_to_minio(key: str, data: Any, bucket: str = SBOM_BUCKET) -> None:
    """Upload JSON data to the sboms bucket."""
    ensure_sbom_bucket()
    get_s3_client().put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data).encode(),
        ContentType="application/json",
    )


def download_from_minio(key: str, bucket: str = SBOM_BUCKET) -> Any | None:
    """Download JSON data from the sboms bucket."""
    from botocore.exceptions import ClientError
    try:
        response = get_s3_client().get_object(Bucket=bucket, Key=key)
        return json.loads(response["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404", "NoSuchBucket"):
            return None
        raise


def populate_components(
    org: str,
    resource_id: str,
    sbom: dict[str, Any],
    source_tool_fn: Callable[[dict[str, Any]], str | None] | None = None,
) -> int:
    """Parse CycloneDX SBOM and upsert components into sbom_components table."""
    components = sbom.get("components", [])
    if not components:
        logger.debug("[+] No components in SBOM for %s/%s — skipping", org, resource_id)
        return 0

    now = datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []
    skipped = 0

    MAX_PURL_LENGTH = 2048
    for comp in components:
        purl = comp.get("purl", "")
        if not purl or not isinstance(purl, str) or len(purl) > MAX_PURL_LENGTH:
            skipped += 1
            continue

        name = comp.get("name", "")
        version = comp.get("version", "")

        ecosystem = ""
        if purl.startswith("pkg:"):
            parts = purl[4:].split("/", 1)
            if parts:
                ecosystem = parts[0]

        source_tool = source_tool_fn(comp) if source_tool_fn else None

        rows.append({
            "org": org.lower(),
            "repo": resource_id,
            "purl": purl,
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "source_tool": source_tool,
            "is_direct": True,
            "scanned_at": now,
        })

    # Deduplicate by purl — SBOMs can list the same package multiple times
    # (e.g. actions/checkout@v4 referenced in multiple workflows)
    seen_purls: set[str] = set()
    unique_rows: list[dict[str, Any]] = []
    for row in rows:
        if row["purl"] not in seen_purls:
            seen_purls.add(row["purl"])
            unique_rows.append(row)

    duplicates = len(rows) - len(unique_rows)
    if duplicates > 0:
        logger.info("[+] Deduplicated %d duplicate PURLs for %s/%s", duplicates, org, resource_id)
    if skipped > 0:
        logger.debug("[+] Skipped %d components without valid PURL for %s/%s", skipped, org, resource_id)

    async def _query(session):
        await session.execute(
            delete(SbomComponent).where(
                SbomComponent.org == org.lower(),
                SbomComponent.repo == resource_id,
            )
        )
        session.add_all([SbomComponent(**row) for row in unique_rows])
        return len(unique_rows)

    try:
        count = run_db(_query)
    except Exception:
        logger.exception("[!] Failed to index components for %s/%s (%d rows)", org, resource_id, len(unique_rows))
        raise

    logger.info("[✓] Indexed %d components for %s/%s", count, org, resource_id)
    return count
