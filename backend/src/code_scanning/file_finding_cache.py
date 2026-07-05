"""Per-file SAST finding cache backed by cache_entries (Postgres) + MinIO blobs.

Phase 2c: read/write/invalidate operations for the SAST incremental delta engine.
Cache key is (repo_id, file_path, file_sha256) so unchanged files reuse their
last-scanned results even across commits.

No live wiring into the scanner path yet — that is the dormant-to-live flip later.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import CacheEntry
from src.shared.sbom_storage import (
    ensure_sbom_bucket,
    upload_to_minio,
    download_from_minio,
)

logger = logging.getLogger(__name__)

_CACHE_TYPE = "sast-file-findings"
_SAST_BUCKET = "sboms"  # reuse the shared bucket; SAST blobs live under sast/ prefix


@dataclass
class Finding:
    file_path: str
    line: int
    rule_id: str
    severity: str
    message: str


def _s3_key(repo_id: str, file_sha256: str) -> str:
    return f"sast/{repo_id}/{file_sha256}.json"


def _cache_key(repo_id: str, file_path: str, file_sha256: str) -> str:
    # Pipe-separated so prefix queries on repo_id|file_path work unambiguously
    return f"{repo_id}|{file_path}|{file_sha256}"


def _repo_prefix(repo_id: str) -> str:
    return f"{repo_id}|%"


def _file_prefix(repo_id: str, file_path: str) -> str:
    return f"{repo_id}|{file_path}|%"


class FileFindingCache:
    """Read/write per-file SAST findings from MinIO and track hits in cache_entries.

    The rule_pack_version column is compared on get(); a stale rule pack means
    the cached findings don't reflect the current ruleset and must be evicted.
    """

    # ── public API ────────────────────────────────────────────────────────────

    def get(
        self,
        repo_id: str,
        file_path: str,
        file_sha256: str,
        rule_pack_version: str,
    ) -> list[Finding] | None:
        """Return cached findings for (repo_id, file_path, file_sha256), or None.

        Returns None when the cache entry is missing, the blob is missing, or the
        stored rule_pack_version differs from the caller's current rule pack.
        """
        key = _cache_key(repo_id, file_path, file_sha256)

        async def _query(session):
            result = await session.execute(
                select(CacheEntry).where(
                    CacheEntry.cache_type == _CACHE_TYPE,
                    CacheEntry.cache_key == key,
                )
            )
            return result.scalars().first()

        entry: CacheEntry | None = run_db(_query)
        if entry is None:
            return None

        # Rule pack mismatch → cached findings are stale
        if entry.rule_pack_version != rule_pack_version:
            return None

        blob = download_from_minio(_s3_key(repo_id, file_sha256), bucket=_SAST_BUCKET)
        if blob is None:
            logger.warning(
                "cache_entries row exists but MinIO blob missing for %s; evicting row",
                key,
            )
            self.invalidate_file(repo_id, file_path)
            return None

        async def _touch(session):
            result = await session.execute(
                select(CacheEntry).where(
                    CacheEntry.cache_type == _CACHE_TYPE,
                    CacheEntry.cache_key == key,
                )
            )
            row = result.scalars().first()
            if row:
                row.last_used_at = datetime.now(timezone.utc)

        run_db(_touch)
        return [Finding(**f) for f in blob]

    def put(
        self,
        repo_id: str,
        file_path: str,
        file_sha256: str,
        findings: list[Finding],
        rule_pack_version: str,
    ) -> None:
        """Write findings to MinIO and upsert cache_entries row."""
        key = _cache_key(repo_id, file_path, file_sha256)
        blob = [asdict(f) for f in findings]

        ensure_sbom_bucket()
        upload_to_minio(_s3_key(repo_id, file_sha256), blob, bucket=_SAST_BUCKET)

        blob_bytes = json.dumps(blob, sort_keys=True).encode()
        content_hash = hashlib.sha256(blob_bytes).hexdigest()
        now = datetime.now(timezone.utc)
        blob_ptr = f"s3://{_SAST_BUCKET}/{_s3_key(repo_id, file_sha256)}"

        async def _upsert(session):
            stmt = (
                pg_insert(CacheEntry)
                .values(
                    cache_type=_CACHE_TYPE,
                    cache_key=key,
                    content_hash=content_hash,
                    tool_version="opengrep",
                    rule_pack_version=rule_pack_version,
                    created_at=now,
                    last_used_at=now,
                    blob_pointer=blob_ptr,
                )
                .on_conflict_do_update(
                    constraint="uq_cache_type_key",
                    set_={
                        "content_hash": content_hash,
                        "rule_pack_version": rule_pack_version,
                        "last_used_at": now,
                        "blob_pointer": blob_ptr,
                    },
                )
            )
            await session.execute(stmt)

        run_db(_upsert)

    def invalidate_repo(self, repo_id: str) -> int:
        """Remove all cached file findings for a repo. Returns count removed."""
        pattern = _repo_prefix(repo_id)

        async def _delete(session):
            result = await session.execute(
                delete(CacheEntry)
                .where(
                    CacheEntry.cache_type == _CACHE_TYPE,
                    CacheEntry.cache_key.like(pattern),
                )
                .returning(CacheEntry.id)
            )
            return len(result.fetchall())

        return run_db(_delete)

    def invalidate_file(self, repo_id: str, file_path: str) -> int:
        """Remove all cached findings for a specific file (all sha256 variants).

        Returns count removed. Useful when a file is deleted or renamed.
        """
        pattern = _file_prefix(repo_id, file_path)

        async def _delete(session):
            result = await session.execute(
                delete(CacheEntry)
                .where(
                    CacheEntry.cache_type == _CACHE_TYPE,
                    CacheEntry.cache_key.like(pattern),
                )
                .returning(CacheEntry.id)
            )
            return len(result.fetchall())

        return run_db(_delete)

    def list_repo_entries(self, repo_id: str) -> list[CacheEntry]:
        """Return all cache_entries rows for a given repo_id."""
        pattern = _repo_prefix(repo_id)

        async def _list(session):
            result = await session.execute(
                select(CacheEntry).where(
                    CacheEntry.cache_type == _CACHE_TYPE,
                    CacheEntry.cache_key.like(pattern),
                )
            )
            return result.scalars().all()

        return run_db(_list)
