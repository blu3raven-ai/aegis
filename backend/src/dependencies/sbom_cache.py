"""SBOM cache backed by cache_entries (Postgres) + MinIO blobs.

Phase 2a: read/write/invalidate operations for the incremental delta engine.
Phase 2b: generalised so container SBOMs reuse the same table and storage
          with a distinct cache_type and S3 namespace.

No live wiring into the scanner path yet — that is a follow-up opt-in step.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import CacheEntry
from src.shared.sbom_storage import (
    SBOM_BUCKET,
    ensure_sbom_bucket,
    upload_to_minio,
    download_from_minio,
)

logger = logging.getLogger(__name__)

# Default cache_type for the Phase 2a dependency scanner — kept as a module
# constant so existing callers (intel_fanout, tests) can import it unchanged.
_CACHE_TYPE = "sbom"

# cache_type value used by the Phase 2b container scanner
_CACHE_TYPE_CONTAINER = "sbom-container"


# ── Phase 2a module-level helpers (kept for backward compatibility) ───────────

def _s3_key(repo_id: str, manifest_set_hash: str) -> str:
    """Return the MinIO object key for a dependency-scanner SBOM blob."""
    return f"sboms/{repo_id}/{manifest_set_hash}.json"


def _blob_pointer(repo_id: str, manifest_set_hash: str) -> str:
    return f"s3://{SBOM_BUCKET}/{_s3_key(repo_id, manifest_set_hash)}"


def _cache_key(repo_id: str, manifest_set_hash: str) -> str:
    return f"{repo_id}|{manifest_set_hash}"


# ── Generic cache class ───────────────────────────────────────────────────────

class SbomCache:
    """Read/write SBOM blobs from MinIO and track hits in cache_entries.

    Constructor args allow callers to create logically separate namespaces
    without code duplication:

    - cache_type   : the value stored in cache_entries.cache_type
    - cache_key_fn : maps (repo_id, manifest_set_hash) → cache_entries.cache_key
    - s3_key_fn    : maps the cache_key string → MinIO object path

    Default values reproduce the exact Phase 2a behaviour so no existing
    callers need to change.
    """

    def __init__(
        self,
        *,
        cache_type: str = _CACHE_TYPE,
        cache_key_fn: Callable[[str, str], str] = _cache_key,
        s3_key_fn: Callable[[str, str], str] = _s3_key,
    ) -> None:
        self._cache_type = cache_type
        self._cache_key_fn = cache_key_fn
        self._s3_key_fn = s3_key_fn

    def _mk_blob_pointer(self, repo_id: str, manifest_set_hash: str) -> str:
        return f"s3://{SBOM_BUCKET}/{self._s3_key_fn(repo_id, manifest_set_hash)}"

    # ── public API ────────────────────────────────────────────────────────────

    def get(self, repo_id: str, manifest_set_hash: str) -> dict[str, Any] | None:
        """Return cached SBOM dict for (repo_id, manifest_set_hash), or None on miss.

        Updates last_used_at on hit so LRU eviction has accurate timestamps.
        """
        key = self._cache_key_fn(repo_id, manifest_set_hash)

        async def _query(session):
            result = await session.execute(
                select(CacheEntry).where(
                    CacheEntry.cache_type == self._cache_type,
                    CacheEntry.cache_key == key,
                )
            )
            return result.scalars().first()

        entry: CacheEntry | None = run_db(_query)
        if entry is None:
            return None

        sbom = download_from_minio(self._s3_key_fn(repo_id, manifest_set_hash))
        if sbom is None:
            # Blob missing despite a valid cache row — treat as miss and clean up
            logger.warning(
                "cache_entries row exists but MinIO blob missing for %s; evicting row",
                key,
            )
            self.invalidate(repo_id, manifest_set_hash=manifest_set_hash)
            return None

        async def _touch(session):
            result = await session.execute(
                select(CacheEntry).where(
                    CacheEntry.cache_type == self._cache_type,
                    CacheEntry.cache_key == key,
                )
            )
            row = result.scalars().first()
            if row:
                row.last_used_at = datetime.now(timezone.utc)

        run_db(_touch)
        return sbom

    def put(
        self,
        repo_id: str,
        manifest_set_hash: str,
        sbom: dict[str, Any],
        tool_version: str,
    ) -> None:
        """Write SBOM to MinIO and upsert cache_entries row."""
        key = self._cache_key_fn(repo_id, manifest_set_hash)

        ensure_sbom_bucket()
        upload_to_minio(self._s3_key_fn(repo_id, manifest_set_hash), sbom)

        sbom_bytes = json.dumps(sbom, sort_keys=True).encode()
        content_hash = hashlib.sha256(sbom_bytes).hexdigest()
        now = datetime.now(timezone.utc)

        async def _upsert(session):
            stmt = (
                pg_insert(CacheEntry)
                .values(
                    cache_type=self._cache_type,
                    cache_key=key,
                    content_hash=content_hash,
                    tool_version=tool_version,
                    created_at=now,
                    last_used_at=now,
                    blob_pointer=self._mk_blob_pointer(repo_id, manifest_set_hash),
                )
                .on_conflict_do_update(
                    constraint="uq_cache_type_key",
                    set_={
                        "content_hash": content_hash,
                        "tool_version": tool_version,
                        "last_used_at": now,
                        "blob_pointer": self._mk_blob_pointer(repo_id, manifest_set_hash),
                    },
                )
            )
            await session.execute(stmt)

        run_db(_upsert)

    def invalidate(
        self,
        repo_id: str,
        *,
        manifest_set_hash: str | None = None,
    ) -> int:
        """Remove cached SBOMs for a repo.

        Pass manifest_set_hash to remove a single entry; omit to remove all
        entries for the repo (e.g. on repo deletion).  Returns count removed.
        """
        if manifest_set_hash is not None:
            key = self._cache_key_fn(repo_id, manifest_set_hash)
            pattern = None
        else:
            key = None
            pattern = f"{repo_id}|%"

        async def _delete(session):
            if key is not None:
                result = await session.execute(
                    delete(CacheEntry).where(
                        CacheEntry.cache_type == self._cache_type,
                        CacheEntry.cache_key == key,
                    ).returning(CacheEntry.id)
                )
            else:
                result = await session.execute(
                    delete(CacheEntry).where(
                        CacheEntry.cache_type == self._cache_type,
                        CacheEntry.cache_key.like(pattern),
                    ).returning(CacheEntry.id)
                )
            return len(result.fetchall())

        return run_db(_delete)

    # ── helpers used by intel_fanout implementations ─────────────────────────

    def list_entries(self) -> list[CacheEntry]:
        """Return all cache_entries rows for this cache_type."""
        async def _list(session):
            result = await session.execute(
                select(CacheEntry).where(
                    CacheEntry.cache_type == self._cache_type
                )
            )
            return result.scalars().all()

        return run_db(_list)

    def download_blob_by_entry(self, entry: CacheEntry) -> dict[str, Any] | None:
        """Download the SBOM blob referenced by a cache_entries row.

        Delegates back to the injected s3_key_fn by reconstructing the
        (repo_id, manifest_set_hash) pair from the cache_key.
        """
        # Default key format is '{repo_id}|{manifest_set_hash}'
        parts = entry.cache_key.split("|", 1)
        if len(parts) == 2:
            repo_id, manifest_hash = parts
        else:
            repo_id, manifest_hash = entry.cache_key, ""
        return download_from_minio(self._s3_key_fn(repo_id, manifest_hash))


# ── Container-specific subclass ───────────────────────────────────────────────

def _container_cache_key(image_digest: str, _unused: str = "") -> str:
    """Cache key for a container image is simply its digest."""
    return image_digest


def _container_s3_key(image_digest: str, _unused: str = "") -> str:
    """MinIO object path for a container SBOM blob."""
    return f"sboms/containers/{image_digest}.json"


class ContainerSbomCache(SbomCache):
    """SbomCache variant keyed by image digest (sha256:...) rather than repo+hash.

    The digest IS the cache key — immutable and deterministic — so no compound
    key is needed.  The public API exposes digest-centric methods so callers
    cannot accidentally pass a manifest hash in the wrong position.
    """

    def __init__(self) -> None:
        super().__init__(
            cache_type=_CACHE_TYPE_CONTAINER,
            cache_key_fn=_container_cache_key,
            s3_key_fn=_container_s3_key,
        )

    def get_by_digest(self, image_digest: str) -> dict[str, Any] | None:
        """Return cached SBOM for image_digest, or None on miss."""
        return self.get(image_digest, "")

    def put_by_digest(
        self,
        image_digest: str,
        sbom: dict[str, Any],
        tool_version: str,
    ) -> None:
        """Cache SBOM keyed by image_digest."""
        self.put(image_digest, "", sbom, tool_version)

    def invalidate_by_digest(self, image_digest: str) -> int:
        """Remove a single cached container SBOM. Returns count removed (0 or 1)."""
        return self.invalidate(image_digest, manifest_set_hash="")
