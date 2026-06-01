"""Tests for SbomCache — put/get/invalidate + MinIO blob round-trips.

Uses the session-wide Postgres + MinIO containers from conftest.py.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from src.dependencies.sbom_cache import SbomCache, _cache_key, _s3_key, _CACHE_TYPE
from src.db.helpers import run_db
from src.db.models import CacheEntry
from sqlalchemy import select


SAMPLE_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
    ],
}

REPO_ID = "acme-org/test-repo"
HASH_A = "aaaa" * 16  # 64-char placeholder
HASH_B = "bbbb" * 16
TOOL_VER = "syft-1.0.0"


@pytest.fixture(autouse=True)
def _clean_cache_entries():
    """Remove test rows before each test so they don't interfere."""
    async def _del(session):
        from sqlalchemy import delete as sa_delete
        await session.execute(
            sa_delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key.like("acme-org/%"),
            )
        )

    run_db(_del)
    yield


# ── put then get ─────────────────────────────────────────────────────────────


def test_put_then_get_returns_same_sbom():
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)
    result = cache.get(REPO_ID, HASH_A)
    assert result is not None
    assert result["bomFormat"] == "CycloneDX"
    assert result["components"][0]["name"] == "lodash"


def test_get_miss_returns_none():
    cache = SbomCache()
    result = cache.get(REPO_ID, "0000" * 16)
    assert result is None


def test_put_overwrites_existing_entry():
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, {"version": 1}, TOOL_VER)
    cache.put(REPO_ID, HASH_A, {"version": 2}, "syft-2.0.0")
    result = cache.get(REPO_ID, HASH_A)
    assert result["version"] == 2


# ── cache_entries row correctness ────────────────────────────────────────────


def test_put_writes_correct_cache_entry_row():
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)

    async def _fetch(session):
        result = await session.execute(
            select(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key == _cache_key(REPO_ID, HASH_A),
            )
        )
        return result.scalars().first()

    entry: CacheEntry | None = run_db(_fetch)
    assert entry is not None
    assert entry.tool_version == TOOL_VER
    expected_hash = hashlib.sha256(
        json.dumps(SAMPLE_SBOM, sort_keys=True).encode()
    ).hexdigest()
    assert entry.content_hash == expected_hash
    assert HASH_A in entry.blob_pointer


def test_put_blob_pointer_format():
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)

    async def _fetch(session):
        result = await session.execute(
            select(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key == _cache_key(REPO_ID, HASH_A),
            )
        )
        return result.scalars().first()

    entry = run_db(_fetch)
    assert entry.blob_pointer.startswith("s3://sboms/")
    assert HASH_A in entry.blob_pointer


# ── invalidate ────────────────────────────────────────────────────────────────


def test_invalidate_single_entry():
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)
    cache.put(REPO_ID, HASH_B, SAMPLE_SBOM, TOOL_VER)

    removed = cache.invalidate(REPO_ID, manifest_set_hash=HASH_A)
    assert removed == 1
    assert cache.get(REPO_ID, HASH_A) is None
    assert cache.get(REPO_ID, HASH_B) is not None


def test_invalidate_all_for_repo():
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)
    cache.put(REPO_ID, HASH_B, SAMPLE_SBOM, TOOL_VER)

    removed = cache.invalidate(REPO_ID)
    assert removed == 2
    assert cache.get(REPO_ID, HASH_A) is None
    assert cache.get(REPO_ID, HASH_B) is None


def test_invalidate_nonexistent_returns_zero():
    cache = SbomCache()
    removed = cache.invalidate("acme-org/ghost-repo")
    assert removed == 0


def test_invalidate_one_repo_does_not_affect_another():
    cache = SbomCache()
    other_repo = "acme-org/other-repo"
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)
    cache.put(other_repo, HASH_A, SAMPLE_SBOM, TOOL_VER)

    cache.invalidate(REPO_ID)
    assert cache.get(other_repo, HASH_A) is not None


# ── MinIO blob round-trip ─────────────────────────────────────────────────────


def test_minio_blob_contains_correct_json(s3_endpoint):
    """s3_endpoint fixture skips if MinIO not available."""
    from src.shared.sbom_storage import download_from_minio

    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, SAMPLE_SBOM, TOOL_VER)

    blob = download_from_minio(_s3_key(REPO_ID, HASH_A))
    assert blob is not None
    assert blob["bomFormat"] == "CycloneDX"
