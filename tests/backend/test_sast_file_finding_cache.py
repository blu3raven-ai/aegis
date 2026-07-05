"""Tests for FileFindingCache — per-file SAST finding cache."""
from __future__ import annotations

import pytest
from sqlalchemy import delete as sa_delete

from src.code_scanning.file_finding_cache import FileFindingCache, Finding, _CACHE_TYPE
from src.db.helpers import run_db
from src.db.models import CacheEntry


REPO_ID = "acme-org/sast-cache-repo"
FILE_A = "src/main.py"
FILE_B = "src/utils.py"
SHA_A1 = "a" * 64
SHA_A2 = "b" * 64  # same file, different content
SHA_B1 = "c" * 64
RULE_PACK_V1 = "rules-v1.0.0"
RULE_PACK_V2 = "rules-v2.0.0"

FINDING_1 = Finding(file_path=FILE_A, line=10, rule_id="sql-injection", severity="high", message="SQL injection risk")
FINDING_2 = Finding(file_path=FILE_A, line=42, rule_id="xss", severity="medium", message="Reflected XSS")


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(
            sa_delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key.like("acme-org/%"),
            )
        )
    run_db(_del)
    yield


# ── get / put basics ─────────────────────────────────────────────────────────


def test_get_returns_none_on_miss():
    cache = FileFindingCache()
    result = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1)
    assert result is None


def test_put_then_get_returns_findings():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1, FINDING_2], RULE_PACK_V1)

    result = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1)
    assert result is not None
    assert len(result) == 2
    assert result[0].rule_id == "sql-injection"
    assert result[1].rule_id == "xss"


def test_put_empty_findings_is_valid():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [], RULE_PACK_V1)

    result = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1)
    assert result == []


def test_get_returns_finding_dataclasses():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_B, SHA_B1, [FINDING_1], RULE_PACK_V1)

    result = cache.get(REPO_ID, FILE_B, SHA_B1, RULE_PACK_V1)
    assert isinstance(result[0], Finding)
    assert result[0].file_path == FILE_A
    assert result[0].line == 10


# ── cache key uniqueness ─────────────────────────────────────────────────────


def test_different_sha_is_cache_miss():
    """Same file path but different sha256 must not return the old findings."""
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)

    result = cache.get(REPO_ID, FILE_A, SHA_A2, RULE_PACK_V1)
    assert result is None


def test_different_file_path_is_separate_entry():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(REPO_ID, FILE_B, SHA_B1, [FINDING_2], RULE_PACK_V1)

    assert cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1)[0].rule_id == "sql-injection"
    assert cache.get(REPO_ID, FILE_B, SHA_B1, RULE_PACK_V1)[0].rule_id == "xss"


def test_different_repo_id_is_separate_entry():
    other_repo = "acme-org/other-repo"
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(other_repo, FILE_A, SHA_A1, [FINDING_2], RULE_PACK_V1)

    r1 = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1)
    r2 = cache.get(other_repo, FILE_A, SHA_A1, RULE_PACK_V1)
    assert r1[0].rule_id == "sql-injection"
    assert r2[0].rule_id == "xss"


# ── rule_pack_version mismatch invalidates ───────────────────────────────────


def test_rule_pack_version_mismatch_returns_none():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)

    # Ask with a different rule pack version → miss
    result = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V2)
    assert result is None


def test_rule_pack_version_match_returns_findings():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V2)

    result = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V2)
    assert result is not None


def test_put_updates_rule_pack_version():
    """Re-putting with a new rule pack version makes the new version queryable."""
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_2], RULE_PACK_V2)

    assert cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1) is None
    result = cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V2)
    assert result is not None
    assert result[0].rule_id == "xss"


# ── invalidate_repo ──────────────────────────────────────────────────────────


def test_invalidate_repo_removes_all_files():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(REPO_ID, FILE_B, SHA_B1, [FINDING_2], RULE_PACK_V1)

    count = cache.invalidate_repo(REPO_ID)
    assert count == 2
    assert cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1) is None
    assert cache.get(REPO_ID, FILE_B, SHA_B1, RULE_PACK_V1) is None


def test_invalidate_repo_returns_zero_on_empty():
    cache = FileFindingCache()
    count = cache.invalidate_repo("acme-org/empty-repo")
    assert count == 0


def test_invalidate_repo_does_not_affect_other_repos():
    other_repo = "acme-org/other-repo"
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(other_repo, FILE_A, SHA_A1, [FINDING_2], RULE_PACK_V1)

    cache.invalidate_repo(REPO_ID)

    assert cache.get(other_repo, FILE_A, SHA_A1, RULE_PACK_V1) is not None


# ── invalidate_file ──────────────────────────────────────────────────────────


def test_invalidate_file_removes_all_sha_variants():
    """invalidate_file should remove entries for all sha256 values of the path."""
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(REPO_ID, FILE_A, SHA_A2, [FINDING_2], RULE_PACK_V1)

    count = cache.invalidate_file(REPO_ID, FILE_A)
    assert count == 2
    assert cache.get(REPO_ID, FILE_A, SHA_A1, RULE_PACK_V1) is None
    assert cache.get(REPO_ID, FILE_A, SHA_A2, RULE_PACK_V1) is None


def test_invalidate_file_does_not_affect_other_files():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(REPO_ID, FILE_B, SHA_B1, [FINDING_2], RULE_PACK_V1)

    cache.invalidate_file(REPO_ID, FILE_A)

    assert cache.get(REPO_ID, FILE_B, SHA_B1, RULE_PACK_V1) is not None


# ── list_repo_entries ────────────────────────────────────────────────────────


def test_list_repo_entries_returns_all_entries():
    cache = FileFindingCache()
    cache.put(REPO_ID, FILE_A, SHA_A1, [FINDING_1], RULE_PACK_V1)
    cache.put(REPO_ID, FILE_B, SHA_B1, [FINDING_2], RULE_PACK_V1)

    entries = cache.list_repo_entries(REPO_ID)
    assert len(entries) == 2


def test_list_repo_entries_empty_for_unknown_repo():
    cache = FileFindingCache()
    entries = cache.list_repo_entries("acme-org/nonexistent")
    assert entries == []
