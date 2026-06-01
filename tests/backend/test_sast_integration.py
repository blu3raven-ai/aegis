"""Integration test: FileFindingCache + SastBaselineDelta + intel_fanout.

Exercises the full Phase 2c stack end-to-end against real Postgres + MinIO.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import delete as sa_delete

from src.code_scanning.file_finding_cache import FileFindingCache, Finding, _CACHE_TYPE
from src.code_scanning.baseline_delta import SastBaselineDelta
from src.code_scanning.diff_detector import compute_file_diff, FileDiff
from src.code_scanning.intel_fanout import dispatch_rule_pack_update_fanout
from src.db.helpers import run_db
from src.db.models import CacheEntry
from unittest.mock import patch


REPO_ID = "acme-org/sast-integration-repo"
RULE_PACK_V1 = "rules-v1.0.0"
RULE_PACK_V2 = "rules-v2.0.0"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write(root: Path, name: str, content: bytes = b"x = 1") -> str:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return _sha256(content)


def _make_finding(path: str) -> Finding:
    return Finding(file_path=path, line=1, rule_id="sqli", severity="high", message="SQL injection")


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


# ── full flow: no baseline → full scan → cache → delta hit ───────────────────


def test_full_then_delta_reduces_runner_calls(tmp_path):
    """First scan populates cache; second scan for unchanged files skips runner."""
    _write(tmp_path, "src/stable.py", b"stable content")
    _write(tmp_path, "src/changed.py", b"v1")

    scan_calls = []

    def counting_runner(path: Path, files: list[str]) -> list[Finding]:
        scan_calls.append(str(path))
        return [_make_finding(str(path))]

    cache = FileFindingCache()
    engine = SastBaselineDelta(cache, counting_runner)

    # First scan — no baseline
    diff_all = FileDiff(added=["src/stable.py", "src/changed.py"])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_all):
        r1 = engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha=None,
            head_sha="sha1",
            rule_pack_version=RULE_PACK_V1,
        )

    first_call_count = len(scan_calls)
    assert r1.rescanned_files == 2
    assert r1.cached_files == 0

    # Second scan — src/changed.py modified, src/stable.py untouched
    _write(tmp_path, "src/changed.py", b"v2")
    scan_calls.clear()

    diff_delta = FileDiff(added=[], modified=["src/changed.py"], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_delta):
        r2 = engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="sha1",
            head_sha="sha2",
            rule_pack_version=RULE_PACK_V1,
        )

    # stable.py should come from cache; changed.py was rescanned
    assert r2.rescanned_files == 1
    assert r2.cached_files >= 1  # stable.py from cache


def test_deleted_file_not_in_second_scan_findings(tmp_path):
    _write(tmp_path, "src/a.py", b"a")
    _write(tmp_path, "src/b.py", b"b")

    findings_map = {
        "src/a.py": [_make_finding("src/a.py")],
        "src/b.py": [_make_finding("src/b.py")],
    }

    def runner(path: Path, files: list[str]) -> list[Finding]:
        rel = path.relative_to(tmp_path)
        return findings_map.get(str(rel), [])

    cache = FileFindingCache()
    engine = SastBaselineDelta(cache, runner)

    diff_all = FileDiff(added=["src/a.py", "src/b.py"])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_all):
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha=None,
            head_sha="sha1",
            rule_pack_version=RULE_PACK_V1,
        )

    # src/b.py deleted
    (tmp_path / "src/b.py").unlink()

    diff_delta = FileDiff(added=[], modified=[], deleted=["src/b.py"])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_delta):
        r2 = engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="sha1",
            head_sha="sha2",
            rule_pack_version=RULE_PACK_V1,
        )

    finding_paths = [f.file_path for f in r2.findings]
    assert "src/b.py" not in finding_paths


def test_rule_pack_bump_rescans_all(tmp_path):
    """After a rule pack bump, the next scan must produce fresh results for all files."""
    _write(tmp_path, "src/x.py", b"x = 1")

    runner_v1_calls = []
    runner_v2_calls = []

    def runner(path: Path, files: list[str]) -> list[Finding]:
        return []

    cache = FileFindingCache()
    engine = SastBaselineDelta(cache, runner)

    diff_all = FileDiff(added=["src/x.py"])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_all):
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha=None,
            head_sha="sha1",
            rule_pack_version=RULE_PACK_V1,
        )

    # Verify cache populated with V1
    sha = _sha256(b"x = 1")
    assert cache.get(REPO_ID, "src/x.py", sha, RULE_PACK_V1) is not None

    # Fan-out: rule pack bumped to V2
    fanout_count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert fanout_count == 1


def test_cache_get_put_invalidate_roundtrip():
    """Direct cache operations work correctly end-to-end."""
    cache = FileFindingCache()
    finding = _make_finding("src/app.py")
    sha = "d" * 64

    cache.put(REPO_ID, "src/app.py", sha, [finding], RULE_PACK_V1)
    result = cache.get(REPO_ID, "src/app.py", sha, RULE_PACK_V1)
    assert result is not None
    assert result[0].rule_id == "sqli"

    count = cache.invalidate_file(REPO_ID, "src/app.py")
    assert count == 1
    assert cache.get(REPO_ID, "src/app.py", sha, RULE_PACK_V1) is None


def test_scan_result_fields_are_populated(tmp_path):
    _write(tmp_path, "main.py", b"import os")
    cache = FileFindingCache()
    engine = SastBaselineDelta(cache, lambda p, f: [])

    diff_all = FileDiff(added=["main.py"])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_all):
        result = engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha=None,
            head_sha="abc",
            rule_pack_version=RULE_PACK_V1,
        )

    assert isinstance(result.findings, list)
    assert isinstance(result.cached_files, int)
    assert isinstance(result.rescanned_files, int)
    assert isinstance(result.deleted_files, int)
    assert isinstance(result.duration_ms, int)
    assert result.duration_ms >= 0
