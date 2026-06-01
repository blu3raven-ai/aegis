"""Integration test: manifest_hash + SbomCache + DepsBaselineDelta + intel_fanout.

Exercises the full Phase 2a stack end-to-end against real Postgres + MinIO.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.dependencies.manifest_hash import compute_manifest_set_hash
from src.dependencies.sbom_cache import SbomCache, _CACHE_TYPE
from src.dependencies.baseline_delta import DepsBaselineDelta
from src.dependencies.intel_fanout import dispatch_intel_fanout
from src.db.helpers import run_db
from src.db.models import CacheEntry
from sqlalchemy import delete as sa_delete


REPO_ID = "acme-org/integration-repo"
TOOL_VER = "syft-1.0.0"

SBOM_V1 = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "metadata": {"toolVersion": TOOL_VER},
    "components": [
        {"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
        {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/log4j-core@2.14.1"},
    ],
}


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


def _checkout(root: Path, files: dict[str, bytes]) -> None:
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)


# ── full flow: miss → scan → cache → hit ─────────────────────────────────────


def test_full_flow_miss_then_hit(tmp_path):
    _checkout(tmp_path, {"package-lock.json": b'{"v":1}', "go.mod": b"module example.com"})

    syft_calls = []

    def mock_syft(path: Path):
        syft_calls.append(path)
        return SBOM_V1

    mock_grype_calls = []

    def mock_grype(sbom):
        mock_grype_calls.append(sbom)
        return [{"id": "CVE-2021-44228", "severity": "critical"}]

    cache = SbomCache()
    engine = DepsBaselineDelta(cache, mock_syft, mock_grype)

    # First scan — cache miss
    r1 = engine.scan(REPO_ID, tmp_path)
    assert r1.cached is False
    assert len(syft_calls) == 1
    assert len(r1.findings) == 1

    # Second scan — same manifests → cache hit, no Syft invocation
    r2 = engine.scan(REPO_ID, tmp_path)
    assert r2.cached is True
    assert len(syft_calls) == 1          # still only one call
    assert r1.manifest_set_hash == r2.manifest_set_hash
    assert len(mock_grype_calls) == 2    # Grype called both times


def test_manifest_change_invalidates_cache(tmp_path):
    _checkout(tmp_path, {"package-lock.json": b'{"v":1}'})

    syft_calls = []

    def mock_syft(path):
        syft_calls.append(path)
        return SBOM_V1

    cache = SbomCache()
    engine = DepsBaselineDelta(cache, mock_syft, lambda s: [])

    engine.scan(REPO_ID, tmp_path)
    assert len(syft_calls) == 1

    # Simulate a dependency update
    (tmp_path / "package-lock.json").write_bytes(b'{"v":2}')
    r2 = engine.scan(REPO_ID, tmp_path)

    assert r2.cached is False
    assert len(syft_calls) == 2


# ── intel fanout after populating cache ──────────────────────────────────────


def test_intel_fanout_after_cache_population(tmp_path, monkeypatch):
    _checkout(tmp_path, {"pom.xml": b"<project/>"})

    cache = SbomCache()
    engine = DepsBaselineDelta(cache, lambda p: SBOM_V1, lambda s: [])
    engine.scan(REPO_ID, tmp_path)

    emitted: list[dict] = []

    def fake_emit(*, org_id, finding, scanner_type, source_component):
        emitted.append(finding)

    monkeypatch.setattr("src.dependencies.intel_fanout.emit_finding_created", fake_emit)

    finding = {"id": "CVE-2021-44228", "severity": "critical", "org_id": "acme-org"}
    affected = [{"name": "log4j-core", "version_range": "<2.17.2"}]

    count = dispatch_intel_fanout(
        "CVE-2021-44228",
        affected,
        cache,
        lambda sbom: [finding],
    )

    assert count == 1
    assert len(emitted) == 1


def test_intel_fanout_skips_unaffected_repos(tmp_path):
    _checkout(tmp_path, {"requirements.txt": b"requests==2.31.0"})

    safe_sbom = {
        "bomFormat": "CycloneDX",
        "metadata": {"toolVersion": TOOL_VER},
        "components": [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ],
    }

    cache = SbomCache()
    engine = DepsBaselineDelta(cache, lambda p: safe_sbom, lambda s: [])
    engine.scan(REPO_ID, tmp_path)

    grype_calls = []
    count = dispatch_intel_fanout(
        "CVE-2021-44228",
        [{"name": "log4j-core", "version_range": "<2.17.2"}],
        cache,
        lambda sbom: grype_calls.append(sbom) or [],
    )

    assert count == 0
    assert len(grype_calls) == 0


# ── cache hash consistency across module boundaries ──────────────────────────


def test_manifest_hash_matches_between_hash_module_and_cache(tmp_path):
    """Hash computed by manifest_hash module must equal the key stored by SbomCache."""
    _checkout(tmp_path, {"Cargo.lock": b"[package]"})

    expected_hash = compute_manifest_set_hash(tmp_path)
    cache = SbomCache()
    engine = DepsBaselineDelta(cache, lambda p: SBOM_V1, lambda s: [])
    result = engine.scan(REPO_ID, tmp_path)

    assert result.manifest_set_hash == expected_hash

    # Verify the cache row uses the same hash in its key
    async def _fetch(session):
        from sqlalchemy import select
        from src.dependencies.sbom_cache import _cache_key
        r = await session.execute(
            select(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key == _cache_key(REPO_ID, expected_hash),
            )
        )
        return r.scalars().first()

    entry = run_db(_fetch)
    assert entry is not None
    assert expected_hash in entry.cache_key
