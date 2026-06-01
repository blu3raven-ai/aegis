"""Integration test: ContainerSbomCache + ContainerBaselineDelta + container intel_fanout.

Exercises the full Phase 2b stack end-to-end against real Postgres + MinIO.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from src.containers.baseline_delta import ContainerBaselineDelta
from src.containers.intel_fanout import dispatch_intel_fanout
from src.dependencies.sbom_cache import ContainerSbomCache, _CACHE_TYPE_CONTAINER
from src.db.helpers import run_db
from src.db.models import CacheEntry
from sqlalchemy import delete as sa_delete


DIGEST_A = "sha256:" + "aa" * 32
DIGEST_B = "sha256:" + "bb" * 32
IMAGE_REF_A = f"registry.example.com/acme-org/payments-api@{DIGEST_A}"
IMAGE_REF_B = f"registry.example.com/acme-org/auth-service@{DIGEST_B}"
TOOL_VER = "syft-1.0.0"

SBOM_WITH_LOG4J = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "metadata": {"toolVersion": TOOL_VER},
    "components": [
        {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/log4j-core@2.14.1"},
        {"name": "netty", "version": "4.1.77.Final", "purl": "pkg:maven/netty@4.1.77.Final"},
    ],
}


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(
            sa_delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE_CONTAINER,
            )
        )
    run_db(_del)
    yield


# ── full flow: miss → scan → cache → hit ─────────────────────────────────────


def test_full_flow_miss_then_hit():
    syft_calls = []

    def mock_syft(ref: str):
        syft_calls.append(ref)
        return SBOM_WITH_LOG4J

    grype_calls = []

    def mock_grype(sbom):
        grype_calls.append(sbom)
        return [{"id": "CVE-2021-44228", "severity": "critical"}]

    cache = ContainerSbomCache()
    engine = ContainerBaselineDelta(cache, mock_syft, mock_grype)

    # First scan — cache miss
    r1 = engine.scan(DIGEST_A, IMAGE_REF_A)
    assert r1.cached is False
    assert len(syft_calls) == 1
    assert syft_calls[0] == IMAGE_REF_A
    assert len(r1.findings) == 1

    # Second scan — same digest → cache hit, no Syft invocation
    r2 = engine.scan(DIGEST_A, IMAGE_REF_A)
    assert r2.cached is True
    assert len(syft_calls) == 1          # still only one call
    assert r1.image_digest == r2.image_digest
    assert len(grype_calls) == 2         # Grype called both times


def test_different_digest_triggers_new_syft_run():
    """A different digest must not share the cache with DIGEST_A."""
    syft_calls = []

    def mock_syft(ref):
        syft_calls.append(ref)
        return SBOM_WITH_LOG4J

    cache = ContainerSbomCache()
    engine = ContainerBaselineDelta(cache, mock_syft, lambda s: [])

    engine.scan(DIGEST_A, IMAGE_REF_A)
    engine.scan(DIGEST_B, IMAGE_REF_B)

    assert len(syft_calls) == 2


# ── intel fanout after populating cache ──────────────────────────────────────


def test_intel_fanout_after_cache_population(monkeypatch):
    cache = ContainerSbomCache()
    engine = ContainerBaselineDelta(cache, lambda ref: SBOM_WITH_LOG4J, lambda s: [])
    engine.scan(DIGEST_A, IMAGE_REF_A)

    emitted: list[dict] = []

    def fake_emit(*, org_id, finding, scanner_type, source_component):
        emitted.append(finding)

    monkeypatch.setattr("src.containers.intel_fanout.emit_finding_created", fake_emit)

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


def test_intel_fanout_skips_unaffected_images(monkeypatch):
    safe_sbom = {
        "bomFormat": "CycloneDX",
        "metadata": {"toolVersion": TOOL_VER},
        "components": [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ],
    }

    cache = ContainerSbomCache()
    engine = ContainerBaselineDelta(cache, lambda ref: safe_sbom, lambda s: [])
    engine.scan(DIGEST_A, IMAGE_REF_A)

    grype_calls = []
    count = dispatch_intel_fanout(
        "CVE-2021-44228",
        [{"name": "log4j-core", "version_range": "<2.17.2"}],
        cache,
        lambda sbom: grype_calls.append(sbom) or [],
    )

    assert count == 0
    assert len(grype_calls) == 0


def test_cache_namespace_isolation():
    """Container and dependency SBOMs must not share cache rows."""
    from src.dependencies.sbom_cache import SbomCache, _CACHE_TYPE

    dep_cache = SbomCache()
    container_cache = ContainerSbomCache()

    dep_sbom = {"bomFormat": "CycloneDX", "components": [{"name": "dep-pkg", "version": "1.0"}]}
    container_sbom = {"bomFormat": "CycloneDX", "components": [{"name": "img-pkg", "version": "2.0"}]}

    # Write a dep SBOM using a key that looks like a digest
    dep_cache.put("acme-org", DIGEST_A, dep_sbom, TOOL_VER)
    container_cache.put_by_digest(DIGEST_A, container_sbom, TOOL_VER)

    # Container cache must return the container SBOM, not the dep SBOM
    result = container_cache.get_by_digest(DIGEST_A)
    assert result is not None
    assert result["components"][0]["name"] == "img-pkg"

    # Dep cache hit for same "key" must also return its own SBOM
    dep_result = dep_cache.get("acme-org", DIGEST_A)
    assert dep_result is not None
    assert dep_result["components"][0]["name"] == "dep-pkg"

    # Clean up dep cache row added by this test
    dep_cache.invalidate("acme-org", manifest_set_hash=DIGEST_A)


def test_grype_failure_does_not_pollute_cache():
    """A Grype failure on a cache miss must leave no entry in the cache."""
    cache = ContainerSbomCache()
    engine = ContainerBaselineDelta(
        cache,
        lambda ref: SBOM_WITH_LOG4J,
        MagicMock(side_effect=RuntimeError("grype fail")),
    )

    import pytest as _pytest
    with _pytest.raises(RuntimeError):
        engine.scan(DIGEST_A, IMAGE_REF_A)

    assert cache.get_by_digest(DIGEST_A) is None
