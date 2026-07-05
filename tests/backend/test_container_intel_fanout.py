"""Tests for containers.dispatch_intel_fanout — CVE-triggered SBOM re-matching."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.containers.intel_fanout import (
    dispatch_intel_fanout,
    _version_in_range,
    _sbom_contains_affected,
    _parse_version_tuple,
)
from src.dependencies.sbom_cache import ContainerSbomCache, _CACHE_TYPE_CONTAINER
from src.db.helpers import run_db
from src.db.models import CacheEntry
from sqlalchemy import delete as sa_delete


DIGEST_A = "sha256:" + "aa" * 32
DIGEST_B = "sha256:" + "bb" * 32
TOOL_VER = "syft-1.0.0"

SBOM_WITH_LOG4J = {
    "bomFormat": "CycloneDX",
    "components": [
        {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/log4j-core@2.14.1"},
    ],
}

SBOM_WITHOUT_LOG4J = {
    "bomFormat": "CycloneDX",
    "components": [
        {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"},
    ],
}

AFFECTED_LOG4J = [{"name": "log4j-core", "version_range": "<2.17.2"}]


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


# ── version range helpers ─────────────────────────────────────────────────────


@pytest.mark.parametrize("version,range_,expected", [
    ("2.14.1", "<2.17.2", True),
    ("2.17.2", "<2.17.2", False),
    ("2.18.0", "<2.17.2", False),
    ("2.17.1", "<=2.17.2", True),
    ("2.17.2", "<=2.17.2", True),
    ("2.17.3", "<=2.17.2", False),
    ("3.0.0", ">2.0.0", True),
    ("1.0.0", ">2.0.0", False),
    ("2.0.0", ">=2.0.0", True),
    ("1.9.9", ">=2.0.0", False),
    ("1.0.0", "==1.0.0", True),
    ("1.0.1", "==1.0.0", False),
    ("1.0.0", "!=1.0.0", False),
    ("1.0.1", "!=1.0.0", True),
    ("", "<2.0.0", True),
    ("1.0.0", "", True),
    ("unparseable", "<2.0.0", True),
])
def test_version_in_range(version, range_, expected):
    assert _version_in_range(version, range_) is expected


def test_parse_version_tuple_handles_snapshot():
    assert _parse_version_tuple("2.17.2-SNAPSHOT") == (2, 17, 2)


def test_parse_version_tuple_empty_returns_empty():
    assert _parse_version_tuple("") == ()


# ── sbom_contains_affected ───────────────────────────────────────────────────


def test_sbom_contains_affected_match():
    assert _sbom_contains_affected(SBOM_WITH_LOG4J, AFFECTED_LOG4J) is True


def test_sbom_contains_affected_no_match():
    assert _sbom_contains_affected(SBOM_WITHOUT_LOG4J, AFFECTED_LOG4J) is False


def test_sbom_contains_affected_case_insensitive():
    sbom = {"components": [{"name": "LOG4J-CORE", "version": "2.14.1"}]}
    assert _sbom_contains_affected(sbom, AFFECTED_LOG4J) is True


def test_sbom_contains_affected_artifacts_schema():
    sbom = {"artifacts": [{"name": "log4j-core", "version": "2.14.1"}]}
    assert _sbom_contains_affected(sbom, AFFECTED_LOG4J) is True


# ── dispatch_intel_fanout ────────────────────────────────────────────────────


def test_fanout_re_matches_only_affected_sboms():
    cache = ContainerSbomCache()
    cache.put_by_digest(DIGEST_A, SBOM_WITH_LOG4J, TOOL_VER)
    cache.put_by_digest(DIGEST_B, SBOM_WITHOUT_LOG4J, TOOL_VER)

    mock_grype = MagicMock(return_value=[])
    count = dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, mock_grype)

    assert count == 1
    assert mock_grype.call_count == 1


def test_fanout_returns_zero_when_no_sbom_affected():
    cache = ContainerSbomCache()
    cache.put_by_digest(DIGEST_B, SBOM_WITHOUT_LOG4J, TOOL_VER)

    mock_grype = MagicMock(return_value=[])
    count = dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, mock_grype)
    assert count == 0
    mock_grype.assert_not_called()


def test_fanout_emits_findings(monkeypatch):
    cache = ContainerSbomCache()
    cache.put_by_digest(DIGEST_A, SBOM_WITH_LOG4J, TOOL_VER)

    finding = {"id": "CVE-2021-44228", "severity": "critical", "org_id": "acme-org"}
    mock_grype = MagicMock(return_value=[finding])

    emitted: list[dict] = []

    def fake_emit(*, org_id, finding, scanner_type, source_component):
        emitted.append({"org_id": org_id, "finding": finding, "scanner_type": scanner_type})

    monkeypatch.setattr(
        "src.containers.intel_fanout.emit_finding_created",
        fake_emit,
    )

    dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, mock_grype)

    assert len(emitted) == 1
    assert emitted[0]["org_id"] == "acme-org"
    assert emitted[0]["scanner_type"] == "containers"


def test_fanout_grype_failure_continues_to_next_sbom():
    """A Grype error on one SBOM must not abort the entire fan-out."""
    cache = ContainerSbomCache()
    cache.put_by_digest(DIGEST_A, SBOM_WITH_LOG4J, TOOL_VER)
    cache.put_by_digest(DIGEST_B, SBOM_WITH_LOG4J, TOOL_VER)

    call_count = 0

    def flaky_grype(sbom):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("grype timeout")
        return []

    count = dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, flaky_grype)
    assert count == 2
    assert call_count == 2


def test_fanout_returns_correct_count_multiple_images():
    cache = ContainerSbomCache()
    cache.put_by_digest(DIGEST_A, SBOM_WITH_LOG4J, TOOL_VER)
    cache.put_by_digest(DIGEST_B, SBOM_WITH_LOG4J, TOOL_VER)

    mock_grype = MagicMock(return_value=[])
    count = dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, mock_grype)
    assert count == 2


def test_fanout_empty_cache_returns_zero():
    cache = ContainerSbomCache()
    count = dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, MagicMock())
    assert count == 0


def test_fanout_source_component_is_containers(monkeypatch):
    """Findings must be emitted with scanner_type='containers'."""
    cache = ContainerSbomCache()
    cache.put_by_digest(DIGEST_A, SBOM_WITH_LOG4J, TOOL_VER)

    finding = {"id": "CVE-2021-44228", "severity": "critical", "org_id": "acme-org"}
    emitted: list[dict] = []

    def fake_emit(*, org_id, finding, scanner_type, source_component):
        emitted.append({"scanner_type": scanner_type, "source_component": source_component})

    monkeypatch.setattr("src.containers.intel_fanout.emit_finding_created", fake_emit)
    dispatch_intel_fanout("CVE-2021-44228", AFFECTED_LOG4J, cache, lambda s: [finding])

    assert emitted[0]["scanner_type"] == "containers"
    assert emitted[0]["source_component"] == "containers.intel_fanout"
