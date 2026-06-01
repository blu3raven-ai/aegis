"""Tests for DepsBaselineDelta — cache-aware scan engine."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from src.dependencies.baseline_delta import DepsBaselineDelta, ScanResult


REPO_ID = "acme-org/delta-repo"
SAMPLE_SBOM = {"bomFormat": "CycloneDX", "components": []}
SAMPLE_FINDINGS = [{"id": "CVE-2021-44228", "severity": "critical"}]


def _write(root: Path, name: str, content: bytes = b"x") -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


# ── cache hit path ────────────────────────────────────────────────────────────


def test_cache_hit_skips_syft(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"v":1}')

    mock_cache = MagicMock()
    mock_cache.get.return_value = SAMPLE_SBOM

    mock_syft = MagicMock()
    mock_grype = MagicMock(return_value=SAMPLE_FINDINGS)

    engine = DepsBaselineDelta(mock_cache, mock_syft, mock_grype)
    result = engine.scan(REPO_ID, tmp_path)

    mock_syft.assert_not_called()
    mock_grype.assert_called_once_with(SAMPLE_SBOM)
    assert result.cached is True
    assert result.findings == SAMPLE_FINDINGS


def test_cache_hit_result_shape(tmp_path):
    _write(tmp_path, "go.mod", b"module example.com")

    mock_cache = MagicMock()
    mock_cache.get.return_value = SAMPLE_SBOM

    engine = DepsBaselineDelta(mock_cache, MagicMock(), MagicMock(return_value=[]))
    result = engine.scan(REPO_ID, tmp_path)

    assert isinstance(result, ScanResult)
    assert result.cached is True
    assert len(result.manifest_set_hash) == 64
    assert result.duration_ms >= 0


# ── cache miss path ───────────────────────────────────────────────────────────


def test_cache_miss_calls_syft_and_writes_cache(tmp_path):
    _write(tmp_path, "requirements.txt", b"requests==2.31.0")

    mock_cache = MagicMock()
    mock_cache.get.return_value = None  # cache miss

    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(return_value=SAMPLE_FINDINGS)

    engine = DepsBaselineDelta(mock_cache, mock_syft, mock_grype)
    result = engine.scan(REPO_ID, tmp_path)

    mock_syft.assert_called_once_with(tmp_path)
    mock_cache.put.assert_called_once()
    assert result.cached is False
    assert result.findings == SAMPLE_FINDINGS


def test_cache_miss_put_called_with_correct_hash(tmp_path):
    _write(tmp_path, "Cargo.lock", b"[package]")

    mock_cache = MagicMock()
    mock_cache.get.return_value = None

    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(return_value=[])

    engine = DepsBaselineDelta(mock_cache, mock_syft, mock_grype)
    result = engine.scan(REPO_ID, tmp_path)

    put_args = mock_cache.put.call_args
    assert put_args[0][0] == REPO_ID
    assert put_args[0][1] == result.manifest_set_hash
    assert put_args[0][2] == SAMPLE_SBOM


def test_cache_miss_tool_version_from_sbom_metadata(tmp_path):
    _write(tmp_path, "go.mod", b"module example.com")
    sbom_with_version = {
        **SAMPLE_SBOM,
        "metadata": {"toolVersion": "syft-0.96.0"},
    }

    mock_cache = MagicMock()
    mock_cache.get.return_value = None
    mock_syft = MagicMock(return_value=sbom_with_version)
    mock_grype = MagicMock(return_value=[])

    engine = DepsBaselineDelta(mock_cache, mock_syft, mock_grype)
    engine.scan(REPO_ID, tmp_path)

    put_args = mock_cache.put.call_args
    assert put_args[0][3] == "syft-0.96.0"


def test_cache_not_written_when_grype_fails(tmp_path):
    """If Grype raises, the SBOM must not be cached (avoid caching a broken result)."""
    _write(tmp_path, "pom.xml", b"<project/>")

    mock_cache = MagicMock()
    mock_cache.get.return_value = None
    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(side_effect=RuntimeError("grype exploded"))

    engine = DepsBaselineDelta(mock_cache, mock_syft, mock_grype)
    with pytest.raises(RuntimeError, match="grype exploded"):
        engine.scan(REPO_ID, tmp_path)

    mock_cache.put.assert_not_called()


def test_second_scan_same_manifest_hits_cache(tmp_path):
    _write(tmp_path, "yarn.lock", b"yarn-v1")

    real_sbom = {"bomFormat": "CycloneDX", "components": []}
    put_store: dict = {}

    class FakeCache:
        def get(self, repo_id, h):
            return put_store.get((repo_id, h))

        def put(self, repo_id, h, sbom, tv):
            put_store[(repo_id, h)] = sbom

    syft_call_count = 0

    def counting_syft(path):
        nonlocal syft_call_count
        syft_call_count += 1
        return real_sbom

    engine = DepsBaselineDelta(FakeCache(), counting_syft, lambda s: [])
    r1 = engine.scan(REPO_ID, tmp_path)
    r2 = engine.scan(REPO_ID, tmp_path)

    assert r1.cached is False
    assert r2.cached is True
    assert syft_call_count == 1


# ── result fields ─────────────────────────────────────────────────────────────


def test_scan_result_has_duration_ms(tmp_path):
    mock_cache = MagicMock()
    mock_cache.get.return_value = SAMPLE_SBOM
    engine = DepsBaselineDelta(mock_cache, MagicMock(), MagicMock(return_value=[]))
    result = engine.scan(REPO_ID, tmp_path)
    assert isinstance(result.duration_ms, int)
    assert result.duration_ms >= 0
