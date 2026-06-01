"""Tests for ContainerBaselineDelta — cache-aware container image scan engine."""
from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from src.containers.baseline_delta import ContainerBaselineDelta, ContainerScanResult

DIGEST_A = "sha256:aaaa" + "a" * 59
IMAGE_REF = "registry.example.com/payments-api@" + DIGEST_A
SAMPLE_SBOM = {"bomFormat": "CycloneDX", "components": []}
SAMPLE_FINDINGS = [{"id": "CVE-2021-44228", "severity": "critical"}]


# ── cache hit path ────────────────────────────────────────────────────────────


def test_cache_hit_skips_syft():
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = SAMPLE_SBOM

    mock_syft = MagicMock()
    mock_grype = MagicMock(return_value=SAMPLE_FINDINGS)

    engine = ContainerBaselineDelta(mock_cache, mock_syft, mock_grype)
    result = engine.scan(DIGEST_A, IMAGE_REF)

    mock_syft.assert_not_called()
    mock_grype.assert_called_once_with(SAMPLE_SBOM)
    assert result.cached is True
    assert result.findings == SAMPLE_FINDINGS


def test_cache_hit_result_shape():
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = SAMPLE_SBOM

    engine = ContainerBaselineDelta(mock_cache, MagicMock(), MagicMock(return_value=[]))
    result = engine.scan(DIGEST_A, IMAGE_REF)

    assert isinstance(result, ContainerScanResult)
    assert result.cached is True
    assert result.image_digest == DIGEST_A
    assert result.duration_ms >= 0


def test_cache_hit_uses_digest_not_pull_ref():
    """Verify cache lookup uses the digest, not the pull ref."""
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = SAMPLE_SBOM

    engine = ContainerBaselineDelta(mock_cache, MagicMock(), MagicMock(return_value=[]))
    engine.scan(DIGEST_A, IMAGE_REF)

    mock_cache.get_by_digest.assert_called_once_with(DIGEST_A)


# ── cache miss path ───────────────────────────────────────────────────────────


def test_cache_miss_calls_syft_with_pull_ref():
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = None

    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(return_value=SAMPLE_FINDINGS)

    engine = ContainerBaselineDelta(mock_cache, mock_syft, mock_grype)
    result = engine.scan(DIGEST_A, IMAGE_REF)

    mock_syft.assert_called_once_with(IMAGE_REF)
    mock_cache.put_by_digest.assert_called_once()
    assert result.cached is False
    assert result.findings == SAMPLE_FINDINGS


def test_cache_miss_put_called_with_correct_digest():
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = None

    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(return_value=[])

    engine = ContainerBaselineDelta(mock_cache, mock_syft, mock_grype)
    result = engine.scan(DIGEST_A, IMAGE_REF)

    put_args = mock_cache.put_by_digest.call_args
    assert put_args[0][0] == DIGEST_A
    assert put_args[0][1] == SAMPLE_SBOM


def test_cache_miss_tool_version_from_sbom_metadata():
    sbom_with_version = {
        **SAMPLE_SBOM,
        "metadata": {"toolVersion": "syft-0.96.0"},
    }
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = None
    mock_syft = MagicMock(return_value=sbom_with_version)
    mock_grype = MagicMock(return_value=[])

    engine = ContainerBaselineDelta(mock_cache, mock_syft, mock_grype)
    engine.scan(DIGEST_A, IMAGE_REF)

    put_args = mock_cache.put_by_digest.call_args
    assert put_args[0][2] == "syft-0.96.0"


def test_cache_miss_tool_version_fallback_to_sentinel():
    """When the SBOM has no version metadata, sentinel value is stored."""
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = None
    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(return_value=[])

    engine = ContainerBaselineDelta(mock_cache, mock_syft, mock_grype)
    engine.scan(DIGEST_A, IMAGE_REF)

    put_args = mock_cache.put_by_digest.call_args
    assert put_args[0][2] == "syft-unknown"


def test_cache_not_written_when_grype_fails():
    """If Grype raises, the SBOM must not be cached (avoid caching a broken result)."""
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = None
    mock_syft = MagicMock(return_value=SAMPLE_SBOM)
    mock_grype = MagicMock(side_effect=RuntimeError("grype exploded"))

    engine = ContainerBaselineDelta(mock_cache, mock_syft, mock_grype)
    with pytest.raises(RuntimeError, match="grype exploded"):
        engine.scan(DIGEST_A, IMAGE_REF)

    mock_cache.put_by_digest.assert_not_called()


def test_second_scan_same_digest_hits_cache():
    """Same digest → second scan must reuse the cached SBOM and skip Syft."""
    real_sbom = {"bomFormat": "CycloneDX", "components": []}
    put_store: dict = {}

    class FakeCache:
        def get_by_digest(self, digest):
            return put_store.get(digest)

        def put_by_digest(self, digest, sbom, tv):
            put_store[digest] = sbom

    syft_call_count = 0

    def counting_syft(ref):
        nonlocal syft_call_count
        syft_call_count += 1
        return real_sbom

    engine = ContainerBaselineDelta(FakeCache(), counting_syft, lambda s: [])
    r1 = engine.scan(DIGEST_A, IMAGE_REF)
    r2 = engine.scan(DIGEST_A, IMAGE_REF)

    assert r1.cached is False
    assert r2.cached is True
    assert syft_call_count == 1


# ── result fields ─────────────────────────────────────────────────────────────


def test_scan_result_has_duration_ms():
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = SAMPLE_SBOM
    engine = ContainerBaselineDelta(mock_cache, MagicMock(), MagicMock(return_value=[]))
    result = engine.scan(DIGEST_A, IMAGE_REF)
    assert isinstance(result.duration_ms, int)
    assert result.duration_ms >= 0


def test_scan_result_image_digest_preserved():
    mock_cache = MagicMock()
    mock_cache.get_by_digest.return_value = SAMPLE_SBOM
    engine = ContainerBaselineDelta(mock_cache, MagicMock(), MagicMock(return_value=[]))
    result = engine.scan(DIGEST_A, IMAGE_REF)
    assert result.image_digest == DIGEST_A
