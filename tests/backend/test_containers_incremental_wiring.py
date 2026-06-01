"""Tests for Phase 7 incremental wiring in the container scanner.

Verifies that _try_incremental_container_scan:
  - Returns None when AEGIS_USE_INCREMENTAL_CONTAINER is unset
  - Calls the engine when the flag is true
  - Returns findings on cache hit
  - Swallows exceptions and falls through to full scan
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.containers.scanner import _try_incremental_container_scan

_DIGEST = "sha256:abc123def456"
_IMAGE = "registry.example.com/myapp:latest"


# ── flag off (default) ────────────────────────────────────────────────────────


def test_flag_unset_returns_none(monkeypatch):
    monkeypatch.delenv("AEGIS_USE_INCREMENTAL_CONTAINER", raising=False)
    assert _try_incremental_container_scan(_DIGEST, _IMAGE) is None


def test_flag_explicit_false_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "false")
    assert _try_incremental_container_scan(_DIGEST, _IMAGE) is None


def test_flag_case_insensitive_false(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "FALSE")
    assert _try_incremental_container_scan(_DIGEST, _IMAGE) is None


# ── flag true, adapter stubs ──────────────────────────────────────────────────


def test_flag_true_stub_adapter_falls_through(monkeypatch):
    """Adapter stubs raise NotImplementedError → caught → None returned."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "true")
    result = _try_incremental_container_scan(_DIGEST, _IMAGE)
    assert result is None


# ── flag true, cache miss ─────────────────────────────────────────────────────


def test_cache_miss_engine_called_returns_empty(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "true")

    mock_result = MagicMock(cached=False, findings=[])
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.containers.baseline_delta.ContainerBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.ContainerSbomCache"),
        patch("src.containers.grype_adapter.run_grype"),
        patch("src.containers.syft_adapter.run_syft"),
    ):
        result = _try_incremental_container_scan(_DIGEST, _IMAGE)

    assert result == []
    mock_engine.scan.assert_called_once_with(image_digest=_DIGEST, image_pull_ref=_IMAGE)


# ── flag true, cache hit ──────────────────────────────────────────────────────


def test_cache_hit_returns_findings(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "true")

    sample = [{"imageDigest": _DIGEST, "severity": "high"}]
    mock_result = MagicMock(cached=True, findings=sample)
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.containers.baseline_delta.ContainerBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.ContainerSbomCache"),
        patch("src.containers.grype_adapter.run_grype"),
        patch("src.containers.syft_adapter.run_syft"),
    ):
        result = _try_incremental_container_scan(_DIGEST, _IMAGE)

    assert result == sample


def test_cache_hit_non_none_means_skip_runner(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "true")

    mock_result = MagicMock(cached=True, findings=[{"severity": "critical"}])
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.containers.baseline_delta.ContainerBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.ContainerSbomCache"),
        patch("src.containers.grype_adapter.run_grype"),
        patch("src.containers.syft_adapter.run_syft"),
    ):
        result = _try_incremental_container_scan(_DIGEST, _IMAGE)

    assert result is not None


# ── engine exceptions are swallowed ──────────────────────────────────────────


def test_engine_scan_exception_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "true")

    mock_engine = MagicMock()
    mock_engine.scan.side_effect = RuntimeError("sbom cache unavailable")

    with (
        patch("src.containers.baseline_delta.ContainerBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.ContainerSbomCache"),
        patch("src.containers.grype_adapter.run_grype"),
        patch("src.containers.syft_adapter.run_syft"),
    ):
        result = _try_incremental_container_scan(_DIGEST, _IMAGE)

    assert result is None


def test_cache_constructor_exception_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_CONTAINER", "true")

    with patch("src.dependencies.sbom_cache.ContainerSbomCache", side_effect=Exception("db down")):
        result = _try_incremental_container_scan(_DIGEST, _IMAGE)

    assert result is None
