"""Tests for Phase 7 incremental wiring in the dependencies scanner.

Verifies that _try_incremental_dep_scan:
  - Returns None when AEGIS_USE_INCREMENTAL_DEPS is unset (existing path unchanged)
  - Calls the engine when the flag is true; on cache miss engine still returns results
  - Returns findings on a real cache hit
  - Swallows all exceptions (including adapter stubs) and returns None to fall through
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.dependencies.scanner import _try_incremental_dep_scan


# ── flag off (default) ────────────────────────────────────────────────────────


def test_flag_unset_returns_none(monkeypatch):
    monkeypatch.delenv("AEGIS_USE_INCREMENTAL_DEPS", raising=False)
    assert _try_incremental_dep_scan("acme-org/0", Path("/tmp")) is None


def test_flag_explicit_false_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "false")
    assert _try_incremental_dep_scan("acme-org/0", Path("/tmp")) is None


def test_flag_case_insensitive_false(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "FALSE")
    assert _try_incremental_dep_scan("acme-org/0", Path("/tmp")) is None


# ── flag true, adapter stubs raise NotImplementedError ───────────────────────


def test_flag_true_notimplemented_falls_through(monkeypatch, tmp_path):
    """Adapters raise NotImplementedError → exception caught → None returned."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "true")
    # Adapters are stubs in the test env; engine.scan will raise NotImplementedError
    # via run_syft/run_grype → helper must catch it and return None.
    result = _try_incremental_dep_scan("acme-org/0", Path("/nonexistent"))
    assert result is None


# ── flag true, engine returns results ────────────────────────────────────────

def _patch_engine(findings, cached=True):
    """Return a context manager that injects a mocked engine into the helper."""
    mock_result = MagicMock()
    mock_result.cached = cached
    mock_result.findings = findings

    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    # The helper does local imports; patch the classes/functions at their
    # source module so the local `from X import Y` picks up the mock.
    return (
        patch("src.dependencies.baseline_delta.DepsBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.SbomCache"),
        patch("src.dependencies.grype_adapter.run_grype"),
        patch("src.dependencies.syft_adapter.run_syft"),
        mock_engine,
    )


def test_cache_miss_engine_called_returns_empty(monkeypatch, tmp_path):
    """Cache miss: engine runs but finds nothing — returns empty list, not None."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "true")

    mock_result = MagicMock(cached=False, findings=[])
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.dependencies.baseline_delta.DepsBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.SbomCache"),
        patch("src.dependencies.grype_adapter.run_grype"),
        patch("src.dependencies.syft_adapter.run_syft"),
    ):
        result = _try_incremental_dep_scan("acme-org/0", tmp_path)

    assert result == []
    mock_engine.scan.assert_called_once()


def test_cache_hit_returns_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "true")

    sample = [{"id": "CVE-2021-44228", "severity": "critical"}]
    mock_result = MagicMock(cached=True, findings=sample)
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.dependencies.baseline_delta.DepsBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.SbomCache"),
        patch("src.dependencies.grype_adapter.run_grype"),
        patch("src.dependencies.syft_adapter.run_syft"),
    ):
        result = _try_incremental_dep_scan("acme-org/0", tmp_path)

    assert result == sample


def test_cache_hit_non_none_means_skip_runner(monkeypatch, tmp_path):
    """The caller skips the full-scan runner when the return value is not None."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "true")

    sample = [{"id": "CVE-2020-1234", "severity": "high"}]
    mock_result = MagicMock(cached=True, findings=sample)
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.dependencies.baseline_delta.DepsBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.SbomCache"),
        patch("src.dependencies.grype_adapter.run_grype"),
        patch("src.dependencies.syft_adapter.run_syft"),
    ):
        result = _try_incremental_dep_scan("acme-org/0", tmp_path)

    assert result is not None


# ── engine exceptions are swallowed ──────────────────────────────────────────


def test_engine_scan_exception_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "true")

    mock_engine = MagicMock()
    mock_engine.scan.side_effect = RuntimeError("cache backend down")

    with (
        patch("src.dependencies.baseline_delta.DepsBaselineDelta", return_value=mock_engine),
        patch("src.dependencies.sbom_cache.SbomCache"),
        patch("src.dependencies.grype_adapter.run_grype"),
        patch("src.dependencies.syft_adapter.run_syft"),
    ):
        result = _try_incremental_dep_scan("acme-org/0", tmp_path)

    assert result is None


def test_cache_init_exception_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_DEPS", "true")

    with patch("src.dependencies.sbom_cache.SbomCache", side_effect=Exception("db unavailable")):
        result = _try_incremental_dep_scan("acme-org/0", tmp_path)

    assert result is None
