"""Tests for Phase 7 incremental wiring in the code scanning (SAST) scanner.

Verifies that _try_incremental_sast_scan:
  - Returns None when AEGIS_USE_INCREMENTAL_SAST is unset
  - Calls the engine when the flag is true
  - Returns findings (converted to dicts) on cache hit
  - Swallows exceptions and falls through to full scan
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.code_scanning.scanner import _try_incremental_sast_scan

_REPO_ID = "acme-org"
_RULE_PACK = "p/owasp-top-ten,p/default"


# ── flag off (default) ────────────────────────────────────────────────────────


def test_flag_unset_returns_none(monkeypatch):
    monkeypatch.delenv("AEGIS_USE_INCREMENTAL_SAST", raising=False)
    result = _try_incremental_sast_scan(
        _REPO_ID, Path("/tmp"), baseline_sha=None, head_sha="abc123", rule_pack_version=_RULE_PACK
    )
    assert result is None


def test_flag_explicit_false_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "false")
    result = _try_incremental_sast_scan(
        _REPO_ID, Path("/tmp"), baseline_sha=None, head_sha="abc123", rule_pack_version=_RULE_PACK
    )
    assert result is None


def test_flag_case_insensitive_false(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "FALSE")
    result = _try_incremental_sast_scan(
        _REPO_ID, Path("/tmp"), baseline_sha=None, head_sha="abc123", rule_pack_version=_RULE_PACK
    )
    assert result is None


# ── flag true, adapter stubs ──────────────────────────────────────────────────


def test_flag_true_stub_adapter_falls_through(monkeypatch):
    """Adapter stubs raise NotImplementedError → caught → None returned."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "true")
    result = _try_incremental_sast_scan(
        _REPO_ID, Path("/nonexistent"), baseline_sha=None, head_sha="abc123", rule_pack_version=_RULE_PACK
    )
    assert result is None


# ── flag true, cache miss ─────────────────────────────────────────────────────


def test_cache_miss_engine_called_returns_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "true")

    mock_result = MagicMock(
        findings=[],
        cached_files=0,
        rescanned_files=0,
        deleted_files=0,
    )
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.code_scanning.baseline_delta.SastBaselineDelta", return_value=mock_engine),
        patch("src.code_scanning.file_finding_cache.FileFindingCache"),
        patch("src.code_scanning.opengrep_adapter.run_opengrep"),
    ):
        result = _try_incremental_sast_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="abc123", rule_pack_version=_RULE_PACK
        )

    assert result == []
    mock_engine.scan.assert_called_once()


# ── flag true, cache hit ──────────────────────────────────────────────────────


def test_cache_hit_returns_findings_as_dicts(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "true")

    # Findings can be dicts (already normalised) or dataclass-like objects
    sample_finding = {"rule_id": "python.flask.sql-injection", "severity": "high", "file": "app.py"}
    mock_result = MagicMock(
        findings=[sample_finding],
        cached_files=1,
        rescanned_files=0,
        deleted_files=0,
    )
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.code_scanning.baseline_delta.SastBaselineDelta", return_value=mock_engine),
        patch("src.code_scanning.file_finding_cache.FileFindingCache"),
        patch("src.code_scanning.opengrep_adapter.run_opengrep"),
    ):
        result = _try_incremental_sast_scan(
            _REPO_ID, tmp_path, baseline_sha="base123", head_sha="head456", rule_pack_version=_RULE_PACK
        )

    assert result is not None
    assert len(result) == 1
    assert result[0] == sample_finding


def test_dataclass_findings_converted_to_dicts(monkeypatch, tmp_path):
    """Finding dataclass instances must be serialised to dicts."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "true")

    class FakeFinding:
        rule_id = "test.rule"
        severity = "medium"

    mock_result = MagicMock(
        findings=[FakeFinding()],
        cached_files=1,
        rescanned_files=0,
        deleted_files=0,
    )
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.code_scanning.baseline_delta.SastBaselineDelta", return_value=mock_engine),
        patch("src.code_scanning.file_finding_cache.FileFindingCache"),
        patch("src.code_scanning.opengrep_adapter.run_opengrep"),
    ):
        result = _try_incremental_sast_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="abc", rule_pack_version=_RULE_PACK
        )

    assert result is not None
    assert all(isinstance(f, dict) for f in result)


# ── engine exceptions are swallowed ──────────────────────────────────────────


def test_engine_scan_exception_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "true")

    mock_engine = MagicMock()
    mock_engine.scan.side_effect = RuntimeError("file cache unavailable")

    with (
        patch("src.code_scanning.baseline_delta.SastBaselineDelta", return_value=mock_engine),
        patch("src.code_scanning.file_finding_cache.FileFindingCache"),
        patch("src.code_scanning.opengrep_adapter.run_opengrep"),
    ):
        result = _try_incremental_sast_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="abc", rule_pack_version=_RULE_PACK
        )

    assert result is None


def test_cache_init_exception_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SAST", "true")

    with patch("src.code_scanning.file_finding_cache.FileFindingCache", side_effect=Exception("no db")):
        result = _try_incremental_sast_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="abc", rule_pack_version=_RULE_PACK
        )

    assert result is None
