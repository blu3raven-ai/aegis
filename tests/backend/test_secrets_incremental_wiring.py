"""Tests for Phase 7 incremental wiring in the secrets scanner.

Verifies that _try_incremental_secrets_scan:
  - Returns None when AEGIS_USE_INCREMENTAL_SECRETS is unset
  - Calls the engine when the flag is true
  - Returns findings (converted to dicts) on cache hit / new verifications
  - Swallows exceptions and falls through to full scan
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.secrets.scanner import _try_incremental_secrets_scan

_REPO_ID = "acme-org/0"
_DETECTOR_VERSION = "light"


# ── flag off (default) ────────────────────────────────────────────────────────


def test_flag_unset_returns_none(monkeypatch):
    monkeypatch.delenv("AEGIS_USE_INCREMENTAL_SECRETS", raising=False)
    result = _try_incremental_secrets_scan(
        _REPO_ID, Path("/tmp"), baseline_sha=None, head_sha="abc", detector_version=_DETECTOR_VERSION
    )
    assert result is None


def test_flag_explicit_false_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "false")
    result = _try_incremental_secrets_scan(
        _REPO_ID, Path("/tmp"), baseline_sha=None, head_sha="abc", detector_version=_DETECTOR_VERSION
    )
    assert result is None


def test_flag_case_insensitive_false(monkeypatch):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "FALSE")
    result = _try_incremental_secrets_scan(
        _REPO_ID, Path("/tmp"), baseline_sha=None, head_sha="abc", detector_version=_DETECTOR_VERSION
    )
    assert result is None


# ── flag true, adapter stubs ──────────────────────────────────────────────────


def test_flag_true_stub_adapter_falls_through(monkeypatch):
    """Adapter stubs raise NotImplementedError → caught → None returned."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "true")
    result = _try_incremental_secrets_scan(
        _REPO_ID, Path("/nonexistent"), baseline_sha=None, head_sha="abc", detector_version=_DETECTOR_VERSION
    )
    assert result is None


# ── flag true, no new commits (cache miss path) ───────────────────────────────


def test_no_new_commits_returns_empty_list(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "true")

    mock_result = MagicMock(
        findings=[],
        commits_scanned=0,
        cached_verifications=0,
        new_verifications=0,
    )
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.secrets.baseline_delta.SecretsBaselineDelta", return_value=mock_engine),
        patch("src.secrets.verified_secrets_cache.VerifiedSecretsCache"),
        patch("src.secrets.trufflehog_adapter.run_trufflehog"),
    ):
        result = _try_incremental_secrets_scan(
            _REPO_ID, tmp_path, baseline_sha="base123", head_sha="head456", detector_version=_DETECTOR_VERSION
        )

    assert result == []
    mock_engine.scan.assert_called_once()


# ── flag true, cache hit ──────────────────────────────────────────────────────


def test_cache_hit_returns_findings_as_dicts(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "true")

    sample_finding = {
        "commit_sha": "deadbeef",
        "file_path": "config/secrets.py",
        "line": 10,
        "detector_id": "AWS",
        "secret_hash": "abc123",
        "verified": False,
        "verification_status": "skipped-cache-hit",
    }
    mock_result = MagicMock(
        findings=[sample_finding],
        commits_scanned=1,
        cached_verifications=1,
        new_verifications=0,
    )
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.secrets.baseline_delta.SecretsBaselineDelta", return_value=mock_engine),
        patch("src.secrets.verified_secrets_cache.VerifiedSecretsCache"),
        patch("src.secrets.trufflehog_adapter.run_trufflehog"),
    ):
        result = _try_incremental_secrets_scan(
            _REPO_ID, tmp_path, baseline_sha="base123", head_sha="head456", detector_version=_DETECTOR_VERSION
        )

    assert result is not None
    assert len(result) == 1


def test_secretfinding_dataclass_converted_to_dict(monkeypatch, tmp_path):
    """SecretFinding dataclass instances must be converted to dicts."""
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "true")

    from src.secrets.baseline_delta import SecretFinding

    sf = SecretFinding(
        commit_sha="abc",
        file_path="main.py",
        line=5,
        detector_id="GitHub",
        secret_hash="hash123",
        verified=False,
        verification_status="unverified",
    )
    mock_result = MagicMock(
        findings=[sf],
        commits_scanned=1,
        cached_verifications=0,
        new_verifications=1,
    )
    mock_engine = MagicMock()
    mock_engine.scan.return_value = mock_result

    with (
        patch("src.secrets.baseline_delta.SecretsBaselineDelta", return_value=mock_engine),
        patch("src.secrets.verified_secrets_cache.VerifiedSecretsCache"),
        patch("src.secrets.trufflehog_adapter.run_trufflehog"),
    ):
        result = _try_incremental_secrets_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="head456", detector_version=_DETECTOR_VERSION
        )

    assert result is not None
    assert all(isinstance(f, dict) for f in result)
    assert result[0]["commit_sha"] == "abc"


# ── engine exceptions are swallowed ──────────────────────────────────────────


def test_engine_scan_exception_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "true")

    mock_engine = MagicMock()
    mock_engine.scan.side_effect = RuntimeError("verification cache error")

    with (
        patch("src.secrets.baseline_delta.SecretsBaselineDelta", return_value=mock_engine),
        patch("src.secrets.verified_secrets_cache.VerifiedSecretsCache"),
        patch("src.secrets.trufflehog_adapter.run_trufflehog"),
    ):
        result = _try_incremental_secrets_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="abc", detector_version=_DETECTOR_VERSION
        )

    assert result is None


def test_cache_constructor_exception_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_USE_INCREMENTAL_SECRETS", "true")

    with patch("src.secrets.verified_secrets_cache.VerifiedSecretsCache", side_effect=Exception("db down")):
        result = _try_incremental_secrets_scan(
            _REPO_ID, tmp_path, baseline_sha=None, head_sha="abc", detector_version=_DETECTOR_VERSION
        )

    assert result is None
