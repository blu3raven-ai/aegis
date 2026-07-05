"""Tests for SastBaselineDelta one-hop expansion (AEGIS_SAST_ONE_HOP_EXPANSION flag)."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.code_scanning.baseline_delta import SastBaselineDelta
from src.code_scanning.file_finding_cache import FileFindingCache, Finding
from src.code_scanning.diff_detector import FileDiff


REPO_ID = "acme-org/one-hop-test"
RULE_PACK = "rules-v1.0.0"


def _make_finding(path: str) -> Finding:
    return Finding(file_path=path, line=1, rule_id="sqli", severity="high", message="SQL injection")


def _write(root: Path, rel: str, content: str = "x = 1") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


# ── Flag off — default behavior, no expansion ─────────────────────────────────


def test_flag_off_no_expansion(tmp_path, monkeypatch):
    """When flag is unset, only directly changed files are scanned."""
    monkeypatch.delenv("AEGIS_SAST_ONE_HOP_EXPANSION", raising=False)

    _write(tmp_path, "app.py", "from utils import helper")
    _write(tmp_path, "utils.py", "def helper(): pass")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []

    diff = FileDiff(added=[], modified=["app.py"], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff):
        engine = SastBaselineDelta(cache, mock_runner)
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="base",
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    # Only app.py should be scanned — utils.py is not in the diff
    scanned_paths = {call.args[0].name for call in mock_runner.call_args_list}
    assert "app.py" in scanned_paths
    assert "utils.py" not in scanned_paths


def test_flag_explicitly_false_no_expansion(tmp_path, monkeypatch):
    """AEGIS_SAST_ONE_HOP_EXPANSION=false must not trigger expansion."""
    monkeypatch.setenv("AEGIS_SAST_ONE_HOP_EXPANSION", "false")

    _write(tmp_path, "app.py", "from utils import helper")
    _write(tmp_path, "utils.py", "def helper(): pass")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []

    diff = FileDiff(added=[], modified=["app.py"], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff):
        engine = SastBaselineDelta(cache, mock_runner)
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="base",
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    scanned_paths = {call.args[0].name for call in mock_runner.call_args_list}
    assert "utils.py" not in scanned_paths


# ── Flag on — expansion applied ───────────────────────────────────────────────


def test_flag_on_expands_to_dependency(tmp_path, monkeypatch):
    """When flag is true, files imported by changed files are also scanned."""
    monkeypatch.setenv("AEGIS_SAST_ONE_HOP_EXPANSION", "true")

    _write(tmp_path, "app.py", "from utils import helper")
    _write(tmp_path, "utils.py", "def helper(): pass")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []

    diff = FileDiff(added=[], modified=["app.py"], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff):
        engine = SastBaselineDelta(cache, mock_runner)
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="base",
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    scanned_paths = {call.args[0].name for call in mock_runner.call_args_list}
    # utils.py is a dependency of app.py — must be included in the scan
    assert "utils.py" in scanned_paths
    assert "app.py" in scanned_paths


def test_flag_on_expands_to_dependent(tmp_path, monkeypatch):
    """When flag is true, files that import a changed file are also scanned."""
    monkeypatch.setenv("AEGIS_SAST_ONE_HOP_EXPANSION", "true")

    # consumer.py imports lib.py; lib.py is the file that changed
    _write(tmp_path, "lib.py", "SECRET = 'changed'")
    _write(tmp_path, "consumer.py", "from lib import SECRET")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []

    diff = FileDiff(added=[], modified=["lib.py"], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff):
        engine = SastBaselineDelta(cache, mock_runner)
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="base",
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    scanned_paths = {call.args[0].name for call in mock_runner.call_args_list}
    assert "lib.py" in scanned_paths
    assert "consumer.py" in scanned_paths


def test_flag_on_full_scan_path_unaffected(tmp_path, monkeypatch):
    """Full scan path (baseline_sha=None) must not be altered by the flag."""
    monkeypatch.setenv("AEGIS_SAST_ONE_HOP_EXPANSION", "true")

    _write(tmp_path, "a.py", "x = 1")
    _write(tmp_path, "b.py", "y = 2")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []

    diff_all = FileDiff(added=["a.py", "b.py"], modified=[], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff_all):
        engine = SastBaselineDelta(cache, mock_runner)
        result = engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha=None,  # triggers full scan
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    # Full scan runs regardless of expansion flag
    assert mock_runner.call_count == 2


def test_flag_on_deleted_files_preserved(tmp_path, monkeypatch):
    """Deletion list must not be affected by one-hop expansion."""
    monkeypatch.setenv("AEGIS_SAST_ONE_HOP_EXPANSION", "true")

    _write(tmp_path, "app.py", "x = 1")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []
    cache.invalidate_file.return_value = 1

    diff = FileDiff(added=["app.py"], modified=[], deleted=["gone.py"])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff):
        engine = SastBaselineDelta(cache, mock_runner)
        result = engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="base",
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    # gone.py invalidation must still be called
    cache.invalidate_file.assert_called_once_with(REPO_ID, "gone.py")


def test_flag_case_insensitive(tmp_path, monkeypatch):
    """Flag value comparison must be case-insensitive (TRUE, True, true)."""
    monkeypatch.setenv("AEGIS_SAST_ONE_HOP_EXPANSION", "TRUE")

    _write(tmp_path, "app.py", "from utils import helper")
    _write(tmp_path, "utils.py", "def helper(): pass")

    mock_runner = MagicMock(return_value=[])
    cache = MagicMock(spec=FileFindingCache)
    cache.get.return_value = None
    cache.list_repo_entries.return_value = []

    diff = FileDiff(added=[], modified=["app.py"], deleted=[])
    with patch("src.code_scanning.baseline_delta.compute_file_diff", return_value=diff):
        engine = SastBaselineDelta(cache, mock_runner)
        engine.scan(
            repo_id=REPO_ID,
            checkout_path=tmp_path,
            baseline_sha="base",
            head_sha="head",
            rule_pack_version=RULE_PACK,
        )

    scanned_paths = {call.args[0].name for call in mock_runner.call_args_list}
    assert "utils.py" in scanned_paths
