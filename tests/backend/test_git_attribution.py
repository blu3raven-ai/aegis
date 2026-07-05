"""Tests for the git blame commit attribution helper."""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.shared.git_attribution import (
    CommitAttribution,
    _find_pr_url,
    _get_remote_url,
    _parse_porcelain,
    _parse_unix_with_tz,
    attribute_to_commit,
)

# ---------------------------------------------------------------------------
# Porcelain output parsing
# ---------------------------------------------------------------------------

SAMPLE_PORCELAIN = """\
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 1 1 1
author Jane Developer
author-mail <jane@acme-org.example>
author-time 1700000000
author-tz +0000
committer Jane Developer
committer-mail <jane@acme-org.example>
committer-time 1700000000
committer-tz +0000
summary fix: patch the vulnerability
filename src/app.py
\tdef vulnerable_function():
"""


def test_parse_porcelain_extracts_sha():
    result = _parse_porcelain(SAMPLE_PORCELAIN, Path("/tmp"))
    assert result is not None
    assert result.commit_sha == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def test_parse_porcelain_extracts_author():
    result = _parse_porcelain(SAMPLE_PORCELAIN, Path("/tmp"))
    assert result is not None
    assert result.author_email == "jane@acme-org.example"
    assert result.author_name == "Jane Developer"


def test_parse_porcelain_authored_at_is_utc():
    result = _parse_porcelain(SAMPLE_PORCELAIN, Path("/tmp"))
    assert result is not None
    assert result.authored_at.tzinfo is not None
    assert result.authored_at == datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)


def test_parse_porcelain_empty_returns_none():
    assert _parse_porcelain("", Path("/tmp")) is None


def test_parse_porcelain_short_sha_returns_none():
    bad = "abc 1 1 1\nauthor X\nauthor-mail <x@x>\nauthor-time 1700000000\nauthor-tz +0000\n\tcode\n"
    assert _parse_porcelain(bad, Path("/tmp")) is None


def test_parse_porcelain_missing_author_time_returns_none():
    no_time = """\
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 1 1 1
author No Time
author-mail <x@x>
author-tz +0000
\tcode
"""
    assert _parse_porcelain(no_time, Path("/tmp")) is None


# ---------------------------------------------------------------------------
# PR URL extraction
# ---------------------------------------------------------------------------

def test_pr_url_extracted_from_merge_commit():
    commit_body = "Merge pull request #42 from acme-org/feature/foo\n\nMerge description."
    remote_url = "https://github.com/acme-org/example-repo.git"

    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.side_effect = [
            # git log call
            MagicMock(returncode=0, stdout=commit_body),
            # git remote get-url call
            MagicMock(returncode=0, stdout=remote_url + "\n"),
        ]
        url = _find_pr_url("a1b2c3d4", Path("/repo"))

    assert url == "https://github.com/acme-org/example-repo/pull/42"


def test_pr_url_none_when_no_pattern():
    commit_body = "chore: update dependencies\n"
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=commit_body)
        url = _find_pr_url("a1b2c3d4", Path("/repo"))
    assert url is None


def test_pr_url_none_when_non_github_remote():
    commit_body = "Merge pull request #5 from team/branch\n"
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=commit_body),
            MagicMock(returncode=0, stdout="https://gitlab.com/acme-org/repo.git\n"),
        ]
        url = _find_pr_url("a1b2c3d4", Path("/repo"))
    assert url is None


def test_pr_url_none_on_git_failure():
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        url = _find_pr_url("a1b2c3d4", Path("/repo"))
    assert url is None


# ---------------------------------------------------------------------------
# attribute_to_commit: error handling
# ---------------------------------------------------------------------------

def test_attribute_to_commit_returns_none_when_git_missing():
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("git not found")
        result = attribute_to_commit(Path("/repo"), "src/app.py", 10)
    assert result is None


def test_attribute_to_commit_returns_none_on_nonzero_exit():
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=128, stdout="", stderr="fatal: not a git repo")
        result = attribute_to_commit(Path("/repo"), "src/app.py", 10)
    assert result is None


def test_attribute_to_commit_returns_none_on_timeout():
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=10)
        result = attribute_to_commit(Path("/repo"), "src/app.py", 10)
    assert result is None


def test_attribute_to_commit_parses_valid_output():
    with patch("src.shared.git_attribution.subprocess.run") as mock_run:
        mock_run.side_effect = [
            # blame call
            MagicMock(returncode=0, stdout=SAMPLE_PORCELAIN),
            # log call (for PR URL)
            MagicMock(returncode=0, stdout="chore: no PR\n"),
        ]
        result = attribute_to_commit(Path("/repo"), "src/app.py", 1)

    assert result is not None
    assert isinstance(result, CommitAttribution)
    assert result.commit_sha == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    assert result.author_email == "jane@acme-org.example"
    assert result.pr_url is None


# ---------------------------------------------------------------------------
# _parse_unix_with_tz
# ---------------------------------------------------------------------------

def test_parse_unix_with_tz_returns_utc():
    dt = _parse_unix_with_tz(0, "+0000")
    assert dt == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
