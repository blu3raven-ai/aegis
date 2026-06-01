"""Tests for commit_range.enumerate_new_commits."""
from __future__ import annotations

import subprocess
from datetime import timezone
from pathlib import Path

import pytest

from src.secrets.commit_range import CommitInfo, FullScanRequired, enumerate_new_commits


# ── Git repo fixture ──────────────────────────────────────────────────────────


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


def _commit(cwd: Path, message: str, files: dict[str, str]) -> str:
    """Create a commit with the given files and return its SHA."""
    for name, content in files.items():
        p = cwd / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        _git(cwd, "add", name)
    _git(cwd, "commit", "--allow-empty", "-m", message)
    return _git(cwd, "rev-parse", "HEAD")


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "ci@acme-org.example")
    _git(tmp_path, "config", "user.name", "CI Bot")
    return tmp_path


# ── baseline_sha=None raises FullScanRequired ─────────────────────────────────


def test_none_baseline_raises_full_scan_required(repo):
    with pytest.raises(FullScanRequired):
        enumerate_new_commits(repo, None, "HEAD")


# ── empty range returns empty list ───────────────────────────────────────────


def test_empty_range_returns_empty(repo):
    sha = _commit(repo, "init", {"README.md": "hello"})
    result = enumerate_new_commits(repo, sha, sha)
    assert result == []


# ── single new commit ─────────────────────────────────────────────────────────


def test_single_new_commit(repo):
    base = _commit(repo, "base", {"init.py": "x = 1"})
    head = _commit(repo, "add feature", {"feature.py": "y = 2"})

    commits = enumerate_new_commits(repo, base, head)

    assert len(commits) == 1
    c = commits[0]
    assert c.sha == head
    assert c.message == "add feature"
    assert c.author_email == "ci@acme-org.example"
    assert c.timestamp.tzinfo is timezone.utc
    assert "feature.py" in c.changed_files


# ── multiple commits are ordered oldest-first ────────────────────────────────


def test_multiple_commits_oldest_first(repo):
    base = _commit(repo, "base", {"a.py": "a"})
    sha1 = _commit(repo, "commit1", {"b.py": "b"})
    sha2 = _commit(repo, "commit2", {"c.py": "c"})

    commits = enumerate_new_commits(repo, base, sha2)

    assert len(commits) == 2
    assert commits[0].sha == sha1
    assert commits[1].sha == sha2


# ── rename appears as both old and new path ──────────────────────────────────


def test_rename_yields_both_paths(repo):
    base = _commit(repo, "base", {"old_name.py": "x = 1"})
    _git(repo, "mv", "old_name.py", "new_name.py")
    _git(repo, "commit", "-m", "rename file")
    head = _git(repo, "rev-parse", "HEAD")

    commits = enumerate_new_commits(repo, base, head)
    assert len(commits) == 1
    assert "old_name.py" in commits[0].changed_files
    assert "new_name.py" in commits[0].changed_files


# ── merge commits are included ────────────────────────────────────────────────


def test_merge_commit_is_included(repo):
    base = _commit(repo, "base", {"main.py": "x = 0"})

    # Create a side branch and commit
    _git(repo, "checkout", "-b", "side")
    side = _commit(repo, "side commit", {"side.py": "s = 1"})

    # Back to main, create a diverging commit
    _git(repo, "checkout", "main")
    _commit(repo, "main commit", {"main.py": "x = 1"})

    # Merge side into main
    _git(repo, "merge", "--no-ff", "side", "-m", "merge side")
    head = _git(repo, "rev-parse", "HEAD")

    commits = enumerate_new_commits(repo, base, head)
    shas = [c.sha for c in commits]
    assert side in shas  # the side branch commit is included
    assert head in shas  # the merge commit itself is included


# ── CommitInfo shape ─────────────────────────────────────────────────────────


def test_commit_info_fields(repo):
    base = _commit(repo, "base", {"a.txt": "hello"})
    head = _commit(repo, "second commit", {"b.txt": "world"})

    commits = enumerate_new_commits(repo, base, head)
    assert len(commits) == 1
    c = commits[0]
    assert isinstance(c, CommitInfo)
    assert isinstance(c.sha, str) and len(c.sha) == 40
    assert isinstance(c.changed_files, list)
    assert isinstance(c.timestamp.tzinfo, type(timezone.utc))
