"""Tests for compute_file_diff — git diff parsing for SAST incremental engine."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.code_scanning.diff_detector import FileDiff, compute_file_diff, _parse_name_status


# ── _parse_name_status unit tests ─────────────────────────────────────────────


def test_parse_added():
    diff = _parse_name_status("A\tsrc/main.py\n")
    assert diff.added == ["src/main.py"]
    assert diff.modified == []
    assert diff.deleted == []


def test_parse_modified():
    diff = _parse_name_status("M\tsrc/utils.py\n")
    assert diff.modified == ["src/utils.py"]
    assert diff.added == []
    assert diff.deleted == []


def test_parse_deleted():
    diff = _parse_name_status("D\told_file.py\n")
    assert diff.deleted == ["old_file.py"]
    assert diff.added == []
    assert diff.modified == []


def test_parse_renamed_becomes_delete_and_add():
    diff = _parse_name_status("R90\tsrc/old.py\tsrc/new.py\n")
    assert "src/old.py" in diff.deleted
    assert "src/new.py" in diff.added
    assert diff.modified == []


def test_parse_multiple_statuses():
    output = "A\tnew.py\nM\texisting.py\nD\tremoved.py\n"
    diff = _parse_name_status(output)
    assert diff.added == ["new.py"]
    assert diff.modified == ["existing.py"]
    assert diff.deleted == ["removed.py"]


def test_parse_empty_output():
    diff = _parse_name_status("")
    assert diff.added == []
    assert diff.modified == []
    assert diff.deleted == []


def test_parse_blank_lines_ignored():
    diff = _parse_name_status("\n\nA\tsrc/foo.py\n\n")
    assert diff.added == ["src/foo.py"]


def test_parse_rename_100_percent_similarity():
    diff = _parse_name_status("R100\tlib/old_name.py\tlib/new_name.py\n")
    assert "lib/old_name.py" in diff.deleted
    assert "lib/new_name.py" in diff.added


# ── compute_file_diff with a real temp git repo ────────────────────────────────


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(
        ["git"] + args,
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def _commit_file(repo: Path, filename: str, content: str, message: str) -> str:
    """Write a file, stage it, commit, and return the commit SHA."""
    path = repo / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    _git(["add", filename], repo)
    _git(["commit", "-m", message], repo)
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture()
def git_repo(tmp_path: Path) -> Path:
    """Create a minimal git repo with an initial commit."""
    _git(["init", "-b", "main"], tmp_path)
    _git(["config", "user.email", "test@example.com"], tmp_path)
    _git(["config", "user.name", "Test"], tmp_path)
    # Initial empty commit so we always have a HEAD
    _git(["commit", "--allow-empty", "-m", "init"], tmp_path)
    return tmp_path


def test_compute_diff_added_file(git_repo: Path):
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    head_sha = _commit_file(git_repo, "src/app.py", "print('hello')", "add app")

    diff = compute_file_diff(git_repo, base_sha, head_sha)
    assert "src/app.py" in diff.added
    assert diff.modified == []
    assert diff.deleted == []


def test_compute_diff_modified_file(git_repo: Path):
    _commit_file(git_repo, "src/app.py", "v1", "initial")
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    head_sha = _commit_file(git_repo, "src/app.py", "v2", "modify app")

    diff = compute_file_diff(git_repo, base_sha, head_sha)
    assert "src/app.py" in diff.modified
    assert diff.added == []
    assert diff.deleted == []


def test_compute_diff_deleted_file(git_repo: Path):
    _commit_file(git_repo, "to_delete.py", "content", "add file")
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    (git_repo / "to_delete.py").unlink()
    _git(["add", "to_delete.py"], git_repo)
    _git(["commit", "-m", "delete file"], git_repo)
    head_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    diff = compute_file_diff(git_repo, base_sha, head_sha)
    assert "to_delete.py" in diff.deleted
    assert diff.added == []
    assert diff.modified == []


def test_compute_diff_no_changes(git_repo: Path):
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    diff = compute_file_diff(git_repo, sha, sha)
    assert diff.added == []
    assert diff.modified == []
    assert diff.deleted == []


def test_baseline_sha_none_returns_all_files_as_added(git_repo: Path):
    """baseline_sha=None should return all tracked files as added."""
    _commit_file(git_repo, "a.py", "a", "add a")
    _commit_file(git_repo, "b.py", "b", "add b")
    head_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    diff = compute_file_diff(git_repo, None, head_sha)
    assert "a.py" in diff.added
    assert "b.py" in diff.added
    assert diff.modified == []
    assert diff.deleted == []


def test_baseline_sha_none_empty_repo_no_files(tmp_path: Path):
    """A repo with no files returns an empty diff when baseline_sha is None."""
    _git(["init", "-b", "main"], tmp_path)
    _git(["config", "user.email", "test@example.com"], tmp_path)
    _git(["config", "user.name", "Test"], tmp_path)
    _git(["commit", "--allow-empty", "-m", "init"], tmp_path)
    head_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, capture_output=True, text=True, check=True
    ).stdout.strip()

    diff = compute_file_diff(tmp_path, None, head_sha)
    assert diff.added == []
    assert diff.modified == []
    assert diff.deleted == []


def test_compute_diff_multiple_files(git_repo: Path):
    _commit_file(git_repo, "old.py", "old", "add old")
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    _commit_file(git_repo, "new.py", "new", "add new")
    _commit_file(git_repo, "old.py", "updated", "update old")
    head_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, capture_output=True, text=True, check=True
    ).stdout.strip()

    diff = compute_file_diff(git_repo, base_sha, head_sha)
    assert "new.py" in diff.added
    assert "old.py" in diff.modified
    assert diff.deleted == []


def test_file_diff_dataclass_fields():
    diff = FileDiff(added=["a.py"], modified=["b.py"], deleted=["c.py"])
    assert diff.added == ["a.py"]
    assert diff.modified == ["b.py"]
    assert diff.deleted == ["c.py"]
