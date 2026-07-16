"""Diff file resolution between two commits."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from runner.scanners._shared import compute_diff_files


def _init_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.x"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    # Some hosts/CI use a non-`main` default — pin to `main` for determinism.
    subprocess.run(["git", "config", "init.defaultBranch", "main"], cwd=tmp_path, check=True)
    return tmp_path


def _commit(repo: Path, files: dict[str, str], msg: str) -> str:
    for name, content in files.items():
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo, check=True)
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True,
    ).strip()


def test_compute_diff_files_returns_changed(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, {"a.py": "1\n", "b.py": "1\n"}, "init")
    head = _commit(repo, {"a.py": "2\n", "c.py": "1\n"}, "edit")
    files = compute_diff_files(str(repo), base, head)
    assert set(files) == {"a.py", "c.py"}


def test_compute_diff_files_empty_when_no_changes(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, {"a.py": "1\n"}, "init")
    files = compute_diff_files(str(repo), base, base)
    assert files == []


def test_compute_diff_files_raises_on_missing_base(tmp_path):
    repo = _init_repo(tmp_path)
    head = _commit(repo, {"a.py": "1\n"}, "init")
    with pytest.raises(ValueError):
        compute_diff_files(str(repo), "deadbeef", head)


def test_compute_diff_files_rejects_non_hex_ref(tmp_path):
    """Refs are interpolated into the git argv, so a value that could be parsed
    as an option (or any non-sha) must be refused before git runs."""
    repo = _init_repo(tmp_path)
    head = _commit(repo, {"a.py": "1\n"}, "init")
    with pytest.raises(ValueError):
        compute_diff_files(str(repo), "--output=/tmp/x", head)
    with pytest.raises(ValueError):
        compute_diff_files(str(repo), head, "HEAD")


def test_compute_diff_files_handles_nested_paths(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, {"src/a.py": "1\n"}, "init")
    head = _commit(repo, {"src/a.py": "2\n", "src/sub/b.py": "1\n"}, "edit")
    files = compute_diff_files(str(repo), base, head)
    assert set(files) == {"src/a.py", "src/sub/b.py"}
