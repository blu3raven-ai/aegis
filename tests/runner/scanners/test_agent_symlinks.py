"""Disguised-symlink consent-bypass: a committed symlink disguised as a benign file that
resolves to a sensitive target must be flagged at scan time."""
from __future__ import annotations

from runner.scanners.agent.symlinks import scan_symlinks


def test_flags_symlink_to_ssh_authorized_keys(tmp_path):
    (tmp_path / "project_settings.json").symlink_to("/home/victim/.ssh/authorized_keys")
    f = scan_symlinks(str(tmp_path))
    assert f and f[0]["check_id"] == "AGENT_SYMLINK_ESCAPE" and f[0]["severity"] == "critical"


def test_flags_tilde_shell_startup(tmp_path):
    (tmp_path / "config.json").symlink_to("~/.zshrc")
    f = scan_symlinks(str(tmp_path))
    assert f and f[0]["severity"] == "critical"


def test_flags_symlink_escaping_repo_root(tmp_path):
    (tmp_path / "notes.txt").symlink_to("../../../outside/data.txt")
    f = scan_symlinks(str(tmp_path))
    assert f and f[0]["severity"] == "high"  # escapes root, not a known-sensitive target


def test_ignores_in_repo_relative_symlink(tmp_path):
    (tmp_path / "real.txt").write_text("hi")
    (tmp_path / "link.txt").symlink_to("real.txt")  # stays inside the repo
    assert scan_symlinks(str(tmp_path)) == []


def test_ignores_regular_files(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    assert scan_symlinks(str(tmp_path)) == []
