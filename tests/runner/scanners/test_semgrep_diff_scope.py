"""Semgrep diff-scoping passes --include for each diff file."""
from __future__ import annotations

from unittest.mock import patch

from runner.scanners.code_scanning.semgrep import run_semgrep, run_semgrep_sarif


def test_run_semgrep_diff_scope_passes_include_flags(tmp_path):
    captured: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        class _R:
            returncode = 0
            stdout = '{"results":[]}'
            stderr = ""
        return _R()

    with patch("runner.scanners.code_scanning.semgrep.subprocess.run", side_effect=fake_run):
        run_semgrep("/repo", include_files=["src/a.py", "src/b.py"])

    cmd = captured[0]
    assert cmd.count("--include") == 2
    assert "src/a.py" in cmd
    assert "src/b.py" in cmd
    # Final positional must be repo_root.
    assert cmd[-1] == "/repo"


def test_run_semgrep_sarif_diff_scope_passes_include_flags(tmp_path):
    captured = []
    sarif_out = tmp_path / "out.sarif"
    sarif_out.write_text('{"version":"2.1.0","runs":[]}')  # Make it look non-empty.

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()

    with patch("runner.scanners.code_scanning.semgrep.subprocess.run", side_effect=fake_run):
        run_semgrep_sarif("/repo", sarif_out, include_files=["src/a.py"])

    cmd = captured[0]
    assert cmd.count("--include") == 1
    assert "src/a.py" in cmd
    assert cmd[-1] == "/repo"


def test_run_semgrep_no_scope_runs_against_whole_tree():
    captured = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        class _R:
            returncode = 0
            stdout = '{"results":[]}'
            stderr = ""
        return _R()

    with patch("runner.scanners.code_scanning.semgrep.subprocess.run", side_effect=fake_run):
        run_semgrep("/repo")

    cmd = captured[0]
    assert "--include" not in cmd


def test_run_semgrep_empty_include_list_treats_as_unrestricted():
    """`include_files=[]` should produce no --include flags — caller short-circuits empty diffs."""
    captured = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        class _R:
            returncode = 0
            stdout = '{"results":[]}'
            stderr = ""
        return _R()

    with patch("runner.scanners.code_scanning.semgrep.subprocess.run", side_effect=fake_run):
        run_semgrep("/repo", include_files=[])

    cmd = captured[0]
    assert "--include" not in cmd
