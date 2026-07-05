"""IacScanner.run_scan — multi-repo dispatch, aggregation, and stamping.

The source-connection scan path comma/newline-joins every discovered repo into
one GIT_REPOS value, so the scanner must scan *all* of them, not just the first.
"""
from __future__ import annotations

import json
from pathlib import Path

import runner.scanners.iac.scanner as scanner_mod
from runner.scanners.iac.scanner import IacScanner, IacScanConfig


def _fake_clone(url, dest, token=None, timeout=None):
    """Materialize a checkout dir so the scan has something to walk."""
    Path(dest).mkdir(parents=True, exist_ok=True)


def _findings_lines(job_dir: Path) -> list[dict]:
    path = job_dir / "findings.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_config_parses_all_repos():
    cfg = IacScanConfig.from_job(
        {"envVars": {"GIT_REPOS": "https://github.com/a/b.git,https://github.com/c/d.git"}}
    )
    assert cfg.repos == ["https://github.com/a/b.git", "https://github.com/c/d.git"]


def test_run_scan_scans_every_repo_and_stamps_each(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_mod, "clone_repo", _fake_clone)

    # One finding per repo, keyed off the checkout path so we can tell them apart.
    def fake_checkov(clone_dir, log_tail, cancel_event):
        return {"results": {"failed_checks": [{
            "check_id": "CKV_TEST_1", "check_name": "n", "file_path": "/main.tf",
            "file_line_range": [1, 1], "resource": str(clone_dir), "severity": "LOW",
        }]}}

    monkeypatch.setattr(scanner_mod, "_run_checkov", fake_checkov)

    job = {"jobId": "t", "envVars": {
        "GIT_REPOS": "https://github.com/acme/a.git\nhttps://github.com/acme/b.git",
    }}
    job_dir = tmp_path / "job"
    result = IacScanner().run_scan(job, job_dir=job_dir)

    assert result.exit_code == 0
    lines = _findings_lines(job_dir)
    repos = sorted(f["repo_full_name"] for f in lines)
    assert repos == ["a", "b"], f"expected both repos scanned, got {repos}"
    by_repo = {f["repo_full_name"]: f["repo_html_url"] for f in lines}
    assert "a" in by_repo["a"] and "b" in by_repo["b"]


def test_run_scan_tolerates_partial_clone_failure(tmp_path, monkeypatch):
    from runner.scanners._shared import GitCloneError

    def flaky_clone(url, dest, token=None, timeout=None):
        if "bad" in url:
            raise GitCloneError("boom")
        Path(dest).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(scanner_mod, "clone_repo", flaky_clone)
    monkeypatch.setattr(scanner_mod, "_run_checkov", lambda d, lt, ce: {"results": {
        "failed_checks": [{"check_id": "CKV_TEST_1", "check_name": "n",
                           "file_path": "/main.tf", "file_line_range": [1, 1],
                           "resource": "r", "severity": "LOW"}]}})

    job = {"jobId": "t", "envVars": {
        "GIT_REPOS": "https://github.com/acme/bad.git,https://github.com/acme/good.git",
    }}
    job_dir = tmp_path / "job"
    result = IacScanner().run_scan(job, job_dir=job_dir)

    assert result.exit_code == 0
    lines = _findings_lines(job_dir)
    assert [f["repo_full_name"] for f in lines] == ["good"]


def test_run_scan_all_clones_fail_reports_failure(tmp_path, monkeypatch):
    from runner.scanners._shared import GitCloneError

    def always_fail(url, dest, token=None, timeout=None):
        raise GitCloneError("boom")

    monkeypatch.setattr(scanner_mod, "clone_repo", always_fail)

    job = {"jobId": "t", "envVars": {
        "GIT_REPOS": "https://github.com/acme/a.git,https://github.com/acme/b.git",
    }}
    job_dir = tmp_path / "job"
    result = IacScanner().run_scan(job, job_dir=job_dir)

    assert result.exit_code == scanner_mod._FAILURE_EXIT_CODE
    assert _findings_lines(job_dir) == []


def test_run_scan_empty_repos_returns_clean(tmp_path):
    job = {"jobId": "t", "envVars": {"GIT_REPOS": ""}}
    job_dir = tmp_path / "job"
    result = IacScanner().run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert _findings_lines(job_dir) == []
