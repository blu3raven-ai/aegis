"""Tests for the embedded dependencies scanner module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Task 2.1 — normalize.py
# ---------------------------------------------------------------------------


def _grype_sample(matches: list[dict]) -> dict:
    return {"matches": matches}


def _basic_match(
    pkg_name: str = "lodash",
    pkg_version: str = "4.17.20",
    advisory_id: str = "GHSA-xxxx",
    severity: str = "High",
    manifest_path: str = "/package.json",
) -> dict:
    return {
        "vulnerability": {
            "id": advisory_id,
            "aliases": ["CVE-2021-23337"],
            "severity": severity,
            "description": "Prototype pollution.",
            "cvss": [{"metrics": {"baseScore": 7.2}}],
            "fix": {"versions": ["4.17.21"], "state": "fixed"},
            "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
        },
        "artifact": {
            "name": pkg_name,
            "version": pkg_version,
            "type": "npm",
            "locations": [{"path": manifest_path}],
        },
    }


# ---------------------------------------------------------------------------
# Task 2.1 — download_sboms.py
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_download_sboms_with_real_minio():
    """Integration test — requires a live MinIO + boto3. Skipped by default."""
    pytest.skip("requires live MinIO endpoint and credentials")


# ---------------------------------------------------------------------------
# Task 2.2 — advisory_db.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Task 2.3 — DependenciesScanner orchestrator
# ---------------------------------------------------------------------------


def test_dependencies_scanner_has_correct_type():
    from runner.scanners.dependencies.scanner import DependenciesScanner

    assert DependenciesScanner.SCANNER_TYPE == "dependencies_scanning"


def test_dependencies_scanner_implements_base_protocol():
    from runner.scanners.base import BaseScanner
    from runner.scanners.dependencies.scanner import DependenciesScanner

    assert isinstance(DependenciesScanner(), BaseScanner)


def test_run_scan_empty_repos_returns_clean(tmp_path):
    """No repos -> _done marker written, exit_code=0."""
    from runner.scanners.base import ExecutionResult
    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    job = {
        "jobId": "test-123",
        "envVars": {"GIT_REPOS": ""},}
    job_dir = tmp_path / "test-123"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert isinstance(result, ExecutionResult)
    assert result.exit_code == 0
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_missing_docker_args_does_not_crash(tmp_path):
    """Job dict without dockerArgs should not raise."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    job = {"jobId": "test-bare"}
    job_dir = tmp_path / "test-bare"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0


def test_run_scan_respects_pre_set_cancel(tmp_path, monkeypatch):
    """Pre-set cancel_event -> returns 137 quickly without doing work."""
    import threading

    from runner.scanners._subprocess import CANCELLED_EXIT_CODE
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setenv("PATH", "/nonexistent")

    scanner = DependenciesScanner()
    cancel = threading.Event()
    cancel.set()
    job = {
        "jobId": "test-cancel",
        "envVars": {"GIT_REPOS": "https://github.com/example/repo.git"},}
    job_dir = tmp_path / "test-cancel"
    result = scanner.run_scan(job, job_dir=job_dir, cancel_event=cancel)
    assert result.exit_code == CANCELLED_EXIT_CODE


def test_run_scan_rejects_unsupported_scan_mode(tmp_path):
    """Truly unknown SCAN_MODE must fail loudly with exit_code=2."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    job = {
        "jobId": "test-mode",
        "envVars": {
                "GIT_REPOS": "https://github.com/example/a.git",
                "SCAN_MODE": "not_a_real_mode",
            },}
    job_dir = tmp_path / "test-mode"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 2
    assert any("SCAN_MODE" in m for m in result.log_tail)
    # _done marker still written so the manifest streamer doesn't hang.
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_tag_sbom_source_appends_property(tmp_path):
    """The internal _tag_sbom_source helper must mirror the bash jq tagging."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {"components": [{"name": "pkg", "properties": [{"name": "x", "value": "y"}]}]}
        )
    )
    DependenciesScanner()._tag_sbom_source(sbom, "syft")
    data = json.loads(sbom.read_text())
    props = data["components"][0]["properties"]
    assert {"name": "scanner:source", "value": "syft"} in props
    assert {"name": "x", "value": "y"} in props


def test_run_scan_emits_progress(tmp_path):
    """on_progress should be called with the expected dict shape, terminating
    in stage='done'."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    captures: list[dict] = []

    def on_progress(log_tail, progress):
        captures.append(dict(progress))

    scanner = DependenciesScanner()
    job = {"jobId": "p1", "envVars": {"GIT_REPOS": ""},}
    scanner.run_scan(job, job_dir=tmp_path / "p1", on_progress=on_progress)

    assert captures, "on_progress was never called"
    assert any(c.get("stage") == "done" for c in captures)
    assert all("scannedRepos" in c for c in captures)
    assert all("finishedRepos" in c for c in captures)
    assert all("expectedRepos" in c for c in captures)


def test_run_scan_emits_progress_done_on_unsupported_mode(tmp_path):
    """The unsupported-mode early exit must still emit a final stage='done'."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    captures: list[dict] = []
    scanner = DependenciesScanner()
    job = {
        "jobId": "p3",
        "envVars": {
                "GIT_REPOS": "https://x/a.git",
                "SCAN_MODE": "not_a_real_mode",
            },}
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p3",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )
    assert captures and captures[-1]["stage"] == "done"


def test_run_scan_emits_progress_done_on_pre_cancel(tmp_path):
    """Pre-set cancel_event must still emit stage='done' before returning."""
    import threading as _threading

    from runner.scanners.dependencies.scanner import DependenciesScanner

    captures: list[dict] = []
    cancel = _threading.Event()
    cancel.set()
    scanner = DependenciesScanner()
    job = {
        "jobId": "p4",
        "envVars": {"GIT_REPOS": "https://x/a.git"},}
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p4",
        on_progress=lambda lt, p: captures.append(dict(p)),
        cancel_event=cancel,
    )
    assert captures and captures[-1]["stage"] == "done"


def test_run_scan_progress_callback_exception_does_not_abort(tmp_path):
    """A raising on_progress must not abort the scan."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    def bad(log_tail, progress):
        raise RuntimeError("boom")

    scanner = DependenciesScanner()
    job = {"jobId": "p5", "envVars": {"GIT_REPOS": ""},}
    result = scanner.run_scan(job, job_dir=tmp_path / "p5", on_progress=bad)
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Gap 1 — Argus DB download
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Gap 1 — Argus integration with grype DB precedence
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Gap 2 — advisories_only scan mode
# ---------------------------------------------------------------------------


def _fake_download_two_sboms(sbom_dir):
    sbom_dir = Path(sbom_dir)
    sbom_dir.mkdir(parents=True, exist_ok=True)
    (sbom_dir / "acme__widget.json").write_text(
        json.dumps({"components": [{"name": "lodash", "version": "4.17.20"}]})
    )
    (sbom_dir / "acme__gizmo.json").write_text(
        json.dumps({"components": [{"name": "flask", "version": "1.0"}]})
    )
    return 2


def _fake_download_two_sboms_kw(*, backend_client, job_id, output_dir):
    return _fake_download_two_sboms(output_dir)


# ---------------------------------------------------------------------------
# Task 3.2 / 3.3 — sbom_only scan mode (skip_grype)
# ---------------------------------------------------------------------------


def test_run_scan_sbom_only_in_supported_modes():
    """sbom_only must be listed in SUPPORTED_SCAN_MODES (no longer deferred)."""
    from runner.scanners.dependencies.scanner import (
        DEFERRED_SCAN_MODES,
        SUPPORTED_SCAN_MODES,
    )

    assert "sbom_only" in SUPPORTED_SCAN_MODES
    assert "sbom_only" not in DEFERRED_SCAN_MODES


# ---------------------------------------------------------------------------
# DependenciesScanConfig
# ---------------------------------------------------------------------------

def _deps_job(env: dict) -> dict:
    return {"jobId": "job-test", "envVars": env}


def test_deps_config_parses_defaults(monkeypatch):
    monkeypatch.delenv("ORG_LABEL", raising=False)
    monkeypatch.delenv("CONCURRENCY", raising=False)
    monkeypatch.delenv("SCAN_MODE", raising=False)
    monkeypatch.delenv("GIT_TOKEN", raising=False)
    from runner.scanners.dependencies.scanner import DependenciesScanConfig
    cfg = DependenciesScanConfig.from_job(_deps_job({"GIT_REPOS": "https://x/a.git"}))
    assert cfg.org_label == "default"
    assert cfg.concurrency == 4
    assert cfg.scan_mode == "full"
    assert cfg.git_token is None
    assert cfg.repos == ["https://x/a.git"]


def test_deps_config_parses_explicit_values():
    from runner.scanners.dependencies.scanner import DependenciesScanConfig
    cfg = DependenciesScanConfig.from_job(_deps_job({
        "GIT_REPOS": "https://x/a.git,https://x/b.git",
        "GIT_TOKEN": "ghp_abc",
        "ORG_LABEL": "acme-org",
        "RUN_ID": "run-42",
        "CONCURRENCY": "8",
        "SCAN_MODE": "sbom_only",
    }))
    assert cfg.repos == ["https://x/a.git", "https://x/b.git"]
    assert cfg.git_token == "ghp_abc"
    assert cfg.org_label == "acme-org"
    assert cfg.run_id == "run-42"
    assert cfg.concurrency == 8
    assert cfg.scan_mode == "sbom_only"


def test_deps_config_rejects_unsupported_scan_mode():
    from runner.scanners._shared import ScannerConfigError
    from runner.scanners.dependencies.scanner import DependenciesScanConfig
    with pytest.raises(ScannerConfigError, match="SCAN_MODE"):
        DependenciesScanConfig.from_job(_deps_job({
            "GIT_REPOS": "https://x/a.git",
            "SCAN_MODE": "invalid_mode",
        }))


def test_deps_config_run_id_falls_back_to_job_id():
    from runner.scanners.dependencies.scanner import DependenciesScanConfig
    cfg = DependenciesScanConfig.from_job({"jobId": "job-99", "envVars": {"GIT_REPOS": "https://x/a.git"}})
    assert cfg.run_id == "job-99"


def test_deps_config_concurrency_bad_value_uses_default():
    from runner.scanners.dependencies.scanner import DependenciesScanConfig
    cfg = DependenciesScanConfig.from_job(_deps_job({
        "GIT_REPOS": "https://x/a.git",
        "CONCURRENCY": "not_a_number",
    }))
    assert cfg.concurrency == 4
