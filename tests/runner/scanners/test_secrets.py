"""Tests for the embedded secrets scanner module."""
from __future__ import annotations

import json
import threading

import pytest


# ---------------------------------------------------------------------------
# Task 4.3 — normalize.py
# ---------------------------------------------------------------------------


def test_normalize_file_trufflehog_jsonl(tmp_path):
    from runner.scanners.secrets.normalize import normalize_file

    raw = tmp_path / "trufflehog.json"
    raw.write_text(
        '{"DetectorName":"aws","Raw":"AKIA..."}\n'
        "\n"
        '{"DetectorName":"github","Raw":"ghp_..."}\n'
    )
    findings = normalize_file(raw, "trufflehog", "acme/widget")
    assert len(findings) == 2
    assert findings[0]["source"] == "trufflehog"
    assert findings[0]["repository"] == "acme/widget"
    assert findings[0]["DetectorName"] == "aws"


def test_normalize_file_trufflehog_skips_bad_json(tmp_path):
    from runner.scanners.secrets.normalize import normalize_file

    raw = tmp_path / "trufflehog.json"
    raw.write_text('{"ok":1}\n{ not json\n{"ok":2}\n')
    findings = normalize_file(raw, "trufflehog", "x")
    assert [f["ok"] for f in findings] == [1, 2]


def test_normalize_secrets_output_aggregates_trufflehog(tmp_path):
    from runner.scanners.secrets.normalize import normalize_secrets_output

    repo_a = tmp_path / "repo-a"
    repo_a.mkdir()
    (repo_a / "trufflehog.json").write_text('{"DetectorName":"aws"}\n')

    repo_b = tmp_path / "repo-b"
    repo_b.mkdir()
    (repo_b / "trufflehog.json").write_text('{"DetectorName":"github"}\n')

    total, errors = normalize_secrets_output("acme", tmp_path, "run-1")
    assert total == 2
    assert errors == 0

    lines = [
        json.loads(line)
        for line in (tmp_path / "findings.jsonl").read_text().splitlines()
    ]
    by_source = {(f["source"], f["repository"]) for f in lines}
    assert ("trufflehog", "repo-a") in by_source
    assert ("trufflehog", "repo-b") in by_source


def test_normalize_secrets_output_no_findings_writes_empty(tmp_path):
    from runner.scanners.secrets.normalize import normalize_secrets_output

    total, errors = normalize_secrets_output("acme", tmp_path, "run-1")
    assert total == 0
    assert errors == 0
    assert (tmp_path / "findings.jsonl").exists()
    assert (tmp_path / "findings.jsonl").read_text() == ""


def test_normalize_secrets_output_uses_compact_separators(tmp_path):
    """Bash original used ``separators=(',', ':')`` - no whitespace."""
    from runner.scanners.secrets.normalize import normalize_secrets_output

    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "trufflehog.json").write_text('{"k":"v"}\n')
    normalize_secrets_output("acme", tmp_path, "run-1")
    content = (tmp_path / "findings.jsonl").read_text().strip()
    # Verify compact separators (no whitespace between JSON tokens) robustly:
    # re-dumping the parsed line with separators=(",", ":") must reproduce it
    # exactly. A naive `", " not in line` check false-positives on legitimate
    # whitespace inside string values (e.g. remediation-runbook prose).
    for line in content.splitlines():
        assert line == json.dumps(json.loads(line), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Task 4.4 — SecretsScanner orchestrator
# ---------------------------------------------------------------------------


def test_secrets_scanner_has_correct_type():
    from runner.scanners.secrets.scanner import SecretsScanner

    assert SecretsScanner.SCANNER_TYPE == "secret_scanning"


def test_secrets_scanner_implements_base_protocol():
    from runner.scanners.base import BaseScanner
    from runner.scanners.secrets.scanner import SecretsScanner

    assert isinstance(SecretsScanner(), BaseScanner)


def test_run_scan_empty_repos_returns_clean(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    job = {"jobId": "test-s", "envVars": {"GIT_REPOS": ""},}
    job_dir = tmp_path / "test-s"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_missing_docker_args_does_not_crash(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    job = {"jobId": "test-bare"}
    job_dir = tmp_path / "test-bare"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0


def test_run_scan_pre_cancel_returns_137(tmp_path):
    from runner.scanners._subprocess import CANCELLED_EXIT_CODE
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    cancel = threading.Event()
    cancel.set()
    job = {
        "jobId": "test-cancel",
        "envVars": {"GIT_REPOS": "https://github.com/example/a.git"},}
    job_dir = tmp_path / "test-cancel"
    result = scanner.run_scan(job, job_dir=job_dir, cancel_event=cancel)
    assert result.exit_code == CANCELLED_EXIT_CODE


def test_run_scan_rejects_unsupported_scan_depth(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    job = {
        "jobId": "test-depth",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SCAN_DEPTH": "extreme",
            },}
    job_dir = tmp_path / "test-depth"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 2
    assert any("SCAN_DEPTH" in m for m in result.log_tail)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_rejects_malformed_start_date(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    job = {
        "jobId": "test-date",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SCAN_DEPTH": "deep",
                "SCAN_START_DATE": "2025/01/01",
            },}
    job_dir = tmp_path / "test-date"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 2
    assert any("SCAN_START_DATE" in m for m in result.log_tail)


def test_run_scan_honours_concurrency_env(tmp_path, monkeypatch):
    from runner.scanners.secrets import scanner as scanner_mod
    from runner.scanners.secrets.scanner import SecretsScanner

    captured: dict = {}

    class _StubPool:
        def __init__(self, max_workers):
            captured["max_workers"] = max_workers

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def map(self, fn, items):
            return [fn(i) for i in items]

    monkeypatch.setattr(
        scanner_mod.concurrent.futures, "ThreadPoolExecutor", _StubPool
    )
    monkeypatch.setattr(SecretsScanner, "_scan_repo", lambda *a, **kw: None)

    scanner = SecretsScanner()
    job = {
        "jobId": "test-conc",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git,https://github.com/c/d.git",
                "CONCURRENCY": "7",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "test-conc")
    assert captured["max_workers"] == 7


def test_run_scan_aggregates_findings(tmp_path, monkeypatch):
    """Per-repo trufflehog.json -> aggregated findings.jsonl."""
    from runner.scanners.secrets.scanner import SecretsScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        out = repo_out / "trufflehog.json"
        out.write_text(json.dumps({"DetectorName": f"detector-{repo_name}"}) + "\n")
        return out

    monkeypatch.setattr(SecretsScanner, "_scan_repo", fake_scan_repo)

    scanner = SecretsScanner()
    job = {
        "jobId": "test-agg",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git\nhttps://github.com/c/d.git",
                "ORG_LABEL": "acme",
            },}
    job_dir = tmp_path / "test-agg"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    lines = [
        json.loads(line)
        for line in (job_dir / "findings.jsonl").read_text().splitlines()
    ]
    detectors = sorted(f["DetectorName"] for f in lines)
    assert detectors == ["detector-b", "detector-d"]


def test_run_scan_tolerates_clone_failure(tmp_path, monkeypatch):
    """A failing repo must not abort the whole scan."""
    from runner.scanners._shared import GitCloneError
    from runner.scanners.secrets.scanner import SecretsScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        raise GitCloneError(f"simulated failure for {repo_url}")

    monkeypatch.setattr(SecretsScanner, "_scan_repo", fake_scan_repo)

    scanner = SecretsScanner()
    job = {
        "jobId": "test-fail",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    job_dir = tmp_path / "test-fail"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert any("simulated failure" in line for line in result.log_tail)


def test_inject_head_sha_annotates_each_record():
    from runner.scanners.secrets.scanner import SecretsScanner

    src = '{"DetectorName":"aws"}\n{"DetectorName":"github"}\n'
    out = SecretsScanner._inject_head_sha(src, "abc1234")
    lines = [json.loads(line) for line in out.splitlines() if line]
    assert all(rec["Commit"] == "abc1234" for rec in lines)
    assert {rec["DetectorName"] for rec in lines} == {"aws", "github"}


def test_inject_head_sha_no_op_when_sha_blank():
    from runner.scanners.secrets.scanner import SecretsScanner

    src = '{"DetectorName":"aws"}\n'
    assert SecretsScanner._inject_head_sha(src, "") == src


def test_cleanup_empty_results_removes_empty_and_array_files(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    (tmp_path / "empty.json").write_text("")
    (tmp_path / "empty_array.json").write_text("[]")
    (tmp_path / "keep.json").write_text('{"DetectorName":"aws"}\n')

    SecretsScanner._cleanup_empty_results(tmp_path)
    assert not (tmp_path / "empty.json").exists()
    assert not (tmp_path / "empty_array.json").exists()
    assert (tmp_path / "keep.json").exists()


def test_run_scan_emits_progress(tmp_path):
    """on_progress should be called with the expected dict shape, terminating
    in stage='done'."""
    from runner.scanners.secrets.scanner import SecretsScanner

    captures: list[dict] = []

    def on_progress(log_tail, progress):
        captures.append(dict(progress))

    scanner = SecretsScanner()
    job = {"jobId": "p1", "envVars": {"GIT_REPOS": ""},}
    scanner.run_scan(job, job_dir=tmp_path / "p1", on_progress=on_progress)

    assert captures, "on_progress was never called"
    assert any(c.get("stage") == "done" for c in captures)
    assert all("scannedRepos" in c for c in captures)
    assert all("finishedRepos" in c for c in captures)
    assert all("expectedRepos" in c for c in captures)


def test_run_scan_emits_progress_per_repo(tmp_path, monkeypatch):
    """Each repo must produce monotonic scanning/finished counters and the
    run must terminate in stage='done'."""
    from runner.scanners.secrets.scanner import SecretsScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        return None

    monkeypatch.setattr(SecretsScanner, "_scan_repo", fake_scan_repo)

    captures: list[dict] = []
    scanner = SecretsScanner()
    job = {
        "jobId": "p2",
        "envVars": {
                "GIT_REPOS": "https://x/a.git,https://x/b.git",
                "CONCURRENCY": "1",
            },}
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p2",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )

    assert all(c["expectedRepos"] == 2 for c in captures)
    assert [c["scannedRepos"] for c in captures] == sorted(
        c["scannedRepos"] for c in captures
    )
    assert [c["finishedRepos"] for c in captures] == sorted(
        c["finishedRepos"] for c in captures
    )
    assert captures[-1]["stage"] == "done"
    assert captures[-1]["finishedRepos"] == 2
    assert any(c.get("stage") == "scanning" for c in captures)
    assert any(c.get("stage") == "normalizing" for c in captures)


def test_run_scan_emits_progress_done_on_unsupported_depth(tmp_path):
    """The unsupported-depth early exit must still emit stage='done'."""
    from runner.scanners.secrets.scanner import SecretsScanner

    captures: list[dict] = []
    scanner = SecretsScanner()
    job = {
        "jobId": "p3",
        "envVars": {
                "GIT_REPOS": "https://x/a.git",
                "SCAN_DEPTH": "bogus",
            },}
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p3",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )
    assert captures and captures[-1]["stage"] == "done"


def test_run_scan_emits_progress_done_on_pre_cancel(tmp_path):
    import threading as _threading

    from runner.scanners.secrets.scanner import SecretsScanner

    captures: list[dict] = []
    cancel = _threading.Event()
    cancel.set()
    scanner = SecretsScanner()
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
    from runner.scanners.secrets.scanner import SecretsScanner

    def bad(log_tail, progress):
        raise RuntimeError("boom")

    scanner = SecretsScanner()
    job = {"jobId": "p5", "envVars": {"GIT_REPOS": ""},}
    result = scanner.run_scan(job, job_dir=tmp_path / "p5", on_progress=bad)
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# SecretsScanConfig
# ---------------------------------------------------------------------------

def _secrets_job(env: dict) -> dict:
    return {"jobId": "job-test", "envVars": env}


def test_secrets_config_parses_defaults():
    from runner.scanners.secrets.scanner import SecretsScanConfig
    cfg = SecretsScanConfig.from_job(_secrets_job({"GIT_REPOS": "https://x/a.git"}))
    assert cfg.org_label == "default"
    assert cfg.concurrency == 4
    assert cfg.scan_depth == "light"
    assert cfg.start_date == ""
    assert cfg.git_token is None
    assert cfg.repos == ["https://x/a.git"]


def test_secrets_config_parses_explicit_values():
    from runner.scanners.secrets.scanner import SecretsScanConfig
    cfg = SecretsScanConfig.from_job(_secrets_job({
        "GIT_REPOS": "https://x/a.git,https://x/b.git",
        "GIT_TOKEN": "ghp_xyz",
        "ORG_LABEL": "acme-org",
        "RUN_ID": "run-7",
        "CONCURRENCY": "2",
        "SCAN_DEPTH": "deep",
        "SCAN_START_DATE": "2024-01-01",
    }))
    assert cfg.repos == ["https://x/a.git", "https://x/b.git"]
    assert cfg.git_token == "ghp_xyz"
    assert cfg.org_label == "acme-org"
    assert cfg.run_id == "run-7"
    assert cfg.concurrency == 2
    assert cfg.scan_depth == "deep"
    assert cfg.start_date == "2024-01-01"


def test_secrets_config_rejects_unsupported_scan_depth():
    from runner.scanners._shared import ScannerConfigError
    from runner.scanners.secrets.scanner import SecretsScanConfig
    with pytest.raises(ScannerConfigError, match="SCAN_DEPTH"):
        SecretsScanConfig.from_job(_secrets_job({
            "GIT_REPOS": "https://x/a.git",
            "SCAN_DEPTH": "turbo",
        }))


def test_secrets_config_rejects_invalid_start_date_format():
    from runner.scanners._shared import ScannerConfigError
    from runner.scanners.secrets.scanner import SecretsScanConfig
    with pytest.raises(ScannerConfigError, match="SCAN_START_DATE"):
        SecretsScanConfig.from_job(_secrets_job({
            "GIT_REPOS": "https://x/a.git",
            "SCAN_DEPTH": "deep",
            "SCAN_START_DATE": "01-01-2024",
        }))


def test_secrets_config_run_id_falls_back_to_job_id():
    from runner.scanners.secrets.scanner import SecretsScanConfig
    cfg = SecretsScanConfig.from_job({"jobId": "job-77", "envVars": {"GIT_REPOS": "https://x/a.git"}})
    assert cfg.run_id == "job-77"


def test_capture_secret_windows_filesystem_mode(tmp_path):
    from runner.scanners.secrets.normalize import capture_secret_windows

    clone = tmp_path / "_checkout"
    clone.mkdir()
    (clone / "app.py").write_text("\n".join(f"l{i}" for i in range(1, 21)))
    out = tmp_path / "out.json"
    out.write_text(
        json.dumps(
            {
                "DetectorName": "aws",
                "Raw": "AKIA",
                "SourceMetadata": {"Data": {"Filesystem": {"file": "app.py", "line": 10}}},
            }
        )
        + "\n"
    )
    capture_secret_windows(out, clone)
    finding = json.loads(out.read_text().strip())
    assert finding["code_window_start_line"] is not None
    assert "l10" in finding["code_window"]


def test_capture_secret_windows_git_mode_and_redaction(tmp_path):
    from runner.scanners.secrets.normalize import capture_secret_windows

    clone = tmp_path / "_checkout"
    clone.mkdir()
    (clone / "cfg.py").write_text("a\nb\nSECRET=AKIAEXAMPLE\nd\ne")
    out = tmp_path / "out.json"
    out.write_text(
        json.dumps(
            {
                "Raw": "AKIAEXAMPLE",
                "SourceMetadata": {"Data": {"Git": {"file": "cfg.py", "line": 3}}},
            }
        )
        + "\n"
    )
    capture_secret_windows(out, clone)
    finding = json.loads(out.read_text().strip())
    assert "code_window" in finding
    assert "AKIAEXAMPLE" not in finding["code_window"]  # masked in the window


def test_capture_secret_windows_tolerates_missing_clone(tmp_path):
    from runner.scanners.secrets.normalize import capture_secret_windows

    out = tmp_path / "out.json"
    out.write_text(json.dumps({"Raw": "x", "SourceMetadata": {"Data": {}}}) + "\n")
    capture_secret_windows(out, tmp_path / "gone")  # no clone -> no crash, no window
    finding = json.loads(out.read_text().strip())
    assert "code_window" not in finding
