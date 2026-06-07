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


def test_normalize_file_emits_expected_shape(tmp_path):
    from runner.scanners.dependencies.normalize import normalize_file

    grype_path = tmp_path / "grype.json"
    grype_path.write_text(json.dumps(_grype_sample([_basic_match()])))

    findings = normalize_file(
        grype_path, org="acme", repo="acme/widget", commit="abc123", manifests_dir=None
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["organization"] == "acme"
    assert f["repository"] == "acme/widget"
    assert f["source"] == "git"
    assert f["commitSha"] == "abc123"
    assert f["packageName"] == "lodash"
    assert f["packageVersion"] == "4.17.20"
    assert f["manifestPath"] == "/package.json"
    assert f["ecosystem"] == "npm"
    assert f["advisoryId"] == "GHSA-xxxx"
    assert f["advisoryAliases"] == ["CVE-2021-23337"]
    assert f["severity"] == "high"
    assert f["cvssScore"] == 7.2
    assert f["fixedVersion"] == "4.17.21"
    assert f["fixState"] == "fixed"
    assert f["scanner"] == "grype"
    assert f["stateCandidate"] == "open"
    assert f["references"] == [
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}
    ]
    assert f["manifestSnippet"] is None
    assert f["manifestMatchLine"] is None


def test_normalize_file_handles_missing_optional_fields(tmp_path):
    from runner.scanners.dependencies.normalize import normalize_file

    grype_path = tmp_path / "grype.json"
    grype_path.write_text(
        json.dumps(
            _grype_sample(
                [
                    {
                        "vulnerability": {"id": "GHSA-yyyy"},
                        "artifact": {"name": "foo", "version": "1.0", "type": "pypi"},
                    }
                ]
            )
        )
    )

    findings = normalize_file(
        grype_path, "acme", "acme/x", "HEAD", manifests_dir=None
    )
    f = findings[0]
    assert f["severity"] == "unknown"
    assert f["cvssScore"] is None
    assert f["fixedVersion"] is None
    assert f["fixState"] == "unknown"
    assert f["references"] == []
    assert f["manifestPath"] == ""


def test_normalize_file_enriches_with_manifest_snippet(tmp_path):
    from runner.scanners.dependencies.normalize import normalize_file

    manifests = tmp_path / "manifests"
    manifests.mkdir()
    (manifests / "requirements.txt").write_text(
        "flask==1.0\nrequests==2.20\nlodash==4.17.20\n"
    )

    grype_path = tmp_path / "grype.json"
    grype_path.write_text(
        json.dumps(
            _grype_sample(
                [_basic_match(manifest_path="/requirements.txt", pkg_name="lodash")]
            )
        )
    )

    findings = normalize_file(
        grype_path, "acme", "acme/x", "HEAD", manifests_dir=manifests
    )
    f = findings[0]
    assert f["manifestMatchLine"] == 3
    assert "lodash==4.17.20" in f["manifestSnippet"]


def test_normalize_grype_output_writes_jsonl(tmp_path):
    from runner.scanners.dependencies.normalize import normalize_grype_output

    repo_dir = tmp_path / "acme__widget"
    repo_dir.mkdir()
    (repo_dir / "findings.json").write_text(
        json.dumps(_grype_sample([_basic_match()]))
    )
    (repo_dir / "head-sha.txt").write_text("deadbeef\n")

    total, errors = normalize_grype_output("acme", tmp_path, "run-1")
    assert total == 1
    assert errors == 0

    out_file = tmp_path / "findings.jsonl"
    assert out_file.exists()
    lines = [json.loads(line) for line in out_file.read_text().splitlines()]
    assert len(lines) == 1
    assert lines[0]["organization"] == "acme"
    assert lines[0]["repository"] == "acme__widget"
    assert lines[0]["commitSha"] == "deadbeef"


def test_normalize_grype_output_handles_no_findings(tmp_path):
    from runner.scanners.dependencies.normalize import normalize_grype_output

    total, errors = normalize_grype_output("acme", tmp_path, "run-1")
    assert total == 0
    assert errors == 0
    assert (tmp_path / "findings.jsonl").exists()


# ---------------------------------------------------------------------------
# Task 2.1 — download_sboms.py
# ---------------------------------------------------------------------------


def test_download_sboms_delegates_to_backend_client(tmp_path):
    from unittest.mock import MagicMock, patch

    from runner.scanners.dependencies.download_sboms import download_sboms

    backend = MagicMock()
    backend.list_sbom_downloads.return_value = []
    count = download_sboms(backend_client=backend, job_id="j1", output_dir=tmp_path)
    assert count == 0
    backend.list_sbom_downloads.assert_called_once_with("j1")


@pytest.mark.integration
def test_download_sboms_with_real_minio():
    """Integration test — requires a live MinIO + boto3. Skipped by default."""
    pytest.skip("requires live MinIO endpoint and credentials")


# ---------------------------------------------------------------------------
# Task 2.2 — advisory_db.py
# ---------------------------------------------------------------------------


def test_build_custom_advisory_db_skips_when_no_providers(tmp_path, monkeypatch):
    from runner.scanners.dependencies.advisory_db import build_custom_advisory_db

    monkeypatch.delenv("ADVISORY_PROVIDERS", raising=False)
    result = build_custom_advisory_db(work_dir=tmp_path)
    assert result is None


def test_build_custom_advisory_db_skips_when_providers_empty(tmp_path, monkeypatch):
    from runner.scanners.dependencies.advisory_db import build_custom_advisory_db

    monkeypatch.setenv("ADVISORY_PROVIDERS", "")
    result = build_custom_advisory_db(work_dir=tmp_path)
    assert result is None


def test_build_custom_advisory_db_skips_when_tools_missing(tmp_path, monkeypatch):
    """When vunnel is not on PATH, function returns None and logs a warning."""
    from runner.scanners.dependencies.advisory_db import build_custom_advisory_db

    monkeypatch.setenv("ADVISORY_PROVIDERS", "nvd")
    monkeypatch.setenv("PATH", "/nonexistent")
    result = build_custom_advisory_db(work_dir=tmp_path)
    assert result is None


def test_build_custom_advisory_db_returns_none_when_build_fails(
    tmp_path, monkeypatch
):
    """If grype-db build returns non-zero, return None."""
    from runner.scanners.dependencies import advisory_db

    monkeypatch.setenv("ADVISORY_PROVIDERS", "nvd")
    monkeypatch.setattr(advisory_db, "_tool_available", lambda _: True)

    calls: list[list[str]] = []

    def fake_run_tool(args, **kwargs):
        calls.append(list(args))
        if args[0] == "grype-db":
            return 1, "", "build error"
        return 0, "", ""

    monkeypatch.setattr(advisory_db, "run_tool", fake_run_tool)
    result = advisory_db.build_custom_advisory_db(work_dir=tmp_path)
    assert result is None
    assert any(c[0] == "vunnel" for c in calls)
    assert any(c[0] == "grype-db" for c in calls)


def test_build_custom_advisory_db_returns_path_on_success(tmp_path, monkeypatch):
    """Successful run returns the path to the produced .db file."""
    from runner.scanners.dependencies import advisory_db

    monkeypatch.setenv("ADVISORY_PROVIDERS", "nvd,github")
    monkeypatch.setattr(advisory_db, "_tool_available", lambda _: True)

    def fake_run_tool(args, **kwargs):
        if args[0] == "grype-db":
            build_dir = Path(args[args.index("-d") + 1])
            build_dir.mkdir(parents=True, exist_ok=True)
            (build_dir / "vulnerability.db").write_bytes(b"fake-db")
        return 0, "", ""

    monkeypatch.setattr(advisory_db, "run_tool", fake_run_tool)
    result = advisory_db.build_custom_advisory_db(work_dir=tmp_path)
    assert result is not None
    assert result.exists()
    assert result.suffix == ".db"


# ---------------------------------------------------------------------------
# Task 2.3 — DependenciesScanner orchestrator
# ---------------------------------------------------------------------------


def test_dependencies_scanner_has_correct_type():
    from runner.scanners.dependencies.scanner import DependenciesScanner

    assert DependenciesScanner.SCANNER_TYPE == "dependencies"


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


def test_run_scan_honours_concurrency_env(tmp_path, monkeypatch):
    """CONCURRENCY env should bound the ThreadPoolExecutor max_workers."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

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
    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db, "build_custom_advisory_db", lambda **_: None
    )
    monkeypatch.setattr(
        DependenciesScanner, "_scan_repo", lambda self, *a, **kw: None
    )

    scanner = DependenciesScanner()
    job = {
        "jobId": "test-conc",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git,https://github.com/c/d.git",
                "CONCURRENCY": "7",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "test-conc")
    assert captured["max_workers"] == 7


def test_run_scan_aggregates_findings(tmp_path, monkeypatch):
    """Per-repo findings.json files should be aggregated into findings.jsonl."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        (repo_out / "findings.json").write_text(
            json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {"id": f"CVE-{repo_name}"},
                            "artifact": {
                                "name": "pkg",
                                "version": "1.0",
                                "type": "npm",
                            },
                        }
                    ]
                }
            )
        )
        return repo_out / "findings.json"

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db, "build_custom_advisory_db", lambda **_: None
    )
    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)

    scanner = DependenciesScanner()
    job = {
        "jobId": "test-agg",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git\nhttps://github.com/c/d.git",
                "ORG_LABEL": "acme",
            },}
    job_dir = tmp_path / "test-agg"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    aggregated = (job_dir / "findings.jsonl").read_text().splitlines()
    advisory_ids = sorted(json.loads(line)["advisoryId"] for line in aggregated)
    assert advisory_ids == ["CVE-b", "CVE-d"]


def test_run_scan_tolerates_clone_failure(tmp_path, monkeypatch):
    """A failing repo should not abort the whole scan."""
    from runner.scanners._shared import GitCloneError
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        raise GitCloneError(f"simulated failure for {repo_url}")

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db, "build_custom_advisory_db", lambda **_: None
    )
    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)

    scanner = DependenciesScanner()
    job = {
        "jobId": "test-fail",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    job_dir = tmp_path / "test-fail"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert any("simulated failure" in line for line in result.log_tail)


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


def test_extract_manifests_copies_files_from_clone(tmp_path):
    """Given an SBOM with syft:location properties and a clone dir,
    manifest files are copied into the flattened layout the normalizer expects."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    clone = tmp_path / "clone"
    (clone / "subdir").mkdir(parents=True)
    (clone / "package.json").write_text('{"name": "test"}')
    (clone / "subdir" / "requirements.txt").write_text("flask==2.0\n")

    merged_sbom = tmp_path / "sbom.cdx.json"
    merged_sbom.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "name": "test",
                        "properties": [
                            {"name": "syft:location:0:path", "value": "/package.json"}
                        ],
                    },
                    {
                        "name": "flask",
                        "properties": [
                            {
                                "name": "syft:location:0:path",
                                "value": "/subdir/requirements.txt",
                            }
                        ],
                    },
                ]
            }
        )
    )

    manifests = tmp_path / "manifests"
    manifests.mkdir()
    scanner = DependenciesScanner()
    count = scanner._extract_manifests(
        merged_sbom, syft_sbom=tmp_path / "missing.json", clone_dir=clone, manifests_dir=manifests
    )
    assert count == 2
    assert (manifests / "package.json").exists()
    # Flattened layout: subdir/requirements.txt -> subdir__requirements.txt
    assert (manifests / "subdir__requirements.txt").exists()


def test_extract_manifests_uses_syft_fallback_when_merged_has_none(tmp_path):
    """When the merged SBOM has no matching properties, fall back to the
    syft SBOM's syft:location:* properties (bash run.sh:223-225)."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "pom.xml").write_text("<project/>\n")

    merged_sbom = tmp_path / "sbom.cdx.json"
    merged_sbom.write_text(json.dumps({"components": [{"name": "x"}]}))

    syft_sbom = tmp_path / "syft-sbom.cdx.json"
    syft_sbom.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "name": "x",
                        "properties": [
                            {"name": "syft:location:0:path", "value": "/pom.xml"}
                        ],
                    }
                ]
            }
        )
    )

    manifests = tmp_path / "manifests"
    manifests.mkdir()
    scanner = DependenciesScanner()
    count = scanner._extract_manifests(merged_sbom, syft_sbom, clone, manifests)
    assert count == 1
    assert (manifests / "pom.xml").exists()


def test_extract_manifests_rejects_path_traversal(tmp_path):
    """Paths containing .. must be rejected (bash run.sh:232)."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    clone = tmp_path / "clone"
    clone.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("dont-leak")

    merged_sbom = tmp_path / "sbom.cdx.json"
    merged_sbom.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "properties": [
                            {
                                "name": "syft:location:0:path",
                                "value": "/../secret.txt",
                            }
                        ]
                    }
                ]
            }
        )
    )

    manifests = tmp_path / "manifests"
    manifests.mkdir()
    scanner = DependenciesScanner()
    count = scanner._extract_manifests(
        merged_sbom, syft_sbom=tmp_path / "missing.json", clone_dir=clone, manifests_dir=manifests
    )
    assert count == 0
    assert not (manifests / "secret.txt").exists()


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


def test_run_scan_emits_progress_per_repo(tmp_path, monkeypatch):
    """Each successfully scanned repo must produce a scanning -> finished pair,
    counters must be monotonic, and the run must terminate in stage='done'."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        (out_dir / repo_name).mkdir(parents=True, exist_ok=True)
        return None

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db, "build_custom_advisory_db", lambda **_: None
    )
    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)

    captures: list[dict] = []

    def on_progress(log_tail, progress):
        captures.append(dict(progress))

    scanner = DependenciesScanner()
    job = {
        "jobId": "p2",
        "envVars": {
                "GIT_REPOS": "https://x/a.git,https://x/b.git",
                "CONCURRENCY": "1",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "p2", on_progress=on_progress)

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


def test_download_argus_db_skips_when_creds_missing(tmp_path, monkeypatch):
    """Either ARGUS_API_KEY or ARGUS_ENDPOINT unset -> returns None without
    touching the network."""
    from runner.scanners.dependencies import argus_db

    calls: list = []

    def fake_run_tool(*a, **kw):
        calls.append(a)
        return 0, "", ""

    monkeypatch.setattr(argus_db, "run_tool", fake_run_tool)

    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    assert argus_db.download_argus_db(tmp_path) is None

    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    assert argus_db.download_argus_db(tmp_path) is None

    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    assert argus_db.download_argus_db(tmp_path) is None

    assert calls == []


def test_download_argus_db_succeeds_with_valid_response(tmp_path, monkeypatch):
    """Mock curl writes the expected body — returned path exists and is the
    file we wrote."""
    from runner.scanners.dependencies import argus_db

    monkeypatch.setenv("ARGUS_API_KEY", "secret-key")
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.setattr(argus_db, "_resolve_host", lambda h: ["93.184.216.34"])

    captured_args: list[list[str]] = []

    def fake_run_tool(args, **kw):
        captured_args.append(list(args))
        out_path = Path(args[args.index("-o") + 1])
        out_path.write_bytes(b"argus-db-binary-blob")
        return 0, "", ""

    monkeypatch.setattr(argus_db, "run_tool", fake_run_tool)

    result = argus_db.download_argus_db(tmp_path)
    assert result is not None
    assert result.exists()
    assert result.read_bytes() == b"argus-db-binary-blob"
    # Sanity check: bearer header and correct path were used.
    flat = " ".join(captured_args[0])
    assert "Authorization: Bearer secret-key" in flat
    assert "https://argus.example.com/api/db/latest" in flat


def test_download_argus_db_returns_none_on_http_error(tmp_path, monkeypatch):
    """curl rc != 0 -> None, partial output file removed."""
    from runner.scanners.dependencies import argus_db

    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.setattr(argus_db, "_resolve_host", lambda h: ["93.184.216.34"])

    def fake_run_tool(args, **kw):
        out_path = Path(args[args.index("-o") + 1])
        out_path.write_bytes(b"partial-error-body")
        return 22, "", "HTTP 403"

    monkeypatch.setattr(argus_db, "run_tool", fake_run_tool)
    result = argus_db.download_argus_db(tmp_path)
    assert result is None
    assert not (tmp_path / "argus.db").exists()


def test_download_argus_db_returns_none_on_invalid_response(tmp_path, monkeypatch):
    """curl rc=0 but output is empty -> None, file removed."""
    from runner.scanners.dependencies import argus_db

    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.setattr(argus_db, "_resolve_host", lambda h: ["93.184.216.34"])

    def fake_run_tool(args, **kw):
        out_path = Path(args[args.index("-o") + 1])
        out_path.write_bytes(b"")
        return 0, "", ""

    monkeypatch.setattr(argus_db, "run_tool", fake_run_tool)
    assert argus_db.download_argus_db(tmp_path) is None
    assert not (tmp_path / "argus.db").exists()


def test_download_argus_db_respects_cancel_event(tmp_path, monkeypatch):
    """cancel_event should be forwarded to run_tool — verify it propagates."""
    import threading

    from runner.scanners.dependencies import argus_db

    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.setattr(argus_db, "_resolve_host", lambda h: ["93.184.216.34"])

    captured: dict = {}

    def fake_run_tool(args, **kw):
        captured["cancel_event"] = kw.get("cancel_event")
        return 1, "", "cancelled"

    monkeypatch.setattr(argus_db, "run_tool", fake_run_tool)
    cancel = threading.Event()
    argus_db.download_argus_db(tmp_path, cancel_event=cancel)
    assert captured["cancel_event"] is cancel


def test_download_argus_db_rejects_invalid_endpoint_scheme(tmp_path, monkeypatch):
    """Non-HTTPS endpoints must be rejected (SSRF guard)."""
    from runner.scanners.dependencies import argus_db

    calls: list = []
    monkeypatch.setattr(
        argus_db, "run_tool", lambda *a, **kw: calls.append(a) or (0, "", "")
    )

    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.setenv("ARGUS_ENDPOINT", "http://argus.example.com")
    assert argus_db.download_argus_db(tmp_path) is None
    assert calls == []

    monkeypatch.setenv("ARGUS_ENDPOINT", "file:///etc/passwd")
    assert argus_db.download_argus_db(tmp_path) is None
    assert calls == []


def test_download_argus_db_rejects_private_ip(tmp_path, monkeypatch):
    """Endpoints resolving to private/loopback ranges must be rejected."""
    from runner.scanners.dependencies import argus_db

    calls: list = []
    monkeypatch.setattr(
        argus_db, "run_tool", lambda *a, **kw: calls.append(a) or (0, "", "")
    )
    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://internal.example.com")
    monkeypatch.setattr(argus_db, "_resolve_host", lambda h: ["10.0.0.5"])
    assert argus_db.download_argus_db(tmp_path) is None
    assert calls == []


def test_download_argus_db_rejects_loopback_hostname(tmp_path, monkeypatch):
    """Explicit deny-list hosts (localhost, GCE metadata) are rejected."""
    from runner.scanners.dependencies import argus_db

    calls: list = []
    monkeypatch.setattr(
        argus_db, "run_tool", lambda *a, **kw: calls.append(a) or (0, "", "")
    )
    monkeypatch.setenv("ARGUS_API_KEY", "k")
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://localhost")
    assert argus_db.download_argus_db(tmp_path) is None

    monkeypatch.setenv("ARGUS_ENDPOINT", "https://metadata.google.internal")
    assert argus_db.download_argus_db(tmp_path) is None
    assert calls == []


# ---------------------------------------------------------------------------
# Gap 1 — Argus integration with grype DB precedence
# ---------------------------------------------------------------------------


def test_run_scan_uses_argus_db_when_creds_set(tmp_path, monkeypatch):
    """When Argus download succeeds, grype must be invoked with --db
    pointing at the Argus path — Argus has top priority."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    argus_marker = tmp_path / "fake-argus.db"
    argus_marker.write_bytes(b"argus")

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: argus_marker,
    )
    vunnel_calls: list = []
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: vunnel_calls.append(kw) or None,
    )

    captured_db: list = []

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        captured_db.append(kwargs.get("custom_db_path"))
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        (out_dir / repo_name).mkdir(parents=True, exist_ok=True)
        return None

    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)

    scanner = DependenciesScanner()
    job = {
        "jobId": "argus-1",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "ARGUS_API_KEY": "k",
                "ARGUS_ENDPOINT": "https://argus.example.com",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "argus-1")
    assert captured_db == [argus_marker]
    # vunnel must NOT be consulted when Argus succeeds — Argus > vunnel.
    assert vunnel_calls == []


def test_run_scan_falls_back_to_vunnel_db_when_argus_download_fails(
    tmp_path, monkeypatch
):
    """Argus returning None must trigger the vunnel-built DB fallback."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    vunnel_marker = tmp_path / "fake-vunnel.db"
    vunnel_marker.write_bytes(b"vunnel")

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: vunnel_marker,
    )

    captured_db: list = []

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        captured_db.append(kwargs.get("custom_db_path"))
        return None

    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)

    scanner = DependenciesScanner()
    job = {
        "jobId": "argus-fallback",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    scanner.run_scan(job, job_dir=tmp_path / "argus-fallback")
    assert captured_db == [vunnel_marker]


def test_run_scan_falls_back_to_default_db_when_neither_available(
    tmp_path, monkeypatch
):
    """No Argus + no vunnel -> custom_db_path is None (grype uses default)."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )

    captured_db: list = []

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        captured_db.append(kwargs.get("custom_db_path"))
        return None

    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)

    scanner = DependenciesScanner()
    job = {
        "jobId": "no-db",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    scanner.run_scan(job, job_dir=tmp_path / "no-db")
    assert captured_db == [None]


# ---------------------------------------------------------------------------
# Gap 2 — advisories_only scan mode
# ---------------------------------------------------------------------------


def test_advisories_only_is_supported_mode():
    from runner.scanners.dependencies.scanner import (
        SCAN_MODE_ADVISORIES_ONLY,
        SCAN_MODE_FULL,
        SUPPORTED_SCAN_MODES,
    )

    assert SCAN_MODE_FULL in SUPPORTED_SCAN_MODES
    assert SCAN_MODE_ADVISORIES_ONLY in SUPPORTED_SCAN_MODES


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


def test_run_scan_advisories_only_skips_clone_and_syft(tmp_path, monkeypatch):
    """advisories_only must NOT clone or run syft/cdxgen."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )

    monkeypatch.setattr(scanner_mod.download_sboms, "download_sboms", _fake_download_two_sboms_kw)

    clone_calls: list = []
    syft_calls: list = []
    cdxgen_calls: list = []
    monkeypatch.setattr(
        scanner_mod, "clone_repo", lambda *a, **kw: clone_calls.append(a)
    )
    monkeypatch.setattr(
        DependenciesScanner, "_run_syft", lambda self, *a, **kw: syft_calls.append(a)
    )
    monkeypatch.setattr(
        DependenciesScanner, "_run_cdxgen", lambda self, *a, **kw: cdxgen_calls.append(a)
    )
    monkeypatch.setattr(
        DependenciesScanner,
        "_run_grype",
        lambda self, sbom, out, db, ce: out.write_text(
            json.dumps({"matches": []})
        )
        or True,
    )

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-skip",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    result = scanner.run_scan(job, job_dir=tmp_path / "adv-skip")
    assert result.exit_code == 0
    assert clone_calls == []
    assert syft_calls == []
    assert cdxgen_calls == []


def test_run_scan_advisories_only_downloads_sboms_from_minio(
    tmp_path, monkeypatch
):
    """advisories_only must call download_sboms with the per-job sbom dir."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )
    monkeypatch.setattr(
        DependenciesScanner,
        "_run_grype",
        lambda self, sbom, out, db, ce: out.write_text(
            json.dumps({"matches": []})
        )
        or True,
    )

    captured: list = []

    def fake_download(*, backend_client, job_id, output_dir):
        captured.append(Path(output_dir))
        return _fake_download_two_sboms(output_dir)

    monkeypatch.setattr(scanner_mod.download_sboms, "download_sboms", fake_download)

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-dl",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    job_dir = tmp_path / "adv-dl"
    scanner.run_scan(job, job_dir=job_dir)
    assert len(captured) == 1
    # The downloader is given a per-job subdir, not the job_dir itself.
    assert captured[0].parent == job_dir


def test_run_scan_advisories_only_runs_grype_against_downloaded_sboms(
    tmp_path, monkeypatch
):
    """Every downloaded SBOM must produce a grype call against it."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )
    monkeypatch.setattr(
        scanner_mod.download_sboms,
        "download_sboms",
        _fake_download_two_sboms_kw,
    )

    grype_calls: list = []

    def fake_grype(self, sbom, out, db, ce):
        grype_calls.append(sbom)
        out.write_text(json.dumps({"matches": []}))
        return True

    monkeypatch.setattr(DependenciesScanner, "_run_grype", fake_grype)

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-grype",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "adv-grype")
    assert len(grype_calls) == 2
    # Each grype call must point at a per-repo sbom.cdx.json inside the
    # output dir — not the raw downloaded file.
    for sbom in grype_calls:
        assert sbom.name == "sbom.cdx.json"


def test_run_scan_advisories_only_emits_progress(tmp_path, monkeypatch):
    """advisories_only must drive the same progress emitter as full mode."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )
    monkeypatch.setattr(
        scanner_mod.download_sboms,
        "download_sboms",
        _fake_download_two_sboms_kw,
    )
    monkeypatch.setattr(
        DependenciesScanner,
        "_run_grype",
        lambda self, sbom, out, db, ce: out.write_text(
            json.dumps({"matches": []})
        )
        or True,
    )

    from unittest.mock import MagicMock
    backend = MagicMock()

    captures: list[dict] = []
    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-prog",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
                "CONCURRENCY": "1",
            },}
    scanner.run_scan(
        job,
        job_dir=tmp_path / "adv-prog",
        on_progress=lambda lt, p: captures.append(dict(p)),
    )
    assert captures[-1]["stage"] == "done"
    assert captures[-1]["finishedRepos"] == 2
    assert any(c.get("stage") == "scanning" for c in captures)
    assert any(c.get("stage") == "normalizing" for c in captures)


def test_run_scan_advisories_only_writes_done_marker(tmp_path, monkeypatch):
    """_done marker must be written at the end of advisories_only."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )
    monkeypatch.setattr(
        scanner_mod.download_sboms,
        "download_sboms",
        _fake_download_two_sboms_kw,
    )
    monkeypatch.setattr(
        DependenciesScanner,
        "_run_grype",
        lambda self, sbom, out, db, ce: out.write_text(
            json.dumps({"matches": []})
        )
        or True,
    )

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-done",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    job_dir = tmp_path / "adv-done"
    scanner.run_scan(job, job_dir=job_dir)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_advisories_only_fails_loudly_when_sboms_unavailable(
    tmp_path, monkeypatch
):
    """If the downloader raises (no creds, bucket unreachable), the scanner
    must exit with code 2 — an empty findings file would silently overwrite
    the previous run."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )

    def raise_err(*, backend_client, job_id, output_dir):
        raise RuntimeError("backend unavailable")

    monkeypatch.setattr(
        scanner_mod.download_sboms, "download_sboms", raise_err
    )

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-fail",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    job_dir = tmp_path / "adv-fail"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 2
    assert any("SBOM download" in line for line in result.log_tail)
    # Still write the _done marker so the manifest streamer doesn't hang.
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_advisories_only_fails_loudly_when_no_sboms_returned(
    tmp_path, monkeypatch
):
    """download_sboms returns 0 / empty dir — must exit 2, not silently 0."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )

    def empty_download(*, backend_client, job_id, output_dir):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return 0

    monkeypatch.setattr(
        scanner_mod.download_sboms, "download_sboms", empty_download
    )

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-empty",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    result = scanner.run_scan(job, job_dir=tmp_path / "adv-empty")
    assert result.exit_code == 2
    assert any("no SBOMs available" in line for line in result.log_tail)


def test_run_scan_advisories_only_normalizes_findings_into_jsonl(
    tmp_path, monkeypatch
):
    """Findings produced in advisories_only mode must end up in findings.jsonl."""
    from runner.scanners.dependencies import scanner as scanner_mod
    from runner.scanners.dependencies.scanner import DependenciesScanner

    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )
    monkeypatch.setattr(
        scanner_mod.argus_db,
        "download_argus_db",
        lambda work_dir, *, cancel_event=None: None,
    )
    monkeypatch.setattr(
        scanner_mod.advisory_db,
        "build_custom_advisory_db",
        lambda **kw: None,
    )
    monkeypatch.setattr(
        scanner_mod.download_sboms,
        "download_sboms",
        _fake_download_two_sboms_kw,
    )

    def fake_grype(self, sbom, out, db, ce):
        repo = sbom.parent.name
        out.write_text(
            json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {
                                "id": f"CVE-{repo}",
                                "severity": "High",
                            },
                            "artifact": {
                                "name": "pkg",
                                "version": "1.0",
                                "type": "npm",
                            },
                        }
                    ]
                }
            )
        )
        return True

    monkeypatch.setattr(DependenciesScanner, "_run_grype", fake_grype)

    from unittest.mock import MagicMock
    backend = MagicMock()

    scanner = DependenciesScanner()
    job = {
        "jobId": "adv-norm",
        "_backend": backend,
        "envVars": {
                "SCAN_MODE": "advisories_only",
                "ORG_LABEL": "acme",
            },}
    job_dir = tmp_path / "adv-norm"
    scanner.run_scan(job, job_dir=job_dir)
    out_file = job_dir / "findings.jsonl"
    assert out_file.exists()
    advisory_ids = sorted(
        json.loads(line)["advisoryId"] for line in out_file.read_text().splitlines()
    )
    assert advisory_ids == ["CVE-gizmo", "CVE-widget"]


# ---------------------------------------------------------------------------
# Task 3.2 / 3.3 — sbom_only scan mode (skip_grype)
# ---------------------------------------------------------------------------


def test_scan_repo_skip_grype_returns_none(tmp_path, monkeypatch):
    """When skip_grype=True, _scan_repo builds SBOM, registers it, but skips
    grype + manifest extraction.

    Bash reference: scanners/dependencies/run.sh has no sbom_only branch
    inside scan_repository, but the runner mirrors the container scanner's
    sbom_only contract (clone + SBOM + register, no grype, no findings.json).
    """
    import threading

    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    grype_called: list[str] = []

    def fake_clone(url, dest, **_kwargs):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "package.json").write_text('{"name": "test"}')

    def fake_read_head_sha(self, clone_dir, cancel_event):
        return "deadbeef"

    def fake_run_syft(self, target, output, cancel_event):
        output.write_text(json.dumps({"components": []}))
        return True

    def fake_run_cdxgen(self, target, output, cancel_event):
        return False

    def fake_run_grype(self, sbom, output, custom_db_path, cancel_event):
        grype_called.append(str(sbom))
        return True

    monkeypatch.setattr(
        "runner.scanners.dependencies.scanner.clone_repo", fake_clone
    )
    monkeypatch.setattr(
        DependenciesScanner, "_read_head_sha", fake_read_head_sha
    )
    monkeypatch.setattr(DependenciesScanner, "_run_syft", fake_run_syft)
    monkeypatch.setattr(DependenciesScanner, "_run_cdxgen", fake_run_cdxgen)
    monkeypatch.setattr(DependenciesScanner, "_run_grype", fake_run_grype)

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = scanner._scan_repo(
        "https://github.com/example/repo.git",
        out_dir,
        git_token=None,
        custom_db_path=None,
        cancel_event=threading.Event(),
        skip_grype=True,
    )

    assert result is None, "skip_grype should return None — no findings file"
    assert grype_called == [], "grype must not be invoked when skip_grype=True"
    # SBOM still written + registered
    assert (out_dir / "repo" / "sbom.cdx.json").exists()


def test_scan_repo_skip_grype_default_false_still_runs_grype(tmp_path, monkeypatch):
    """Default skip_grype=False keeps the full flow — regression guard."""
    import threading

    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    grype_called: list[str] = []

    def fake_clone(url, dest, **_kwargs):
        dest.mkdir(parents=True, exist_ok=True)

    def fake_read_head_sha(self, clone_dir, cancel_event):
        return "deadbeef"

    def fake_run_syft(self, target, output, cancel_event):
        output.write_text(json.dumps({"components": []}))
        return True

    def fake_run_cdxgen(self, target, output, cancel_event):
        return False

    def fake_run_grype(self, sbom, output, custom_db_path, cancel_event):
        grype_called.append(str(sbom))
        output.write_text("{}")
        return True

    monkeypatch.setattr(
        "runner.scanners.dependencies.scanner.clone_repo", fake_clone
    )
    monkeypatch.setattr(
        DependenciesScanner, "_read_head_sha", fake_read_head_sha
    )
    monkeypatch.setattr(DependenciesScanner, "_run_syft", fake_run_syft)
    monkeypatch.setattr(DependenciesScanner, "_run_cdxgen", fake_run_cdxgen)
    monkeypatch.setattr(DependenciesScanner, "_run_grype", fake_run_grype)

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = scanner._scan_repo(
        "https://github.com/example/repo.git",
        out_dir,
        git_token=None,
        custom_db_path=None,
        cancel_event=threading.Event(),
    )

    assert result is not None
    assert len(grype_called) == 1


def test_run_scan_sbom_only_skips_grype_and_writes_done(tmp_path, monkeypatch):
    """sbom_only mode: builds SBOM for each repo, skips grype, writes _done marker.

    Bash reference: SCAN_MODE=sbom_only does NOT emit a findings.jsonl (no
    per-repo findings.json is produced when grype is skipped, so the
    normalization loop yields zero rows). The runner matches this by simply
    skipping normalization entirely — only the _done manifest marker is
    written.
    """
    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    grype_called: list[str] = []
    scan_repo_calls: list[tuple[str, bool]] = []

    def fake_scan_repo(
        self, repo_url, out_dir, *, git_token, custom_db_path, cancel_event,
        skip_grype=False,
    ):
        scan_repo_calls.append((repo_url, skip_grype))
        if skip_grype:
            return None
        grype_called.append(repo_url)
        return out_dir / "findings.json"

    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)
    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )

    job = {
        "jobId": "sbom-test",
        "envVars": {
            "GIT_REPOS": "https://github.com/example/a.git",
            "SCAN_MODE": "sbom_only",
            "CONCURRENCY": "1",
        },}
    job_dir = tmp_path / "sbom-test"
    result = scanner.run_scan(job, job_dir=job_dir)

    assert result.exit_code == 0
    assert grype_called == [], "grype must not run in sbom_only mode"
    assert scan_repo_calls and all(skip for _, skip in scan_repo_calls)
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest
    # No findings.jsonl is emitted — match bash (nothing to normalize).
    assert not (job_dir / "findings.jsonl").exists()


def test_run_scan_sbom_only_emits_progress_done(tmp_path, monkeypatch):
    """sbom_only mode emits final progress event with stage='done' and
    finishedRepos == expectedRepos."""
    from runner.scanners.dependencies.scanner import DependenciesScanner

    scanner = DependenciesScanner()
    progress_events: list[dict] = []

    def fake_scan_repo(self, *args, **kwargs):
        return None

    monkeypatch.setattr(DependenciesScanner, "_scan_repo", fake_scan_repo)
    monkeypatch.setattr(
        DependenciesScanner, "_ensure_grype_db", lambda self, c: None
    )

    job = {
        "jobId": "sbom-prog",
        "envVars": {
            "GIT_REPOS": "https://github.com/example/a.git,https://github.com/example/b.git",
            "SCAN_MODE": "sbom_only",
        },}
    scanner.run_scan(
        job, job_dir=tmp_path / "sbom-prog",
        on_progress=lambda log, prog: progress_events.append(dict(prog)),
    )

    assert any(p.get("stage") == "done" for p in progress_events)
    final = progress_events[-1]
    assert final["finishedRepos"] == final["expectedRepos"] == 2


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
