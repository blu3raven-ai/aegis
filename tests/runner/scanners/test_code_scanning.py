"""Tests for the embedded code-scanning scanner module."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path


# ---------------------------------------------------------------------------
# Task 5.1 - extract_context.py
# ---------------------------------------------------------------------------


def _write_minimal_sarif(path: Path, locations: list[tuple[str, int]]) -> None:
    results = [
        {
            "ruleId": "test.rule",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line},
                    }
                }
            ],
        }
        for uri, line in locations
    ]
    path.write_text(json.dumps({"runs": [{"results": results}]}))


def test_extract_context_missing_sarif_writes_empty(tmp_path):
    from runner.scanners.code_scanning.extract_context import extract_context

    clone = tmp_path / "clone"
    clone.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    n = extract_context(clone, out)
    assert n == 0
    assert (out / "context.json").read_text() == "{}"


def test_extract_context_writes_window_and_imports(tmp_path):
    from runner.scanners.code_scanning.extract_context import extract_context

    clone = tmp_path / "clone"
    clone.mkdir()
    src = clone / "app.py"
    src.write_text(
        "import os\n"
        "from x import y\n"
        "\n"
        "def f():\n"
        "    SECRET = 'AKIA...'\n"
    )
    out = tmp_path / "out"
    out.mkdir()
    _write_minimal_sarif(out / "semgrep.sarif", [("app.py", 5)])

    n = extract_context(clone, out)
    assert n == 1
    payload = json.loads((out / "context.json").read_text())
    entry = payload["app.py:5"]
    assert entry["file_class"] == "source"
    assert "import os" in entry["imports"]
    assert "SECRET" in entry["code_window"]


def test_extract_context_skips_path_traversal(tmp_path):
    from runner.scanners.code_scanning.extract_context import extract_context

    clone = tmp_path / "clone"
    clone.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    _write_minimal_sarif(
        out / "semgrep.sarif",
        [("../etc/passwd", 1), ("/etc/passwd", 1)],
    )

    extract_context(clone, out)
    payload = json.loads((out / "context.json").read_text())
    assert payload == {}


def test_extract_context_strips_tmp_prefix(tmp_path):
    from runner.scanners.code_scanning.extract_context import extract_context

    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "main.py").write_text("a\nb\nc\n")
    out = tmp_path / "out"
    out.mkdir()
    # Semgrep emits absolute /tmp/tmp.XXXX/main.py — the prefix must be stripped
    _write_minimal_sarif(out / "semgrep.sarif", [("/tmp/tmp.AbCd1234/main.py", 2)])

    extract_context(clone, out)
    payload = json.loads((out / "context.json").read_text())
    assert "main.py:2" in payload


def test_classify_vendor_and_generated_and_test(tmp_path):
    from runner.scanners.code_scanning.extract_context import _classify

    assert _classify("node_modules/foo/bar.js") == "vendor"
    assert _classify("src/foo/bar.min.js") == "generated"
    assert _classify("tests/test_foo.py") == "test"
    assert _classify("src/handler.py") == "source"


# ---------------------------------------------------------------------------
# Task 5.1 - reachability.py (lazy tree-sitter)
# ---------------------------------------------------------------------------


def test_reachability_module_does_not_import_tree_sitter_at_module_level():
    """Importing reachability.py must NOT load tree_sitter/tree_sitter_languages."""
    code = (
        "import sys\n"
        "for mod in list(sys.modules):\n"
        "    if mod.startswith(('tree_sitter',)):\n"
        "        del sys.modules[mod]\n"
        "import runner.scanners.code_scanning.reachability  # noqa\n"
        "leaked = [m for m in sys.modules if m.startswith('tree_sitter')]\n"
        "assert not leaked, f'tree_sitter leaked at import: {leaked}'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[3],
    )
    assert result.returncode == 0, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_reachability_missing_sarif_returns_empty(tmp_path):
    from runner.scanners.code_scanning.reachability import build_reachability

    result = build_reachability(tmp_path, tmp_path / "no-such.json")
    assert result == {}


def test_reachability_no_findings_returns_empty(tmp_path):
    from runner.scanners.code_scanning.reachability import build_reachability

    sarif = tmp_path / "opengrep.json"
    sarif.write_text(json.dumps({"runs": [{"results": []}]}))
    assert build_reachability(tmp_path, sarif) == {}


def test_reachability_write_writes_empty_on_missing(tmp_path):
    from runner.scanners.code_scanning.reachability import write_reachability

    out = tmp_path / "reachability.json"
    write_reachability(tmp_path, tmp_path / "no-such.json", out)
    assert out.read_text() == "{}"


def test_reachability_dead_code_dirs_marked_unreachable(tmp_path):
    """Module-level finding under a dead-code directory is unreachable
    even without a tree-sitter parser available."""
    from runner.scanners.code_scanning.reachability import build_reachability

    clone = tmp_path / "clone"
    (clone / "archived").mkdir(parents=True)
    sarif = tmp_path / "opengrep.json"
    _write_minimal_sarif(sarif, [("archived/old.py", 1)])
    result = build_reachability(clone, sarif)
    assert result["archived/old.py:1"] == {"verdict": "unreachable"}


def test_reachability_module_level_default_reachable(tmp_path):
    from runner.scanners.code_scanning.reachability import build_reachability

    clone = tmp_path / "clone"
    (clone / "src").mkdir(parents=True)
    sarif = tmp_path / "opengrep.json"
    _write_minimal_sarif(sarif, [("src/main.py", 1)])
    result = build_reachability(clone, sarif)
    assert result["src/main.py:1"]["verdict"] == "reachable"
    assert result["src/main.py:1"]["entry_point"] == "module-level"


# ---------------------------------------------------------------------------
# Task 5.2 - normalize.py
# ---------------------------------------------------------------------------


def _sarif_with(results: list[dict], rules: list[dict] | None = None) -> dict:
    return {
        "runs": [
            {
                "tool": {"driver": {"rules": rules or []}},
                "results": results,
            }
        ]
    }


def test_normalize_file_emits_finding_with_severity(tmp_path):
    from runner.scanners.code_scanning.normalize import normalize_file

    sarif = tmp_path / "opengrep.json"
    sarif.write_text(
        json.dumps(
            _sarif_with(
                results=[
                    {
                        "ruleId": "py.sqli",
                        "level": "error",
                        "message": {"text": "SQLi"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {
                                        "startLine": 3,
                                        "endLine": 3,
                                        "snippet": {"text": "exec(q)"},
                                    },
                                }
                            }
                        ],
                    }
                ],
                rules=[
                    {
                        "id": "py.sqli",
                        "shortDescription": {"text": "SQL injection"},
                        "defaultConfiguration": {"level": "error"},
                        "properties": {
                            "precision": "high",
                            "tags": ["CWE-89", "security"],
                        },
                    }
                ],
            )
        )
    )
    findings, active = normalize_file(sarif, "acme", "acme/repo", "abc123", {}, {})
    assert active == {"py.sqli"}
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["confidence"] == "high"
    assert f["rule_id"] == "py.sqli"
    assert f["repo_full_name"] == "acme/repo"
    assert f["commit_sha"] == "abc123"
    assert f["cwe"] == ["CWE-89"]
    assert f["file_class"] == "source"
    assert f["reachability"] is None


def test_normalize_file_filters_vendor_and_secret_rules(tmp_path):
    from runner.scanners.code_scanning.normalize import normalize_file

    sarif = tmp_path / "opengrep.json"
    sarif.write_text(
        json.dumps(
            _sarif_with(
                results=[
                    {
                        "ruleId": "rule.secrets.aws",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rule.x",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "node_modules/foo/bar.js"
                                    },
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    },
                ],
                rules=[
                    {"id": "rule.secrets.aws"},
                    {"id": "rule.x"},
                ],
            )
        )
    )
    context = {"node_modules/foo/bar.js:1": {"file_class": "vendor"}}
    findings, _ = normalize_file(sarif, "acme", "r", "HEAD", context, {})
    assert findings == []


def test_normalize_file_strips_tmp_prefix_for_context_lookup(tmp_path):
    from runner.scanners.code_scanning.normalize import normalize_file

    sarif = tmp_path / "opengrep.json"
    sarif.write_text(
        json.dumps(
            _sarif_with(
                results=[
                    {
                        "ruleId": "r",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "/tmp/tmp.AbCd/main.py"
                                    },
                                    "region": {"startLine": 4},
                                }
                            }
                        ],
                    }
                ],
                rules=[{"id": "r"}],
            )
        )
    )
    context = {"main.py:4": {"file_class": "source", "code_window": "WIN"}}
    reach = {"main.py:4": {"verdict": "reachable"}}
    findings, _ = normalize_file(sarif, "acme", "r", "HEAD", context, reach)
    assert findings[0]["code_window"] == "WIN"
    assert findings[0]["reachability"] == {"verdict": "reachable"}


def test_normalize_code_scanning_output_writes_jsonl(tmp_path):
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "repo-a"
    repo.mkdir()
    (repo / "head-sha.txt").write_text("abc1234\n")
    (repo / "html_url.txt").write_text("https://github.com/acme/repo-a\n")
    (repo / "semgrep.sarif").write_text(
        json.dumps(
            _sarif_with(
                results=[
                    {
                        "ruleId": "r",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
                rules=[{"id": "r"}],
            )
        )
    )
    total, errors = normalize_code_scanning_output("acme", tmp_path, "run-1")
    assert total == 1
    assert errors == 0
    line = (tmp_path / "findings.jsonl").read_text().strip()
    record = json.loads(line)
    assert record["repo_full_name"] == "repo-a"
    assert record["commit_sha"] == "abc1234"
    assert record["repo_html_url"] == "https://github.com/acme/repo-a"


def test_normalize_code_scanning_output_uses_compact_separators(tmp_path):
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "semgrep.sarif").write_text(
        json.dumps(
            _sarif_with(
                results=[
                    {
                        "ruleId": "r",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
                rules=[{"id": "r"}],
            )
        )
    )
    normalize_code_scanning_output("acme", tmp_path, "run-1")
    line = (tmp_path / "findings.jsonl").read_text().strip()
    assert ", " not in line and ": " not in line


def test_normalize_code_scanning_output_writes_active_rules(tmp_path):
    from runner.scanners.code_scanning.normalize import (
        normalize_code_scanning_output,
    )

    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "semgrep.sarif").write_text(
        json.dumps(
            _sarif_with(
                results=[],
                rules=[{"id": "a"}, {"id": "b"}],
            )
        )
    )
    normalize_code_scanning_output("acme", tmp_path, "run-1")
    rules = json.loads((tmp_path / "active_rules.json").read_text())
    assert rules == ["a", "b"]


# ---------------------------------------------------------------------------
# Task 5.3 - CodeScanningScanner orchestrator
# ---------------------------------------------------------------------------


def test_code_scanning_scanner_has_correct_type():
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    assert CodeScanningScanner.SCANNER_TYPE == "code_scanning"


def test_code_scanning_scanner_implements_base_protocol():
    from runner.scanners.base import BaseScanner
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    assert isinstance(CodeScanningScanner(), BaseScanner)


def test_run_scan_empty_repos_returns_clean(tmp_path):
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    scanner = CodeScanningScanner()
    job = {"jobId": "test-cs", "envVars": {"GIT_REPOS": ""},}
    job_dir = tmp_path / "test-cs"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    manifest = (job_dir / "_manifest.jsonl").read_text()
    assert '"file": "_done"' in manifest


def test_run_scan_missing_docker_args_does_not_crash(tmp_path):
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    scanner = CodeScanningScanner()
    result = scanner.run_scan({"jobId": "bare"}, job_dir=tmp_path / "bare")
    assert result.exit_code == 0


def test_run_scan_pre_cancel_returns_137(tmp_path):
    from runner.scanners._subprocess import CANCELLED_EXIT_CODE
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    scanner = CodeScanningScanner()
    cancel = threading.Event()
    cancel.set()
    job = {
        "jobId": "x",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    result = scanner.run_scan(
        job, job_dir=tmp_path / "x", cancel_event=cancel
    )
    assert result.exit_code == CANCELLED_EXIT_CODE


def test_build_config_args_default_uses_registry_packs():
    from runner.scanners.code_scanning.scanner import (
        CodeScanningScanner,
        DEFAULT_REGISTRY_RULESETS,
    )

    # No RULESETS and no SEMGREP_RULES_PATH, registry reachable → the packs.
    args = CodeScanningScanner._build_config_args("", "", registry_reachable=lambda: True)
    expected = [a for pack in DEFAULT_REGISTRY_RULESETS for a in ("--config", pack)]
    assert args == expected


def test_build_config_args_registry_unreachable_falls_back_to_bundled():
    from runner.scanners.code_scanning.scanner import (
        CodeScanningScanner,
        DEFAULT_SEMGREP_RULES_PATH,
    )

    # Offline runner: the registry packs can't be fetched, so degrade to the
    # bundled rules instead of failing the code scan.
    args = CodeScanningScanner._build_config_args("", "", registry_reachable=lambda: False)
    assert args == ["--config", DEFAULT_SEMGREP_RULES_PATH]


def test_build_config_args_explicit_refs_skip_registry_probe():
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    # Explicit RULESETS / rules_path win before any probe — an unreachable
    # registry must not override an operator's explicit choice.
    def _boom() -> bool:
        raise AssertionError("registry probe should not run when refs are explicit")

    assert CodeScanningScanner._build_config_args(
        "p/foo", "", registry_reachable=_boom
    ) == ["--config", "p/foo"]
    assert CodeScanningScanner._build_config_args(
        "", "/opt/semgrep-rules", registry_reachable=_boom
    ) == ["--config", "/opt/semgrep-rules"]


def test_build_config_args_explicit_rules_path_wins_over_default():
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    args = CodeScanningScanner._build_config_args("", "/opt/semgrep-rules")
    assert args == ["--config", "/opt/semgrep-rules"]


def test_build_config_args_named_rulesets_pass_through():
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    # Registry refs given via RULESETS are passed to semgrep directly.
    args = CodeScanningScanner._build_config_args(
        "p/security-audit, p/owasp", "/opt/semgrep-rules"
    )
    assert args == ["--config", "p/security-audit", "--config", "p/owasp"]


def test_build_config_args_absolute_path_passes_through(tmp_path):
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    rules = tmp_path / "rules"
    rules.mkdir()
    args = CodeScanningScanner._build_config_args(
        str(rules), "/opt/semgrep-rules"
    )
    assert args == ["--config", str(rules)]


def test_run_scan_uses_env_semgrep_rules_path(tmp_path, monkeypatch):
    """SEMGREP_RULES_PATH env override should be honoured."""
    from runner.scanners.code_scanning import scanner as scanner_mod
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    monkeypatch.delenv("SEMGREP_RULES_PATH", raising=False)
    captured: dict = {}

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        captured["config_args"] = kwargs["config_args"]
        return None

    monkeypatch.setattr(CodeScanningScanner, "_scan_repo", fake_scan_repo)

    scanner = CodeScanningScanner()
    job = {
        "jobId": "j",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SEMGREP_RULES_PATH": "/custom/rules",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "j")
    assert captured["config_args"] == ["--config", "/custom/rules"]


def test_run_scan_uses_process_env_semgrep_rules_path(tmp_path, monkeypatch):
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    monkeypatch.setenv("SEMGREP_RULES_PATH", "/from/env")
    captured: dict = {}

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        captured["config_args"] = kwargs["config_args"]
        return None

    monkeypatch.setattr(CodeScanningScanner, "_scan_repo", fake_scan_repo)

    scanner = CodeScanningScanner()
    job = {
        "jobId": "j",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    scanner.run_scan(job, job_dir=tmp_path / "j")
    assert captured["config_args"] == ["--config", "/from/env"]


def test_run_scan_honours_concurrency_env(tmp_path, monkeypatch):
    from runner.scanners.code_scanning import scanner as scanner_mod
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

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
    monkeypatch.setattr(CodeScanningScanner, "_scan_repo", lambda *a, **kw: None)

    scanner = CodeScanningScanner()
    job = {
        "jobId": "test-conc",
        "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git,https://github.com/c/d.git",
                "CONCURRENCY": "9",
            },}
    scanner.run_scan(job, job_dir=tmp_path / "test-conc")
    assert captured["max_workers"] == 9


def test_run_scan_tolerates_clone_failure(tmp_path, monkeypatch):
    from runner.scanners._shared import GitCloneError
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        raise GitCloneError(f"simulated failure for {repo_url}")

    monkeypatch.setattr(CodeScanningScanner, "_scan_repo", fake_scan_repo)

    scanner = CodeScanningScanner()
    job = {
        "jobId": "test-fail",
        "envVars": {"GIT_REPOS": "https://github.com/a/b.git"},}
    job_dir = tmp_path / "test-fail"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert any("simulated failure" in line for line in result.log_tail)


def test_run_scan_aggregates_findings_jsonl(tmp_path, monkeypatch):
    """Stubbed per-repo SARIF -> normalize.normalize_code_scanning_output
    aggregates into findings.jsonl correctly."""
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        repo_out = out_dir / repo_name
        repo_out.mkdir(parents=True, exist_ok=True)
        sarif = repo_out / "semgrep.sarif"
        sarif.write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "tool": {"driver": {"rules": [{"id": "r"}]}},
                            "results": [
                                {
                                    "ruleId": "r",
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": "a.py"
                                                },
                                                "region": {"startLine": 1},
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            )
        )
        return sarif

    monkeypatch.setattr(CodeScanningScanner, "_scan_repo", fake_scan_repo)

    scanner = CodeScanningScanner()
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
    repos = sorted({f["repo_full_name"] for f in lines})
    assert repos == ["b", "d"]




def test_run_scan_emits_progress(tmp_path):
    """on_progress should be called with the expected dict shape, terminating
    in stage='done'."""
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    captures: list[dict] = []

    def on_progress(log_tail, progress):
        captures.append(dict(progress))

    scanner = CodeScanningScanner()
    job = {"jobId": "p1", "envVars": {"GIT_REPOS": ""},}
    scanner.run_scan(job, job_dir=tmp_path / "p1", on_progress=on_progress)

    assert captures, "on_progress was never called"
    assert any(c.get("stage") == "done" for c in captures)
    assert all("scannedRepos" in c for c in captures)
    assert all("finishedRepos" in c for c in captures)
    assert all("expectedRepos" in c for c in captures)


def test_run_scan_emits_progress_per_repo(tmp_path, monkeypatch):
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    def fake_scan_repo(self, repo_url, out_dir, **kwargs):
        return None

    monkeypatch.setattr(CodeScanningScanner, "_scan_repo", fake_scan_repo)

    captures: list[dict] = []
    scanner = CodeScanningScanner()
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


def test_run_scan_emits_progress_done_on_pre_cancel(tmp_path):
    import threading as _threading

    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    captures: list[dict] = []
    cancel = _threading.Event()
    cancel.set()
    scanner = CodeScanningScanner()
    job = {
        "jobId": "p3",
        "envVars": {"GIT_REPOS": "https://x/a.git"},}
    scanner.run_scan(
        job,
        job_dir=tmp_path / "p3",
        on_progress=lambda lt, p: captures.append(dict(p)),
        cancel_event=cancel,
    )
    assert captures and captures[-1]["stage"] == "done"


def test_run_scan_progress_callback_exception_does_not_abort(tmp_path):
    from runner.scanners.code_scanning.scanner import CodeScanningScanner

    def bad(log_tail, progress):
        raise RuntimeError("boom")

    scanner = CodeScanningScanner()
    job = {"jobId": "p4", "envVars": {"GIT_REPOS": ""},}
    result = scanner.run_scan(job, job_dir=tmp_path / "p4", on_progress=bad)
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# CodeScanningConfig
# ---------------------------------------------------------------------------

def _code_job(env: dict) -> dict:
    return {"jobId": "job-test", "envVars": env}


def test_code_config_parses_defaults():
    from runner.scanners.code_scanning.scanner import CodeScanningConfig
    cfg = CodeScanningConfig.from_job(_code_job({"GIT_REPOS": "https://x/a.git"}))
    assert cfg.org_label == "default"
    assert cfg.concurrency == 4
    assert cfg.rulesets == ""
    # Unset by default → _build_config_args falls through to the registry packs.
    assert cfg.rules_path == ""
    assert cfg.git_token is None
    assert cfg.repos == ["https://x/a.git"]


def test_code_config_parses_explicit_values():
    from runner.scanners.code_scanning.scanner import CodeScanningConfig
    cfg = CodeScanningConfig.from_job(_code_job({
        "GIT_REPOS": "https://x/a.git",
        "GIT_TOKEN": "ghp_tok",
        "ORG_LABEL": "acme-org",
        "RUN_ID": "run-3",
        "CONCURRENCY": "3",
        "RULESETS": "p/python,p/javascript",
        "SEMGREP_RULES_PATH": "/custom/rules",
    }))
    assert cfg.repos == ["https://x/a.git"]
    assert cfg.git_token == "ghp_tok"
    assert cfg.org_label == "acme-org"
    assert cfg.run_id == "run-3"
    assert cfg.concurrency == 3
    assert cfg.rulesets == "p/python,p/javascript"
    assert cfg.rules_path == "/custom/rules"


def test_code_config_run_id_falls_back_to_job_id():
    from runner.scanners.code_scanning.scanner import CodeScanningConfig
    cfg = CodeScanningConfig.from_job({"jobId": "job-55", "envVars": {"GIT_REPOS": "https://x/a.git"}})
    assert cfg.run_id == "job-55"


def test_code_config_concurrency_bad_value_uses_default():
    from runner.scanners.code_scanning.scanner import CodeScanningConfig
    cfg = CodeScanningConfig.from_job(_code_job({
        "GIT_REPOS": "https://x/a.git",
        "CONCURRENCY": "bad",
    }))
    assert cfg.concurrency == 4
