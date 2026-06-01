"""Tests for the embedded secrets scanner module."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Task 4.1 — classify.py (ML classifier, lazy imports)
# ---------------------------------------------------------------------------


def test_classify_default_model_path_is_embedded_runner_location(monkeypatch):
    """Default path must point to the bundle baked into the runner image
    (``/opt/aegis/secrets-model``). The path can be overridden via the
    ``SECRETS_MODEL_PATH`` env var; the env reload here proves the override
    path is the only customisation hook so production stays predictable."""
    import importlib

    from runner.scanners.secrets import classify as classify_mod

    try:
        monkeypatch.delenv("SECRETS_MODEL_PATH", raising=False)
        reloaded = importlib.reload(classify_mod)
        assert reloaded.DEFAULT_MODEL_PATH == "/opt/aegis/secrets-model"

        monkeypatch.setenv("SECRETS_MODEL_PATH", "/tmp/override-model")
        reloaded = importlib.reload(classify_mod)
        assert reloaded.DEFAULT_MODEL_PATH == "/tmp/override-model"
    finally:
        monkeypatch.delenv("SECRETS_MODEL_PATH", raising=False)
        importlib.reload(classify_mod)


def test_classify_module_does_not_import_heavy_libs_on_import():
    """Importing the classify module must NOT load onnxruntime/transformers/numpy.

    These libs together weigh hundreds of MB; the runner agent loads the
    scanner registry on every job, so eager import would balloon cold start.
    """
    code = (
        "import sys\n"
        "for mod in list(sys.modules):\n"
        "    if mod.startswith(('onnxruntime', 'transformers', 'numpy')):\n"
        "        del sys.modules[mod]\n"
        "import runner.scanners.secrets.classify  # noqa\n"
        "assert 'onnxruntime' not in sys.modules, 'onnxruntime leaked at import'\n"
        "assert 'transformers' not in sys.modules, 'transformers leaked at import'\n"
        "assert 'numpy' not in sys.modules, 'numpy leaked at import'\n"
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


def test_classify_findings_passes_through_when_model_unavailable(tmp_path):
    """When the model dir doesn't exist, classify_findings copies input -> output."""
    from runner.scanners.secrets.classify import classify_findings

    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            [
                {"Secret": "abc", "RuleID": "aws", "File": "a.py", "Line": 1},
                {"Secret": "def", "RuleID": "github", "File": "b.py", "Line": 5},
            ]
        )
    )
    out = tmp_path / "out.json"
    count = classify_findings(raw, out, model_path=str(tmp_path / "no-model"))
    assert count == 0
    payload = json.loads(out.read_text())
    assert payload == json.loads(raw.read_text())


def test_classify_findings_empty_input_writes_empty_array(tmp_path):
    """Empty input -> empty array out, no model load attempted."""
    from runner.scanners.secrets.classify import classify_findings

    raw = tmp_path / "raw.json"
    raw.write_text("[]")
    out = tmp_path / "out.json"
    count = classify_findings(raw, out, model_path=str(tmp_path / "no-model"))
    assert count == 0
    assert json.loads(out.read_text()) == []


def test_classify_findings_with_mock_model_annotates(tmp_path):
    """Pass an in-process callable as the model; verify annotation shape."""
    from runner.scanners.secrets.classify import classify_findings

    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            [
                {"Secret": "x", "RuleID": "r1", "File": "a", "Line": 1},
                {"Secret": "y", "RuleID": "r2", "File": "b", "Line": 2},
            ]
        )
    )
    out = tmp_path / "out.json"

    def fake_model(findings):
        return [
            {"label": "label_1", "score": 0.97, "reasoning": "looks real"}
            for _ in findings
        ]

    count = classify_findings(raw, out, model=fake_model)
    assert count == 2
    annotated = json.loads(out.read_text())
    assert annotated[0]["ai_classification"] == "likely_real"
    assert annotated[0]["ai_confidence"] == 0.97
    assert annotated[0]["ai_reasoning"] == "looks real"


def test_classify_batch_pass_through_when_model_unavailable(tmp_path):
    """Batch mode: pass-through writes betterleaks.json with original findings."""
    from runner.scanners.secrets.classify import classify_batch

    repo = tmp_path / "repo-a"
    repo.mkdir()
    raw = repo / "betterleaks_raw.json"
    raw.write_text(
        json.dumps([{"Secret": "s", "RuleID": "r", "File": "f", "Line": 1}])
    )
    count = classify_batch(tmp_path, model_path=str(tmp_path / "no-model"))
    assert count == 0
    assert not raw.exists()
    out = repo / "betterleaks.json"
    assert out.exists()
    assert len(json.loads(out.read_text())) == 1


def test_classify_batch_dedup_via_mock_model(tmp_path):
    """Mock model receives a single inference batch across repos and applies
    annotations correctly back to each file."""
    from runner.scanners.secrets.classify import classify_batch

    for name in ("r1", "r2"):
        repo = tmp_path / name
        repo.mkdir()
        (repo / "betterleaks_raw.json").write_text(
            json.dumps([{"Secret": name, "RuleID": "rule", "File": "f"}])
        )

    def fake_model(findings):
        return [
            {"label": "label_0", "score": 0.2, "reasoning": ""} for _ in findings
        ]

    count = classify_batch(tmp_path, model=fake_model)
    assert count == 2
    for name in ("r1", "r2"):
        out = json.loads((tmp_path / name / "betterleaks.json").read_text())
        assert out[0]["ai_classification"] == "likely_false_positive"


# ---------------------------------------------------------------------------
# Task 4.2 — enrich_context.py
# ---------------------------------------------------------------------------


def _init_git_repo(repo_dir: Path) -> str:
    """Create a tiny git repo with one commit; return the HEAD SHA."""
    subprocess.run(
        ["git", "init", "-q"], cwd=repo_dir, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "t@t"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "t"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "add", "-A"], cwd=repo_dir, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "init"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    rev = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    return rev.stdout.strip()


def test_enrich_adds_context_from_working_tree(tmp_path):
    """No commit recorded -> fall back to the working tree."""
    from runner.scanners.secrets.enrich_context import enrich

    (tmp_path / "secrets.py").write_text(
        "line1\nline2\nAWS_KEY = 'AKIA...'\nline4\nline5\n"
    )
    findings = [{"File": "secrets.py", "Line": 3}]
    enrich(findings, tmp_path, context_lines=1)
    assert findings[0]["ContextBefore"] == ["line2"]
    assert findings[0]["ContextAfter"] == ["line4"]


def test_enrich_reads_at_commit_when_provided(tmp_path):
    """When ``Commit`` is set, ``git show`` is used to read the file."""
    from runner.scanners.secrets.enrich_context import enrich

    (tmp_path / "secrets.py").write_text(
        "aaa\nbbb\nccc\nDDD = 'x'\neee\nfff\nggg\n"
    )
    sha = _init_git_repo(tmp_path)
    findings = [{"file": "secrets.py", "line": 4, "Commit": sha}]
    enrich(findings, tmp_path, context_lines=2)
    assert findings[0]["ContextBefore"] == ["bbb", "ccc"]
    assert findings[0]["ContextAfter"] == ["eee", "fff"]


def test_enrich_rejects_path_traversal(tmp_path):
    """Findings with ``..`` in path are skipped silently."""
    from runner.scanners.secrets.enrich_context import _validate_file_path, enrich

    assert not _validate_file_path("../etc/passwd")
    assert not _validate_file_path("/etc/passwd")
    (tmp_path / "secrets.py").write_text("a\nb\n")
    findings = [{"File": "../secrets.py", "Line": 1}]
    enrich(findings, tmp_path)
    assert "ContextBefore" not in findings[0]
    assert "ContextAfter" not in findings[0]


def test_enrich_rejects_invalid_commit_ref():
    from runner.scanners.secrets.enrich_context import _validate_git_ref

    assert _validate_git_ref("abcdef1234")
    assert _validate_git_ref("a" * 40)
    assert not _validate_git_ref("abc")  # too short
    assert not _validate_git_ref("abc; rm -rf /")
    assert not _validate_git_ref("HEAD")


def test_enrich_file_writes_back_in_place(tmp_path):
    """``enrich_file`` rewrites the JSON file with context fields."""
    from runner.scanners.secrets.enrich_context import enrich_file

    (tmp_path / "a.py").write_text("x\ny\nSECRET = 'z'\n")
    findings_path = tmp_path / "raw.json"
    findings_path.write_text(json.dumps([{"File": "a.py", "Line": 3}]))
    n = enrich_file(findings_path, tmp_path, context_lines=1)
    assert n == 1
    data = json.loads(findings_path.read_text())
    assert data[0]["ContextBefore"] == ["y"]


def test_enrich_file_empty_no_op(tmp_path):
    from runner.scanners.secrets.enrich_context import enrich_file

    findings_path = tmp_path / "raw.json"
    findings_path.write_text("[]")
    assert enrich_file(findings_path, tmp_path) == 0
    assert findings_path.read_text() == "[]"


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


def test_normalize_file_betterleaks_array(tmp_path):
    from runner.scanners.secrets.normalize import normalize_file

    raw = tmp_path / "betterleaks.json"
    raw.write_text(
        json.dumps([{"RuleID": "aws"}, {"RuleID": "github"}])
    )
    findings = normalize_file(raw, "betterleaks", "repo-1")
    assert len(findings) == 2
    for f in findings:
        assert f["source"] == "betterleaks"
        assert f["repository"] == "repo-1"


def test_normalize_secrets_output_aggregates_both_sources(tmp_path):
    from runner.scanners.secrets.normalize import normalize_secrets_output

    repo_a = tmp_path / "repo-a"
    repo_a.mkdir()
    (repo_a / "trufflehog.json").write_text('{"DetectorName":"aws"}\n')
    (repo_a / "betterleaks.json").write_text(
        json.dumps([{"RuleID": "aws-key"}])
    )

    repo_b = tmp_path / "repo-b"
    repo_b.mkdir()
    (repo_b / "trufflehog.json").write_text('{"DetectorName":"github"}\n')

    total, errors = normalize_secrets_output("acme", tmp_path, "run-1")
    assert total == 3
    assert errors == 0

    lines = [
        json.loads(line)
        for line in (tmp_path / "findings.jsonl").read_text().splitlines()
    ]
    by_source = {(f["source"], f["repository"]) for f in lines}
    assert ("trufflehog", "repo-a") in by_source
    assert ("trufflehog", "repo-b") in by_source
    assert ("betterleaks", "repo-a") in by_source


def test_normalize_secrets_output_fallback_to_raw_when_no_classified(tmp_path):
    """When a repo only has betterleaks_raw.json, normalize falls back to it."""
    from runner.scanners.secrets.normalize import normalize_secrets_output

    repo = tmp_path / "repo-x"
    repo.mkdir()
    (repo / "betterleaks_raw.json").write_text(
        json.dumps([{"RuleID": "stripe"}])
    )

    total, errors = normalize_secrets_output("acme", tmp_path, "run-1")
    assert total == 1
    assert errors == 0
    lines = [
        json.loads(line)
        for line in (tmp_path / "findings.jsonl").read_text().splitlines()
    ]
    assert lines[0]["source"] == "betterleaks"
    assert lines[0]["repository"] == "repo-x"


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
    line = (tmp_path / "findings.jsonl").read_text().strip()
    assert ", " not in line and ": " not in line


# ---------------------------------------------------------------------------
# Task 4.4 — SecretsScanner orchestrator
# ---------------------------------------------------------------------------


def test_secrets_scanner_has_correct_type():
    from runner.scanners.secrets.scanner import SecretsScanner

    assert SecretsScanner.SCANNER_TYPE == "secrets"


def test_secrets_scanner_implements_base_protocol():
    from runner.scanners.base import BaseScanner
    from runner.scanners.secrets.scanner import SecretsScanner

    assert isinstance(SecretsScanner(), BaseScanner)


def test_run_scan_empty_repos_returns_clean(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    job = {"jobId": "test-s", "dockerArgs": {"envVars": {"GIT_REPOS": ""}}}
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
        "dockerArgs": {
            "envVars": {"GIT_REPOS": "https://github.com/example/a.git"}
        },
    }
    job_dir = tmp_path / "test-cancel"
    result = scanner.run_scan(job, job_dir=job_dir, cancel_event=cancel)
    assert result.exit_code == CANCELLED_EXIT_CODE


def test_run_scan_rejects_unsupported_scan_depth(tmp_path):
    from runner.scanners.secrets.scanner import SecretsScanner

    scanner = SecretsScanner()
    job = {
        "jobId": "test-depth",
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SCAN_DEPTH": "extreme",
            }
        },
    }
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
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SCAN_DEPTH": "deep",
                "SCAN_START_DATE": "2025/01/01",
            }
        },
    }
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
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git,https://github.com/c/d.git",
                "CONCURRENCY": "7",
            }
        },
    }
    scanner.run_scan(job, job_dir=tmp_path / "test-conc")
    assert captured["max_workers"] == 7


def test_run_scan_aggregates_findings(tmp_path, monkeypatch):
    """Per-repo trufflehog.json / betterleaks.json -> aggregated findings.jsonl."""
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
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git\nhttps://github.com/c/d.git",
                "ORG_LABEL": "acme",
            }
        },
    }
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
        "dockerArgs": {
            "envVars": {"GIT_REPOS": "https://github.com/a/b.git"}
        },
    }
    job_dir = tmp_path / "test-fail"
    result = scanner.run_scan(job, job_dir=job_dir)
    assert result.exit_code == 0
    assert any("simulated failure" in line for line in result.log_tail)


def test_run_scan_ai_enhanced_invokes_classify_batch(tmp_path, monkeypatch):
    """ai_enhanced depth must call classify_batch after the pool drains."""
    from runner.scanners.secrets import scanner as scanner_mod
    from runner.scanners.secrets.scanner import SecretsScanner

    monkeypatch.setattr(SecretsScanner, "_scan_repo", lambda *a, **kw: None)
    called: list[Path] = []

    def fake_classify_batch(target_dir, *args, **kwargs):
        called.append(Path(target_dir))
        return 0

    monkeypatch.setattr(scanner_mod.classify, "classify_batch", fake_classify_batch)

    scanner = SecretsScanner()
    job = {
        "jobId": "test-ai",
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SCAN_DEPTH": "ai_enhanced",
            }
        },
    }
    job_dir = tmp_path / "test-ai"
    scanner.run_scan(job, job_dir=job_dir)
    assert called == [job_dir]


def test_run_scan_light_does_not_invoke_classify(tmp_path, monkeypatch):
    from runner.scanners.secrets import scanner as scanner_mod
    from runner.scanners.secrets.scanner import SecretsScanner

    monkeypatch.setattr(SecretsScanner, "_scan_repo", lambda *a, **kw: None)
    called: list[Path] = []
    monkeypatch.setattr(
        scanner_mod.classify,
        "classify_batch",
        lambda d, *a, **kw: called.append(d),
    )

    scanner = SecretsScanner()
    job = {
        "jobId": "test-light",
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://github.com/a/b.git",
                "SCAN_DEPTH": "light",
            }
        },
    }
    scanner.run_scan(job, job_dir=tmp_path / "test-light")
    assert called == []


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
    job = {"jobId": "p1", "dockerArgs": {"envVars": {"GIT_REPOS": ""}}}
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
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://x/a.git,https://x/b.git",
                "CONCURRENCY": "1",
            }
        },
    }
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
        "dockerArgs": {
            "envVars": {
                "GIT_REPOS": "https://x/a.git",
                "SCAN_DEPTH": "bogus",
            }
        },
    }
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
        "dockerArgs": {"envVars": {"GIT_REPOS": "https://x/a.git"}},
    }
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
    job = {"jobId": "p5", "dockerArgs": {"envVars": {"GIT_REPOS": ""}}}
    result = scanner.run_scan(job, job_dir=tmp_path / "p5", on_progress=bad)
    assert result.exit_code == 0
