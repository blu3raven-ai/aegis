"""Unit tests for runner.scanners.code_scanning.joern_adapter."""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from runner.scanners.code_scanning import joern_adapter


@pytest.fixture
def tmp_repo(tmp_path):
    """A throwaway repo dir with one Python file so language detection works."""
    (tmp_path / "app.py").write_text("def main(): pass\n")
    return tmp_path


def test_run_returns_empty_when_cpg_build_fails(tmp_repo, tmp_path):
    with patch.object(joern_adapter, "_run_subprocess") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
        result = joern_adapter.run(repo_path=tmp_repo, workdir=tmp_path / "work")

    assert result.findings == []
    assert result.status.startswith("failed:")


def test_run_returns_empty_when_query_times_out(tmp_repo, tmp_path):
    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="joern-parse", timeout=600)

    with patch.object(joern_adapter, "_run_subprocess", side_effect=_raise_timeout):
        result = joern_adapter.run(repo_path=tmp_repo, workdir=tmp_path / "work")

    assert result.findings == []
    assert "timeout" in result.status.lower()


def test_run_skips_unsupported_languages(tmp_path):
    # Only Go files — Joern v1 enables JS/TS/Python/Java; Go is Opengrep-only.
    (tmp_path / "main.go").write_text("package main\nfunc main(){}\n")
    with patch.object(joern_adapter, "_run_subprocess") as mock_run:
        result = joern_adapter.run(repo_path=tmp_path, workdir=tmp_path / "work")

    assert result.findings == []
    assert result.status == "skipped: no supported language"
    mock_run.assert_not_called()  # Never even tried to build a CPG.


def test_run_normalizes_query_output_to_finding_schema(monkeypatch, tmp_repo, tmp_path):
    # Stage a dummy query script so the adapter has something to iterate.
    # Task 3 will populate the real joern_queries/ directory; we mock execution here.
    queries_dir = tmp_path / "queries"
    queries_dir.mkdir()
    (queries_dir / "sqli.sc").write_text("// stub")
    monkeypatch.setattr(joern_adapter, "_QUERIES_DIR", queries_dir)

    fake_joern_output = [
        {
            "cwe": "CWE-89",
            "file": "app.py",
            "line": 10,
            "rule_id": "joern-sqli",
            "severity": "high",
            "title": "SQL Injection",
            "dataflow_trace": [
                {"file": "app.py", "line": 5, "snippet": "id = req.args['id']", "role": "source"},
                {"file": "app.py", "line": 10, "snippet": "db.execute(f'... {id}')", "role": "sink"},
            ],
        }
    ]

    with patch.object(joern_adapter, "_run_subprocess") as mock_run, \
         patch.object(joern_adapter, "_read_query_output", return_value=fake_joern_output):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        result = joern_adapter.run(repo_path=tmp_repo, workdir=tmp_path / "work")

    assert result.status == "ok"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["engine"] == "joern"
    assert f["cwe"] == "CWE-89"
    assert f["file"] == "app.py"
    assert f["line"] == 10
    assert f["dataflow_trace"][0]["role"] == "source"


def test_run_respects_resource_cap_env_vars(monkeypatch, tmp_repo, tmp_path):
    monkeypatch.setenv("JOERN_MAX_MEMORY_MB", "512")
    monkeypatch.setenv("JOERN_TIMEOUT_SECONDS", "120")

    # Stage a query so the loop runs and we can observe the query call too.
    queries_dir = tmp_path / "queries"
    queries_dir.mkdir()
    (queries_dir / "sqli.sc").write_text("// stub")
    monkeypatch.setattr(joern_adapter, "_QUERIES_DIR", queries_dir)

    def _capture(cmd, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch.object(joern_adapter, "_run_subprocess", side_effect=_capture) as mock_run, \
         patch.object(joern_adapter, "_read_query_output", return_value=[]):
        joern_adapter.run(repo_path=tmp_repo, workdir=tmp_path / "work")

    # Both parse and query commands should carry the memory cap.
    assert len(mock_run.call_args_list) >= 2
    parse_call = mock_run.call_args_list[0]
    query_call = mock_run.call_args_list[1]

    parse_cmd = parse_call.args[0]
    query_cmd = query_call.args[0]
    assert any("-Xmx512m" in arg for arg in parse_cmd)
    assert any("-Xmx512m" in arg for arg in query_cmd)

    # Timeout should reflect the wall-clock budget. monotonic() advances
    # nanoseconds between deadline computation and the subprocess call, so
    # the parse timeout should be very close to the 120s budget.
    parse_timeout = parse_call.kwargs.get("timeout")
    assert parse_timeout is not None
    assert parse_timeout > 100
    assert parse_timeout <= 120

    # Query timeout should also be close to the budget (parse was mocked, so
    # virtually no time has elapsed).
    query_timeout = query_call.kwargs.get("timeout")
    assert query_timeout is not None
    assert query_timeout > 100
    assert query_timeout <= 120


def test_run_continues_when_query_output_is_malformed(monkeypatch, tmp_repo, tmp_path):
    # Two queries: first emits malformed JSONL, second emits a valid finding.
    # The adapter must skip the broken one and still return the good finding,
    # and mark the run as ok-with-failures.
    queries_dir = tmp_path / "queries"
    queries_dir.mkdir()
    (queries_dir / "a_broken.sc").write_text("// stub")
    (queries_dir / "b_good.sc").write_text("// stub")
    monkeypatch.setattr(joern_adapter, "_QUERIES_DIR", queries_dir)

    workdir = tmp_path / "work"

    def _fake_subprocess(cmd, **kwargs):
        # Simulate joern writing the per-query JSONL output file.
        if "--script" in cmd:
            script_idx = cmd.index("--script")
            script_path = cmd[script_idx + 1]
            stem = script_path.rsplit("/", 1)[-1].removesuffix(".sc")
            out_path = workdir / f"{stem}.jsonl"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if stem == "a_broken":
                out_path.write_text("{not valid json}\n")
            else:
                out_path.write_text(
                    '{"cwe":"CWE-89","file":"app.py","line":10,'
                    '"rule_id":"joern-sqli","severity":"high","title":"SQLi",'
                    '"dataflow_trace":[]}\n'
                )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch.object(joern_adapter, "_run_subprocess", side_effect=_fake_subprocess):
        result = joern_adapter.run(repo_path=tmp_repo, workdir=workdir)

    # The good query's finding should still be present.
    assert len(result.findings) == 1
    assert result.findings[0]["cwe"] == "CWE-89"
    # Status should reflect the one query failure.
    assert result.status.startswith("ok:")
    assert "1/2" in result.status


def test_metrics_emitted_on_successful_scan(monkeypatch, tmp_repo, tmp_path):
    """Joern metrics fire on the success path."""
    findings_counter_calls: list[dict] = []
    scans_counter_calls: list[dict] = []

    class _RecChild:
        def __init__(self, parent, kw):
            self.parent = parent
            self.kw = kw

        def inc(self):
            self.parent.calls.append(self.kw)

    class _RecCounter:
        def __init__(self):
            self.calls: list[dict] = []

        def labels(self, **kw):
            return _RecChild(self, kw)

    fake_scans = _RecCounter()
    fake_scans.calls = scans_counter_calls
    fake_findings = _RecCounter()
    fake_findings.calls = findings_counter_calls

    fake_hist = type("_H", (), {"observe": lambda self, _v: None})()

    monkeypatch.setattr(joern_adapter, "joern_scans_total", fake_scans)
    monkeypatch.setattr(joern_adapter, "joern_findings_total", fake_findings)
    monkeypatch.setattr(joern_adapter, "joern_scan_duration_seconds", fake_hist)
    monkeypatch.setattr(joern_adapter, "joern_cpg_build_duration_seconds", fake_hist)

    queries_dir = tmp_path / "queries"
    queries_dir.mkdir()
    (queries_dir / "stub.sc").write_text("// stub")
    monkeypatch.setattr(joern_adapter, "_QUERIES_DIR", queries_dir)

    fake_finding = {
        "cwe": "CWE-89",
        "file": "app.py",
        "line": 5,
        "rule_id": "joern-sqli",
        "severity": "high",
        "title": "SQL Injection",
        "dataflow_trace": [],
    }

    with patch.object(
        joern_adapter,
        "_run_subprocess",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ), patch.object(joern_adapter, "_read_query_output", return_value=[fake_finding]):
        result = joern_adapter.run(repo_path=tmp_repo, workdir=tmp_path / "work")

    assert result.status == "ok"
    assert {"cwe": "CWE-89"} in findings_counter_calls
    assert {"outcome": "ok"} in scans_counter_calls
