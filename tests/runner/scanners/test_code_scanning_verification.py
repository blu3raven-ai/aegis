"""Code scanning scanner: verification integration."""
from __future__ import annotations

import json
from pathlib import Path

from runner.scanners._shared import JobEnv
from runner.scanners.code_scanning.scanner import CodeScanningScanner, _maybe_verify
from runner.verification.budget import ScanBudget


def _env(api_key: str | None = None) -> JobEnv:
    env_vars: dict[str, str] = {}
    if api_key:
        env_vars["LLM_API_KEY"] = api_key
    return JobEnv({"envVars": env_vars})


def test_no_llm_config_marks_skipped(monkeypatch):
    findings = [{"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"}]
    result = _maybe_verify(
        findings=findings, repo_root="/x", llm=None,
        scan_budget=ScanBudget(scan_budget=100, daily_remaining=10_000),
    )
    assert result[0]["verdict"] is None
    assert result[0]["verification_metadata"]["skipped"] == "llm_disabled"


def test_below_severity_skipped():
    findings = [{"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "info"}]
    result = _maybe_verify(
        findings=findings, repo_root="/x", llm=object(),
        scan_budget=ScanBudget(scan_budget=100, daily_remaining=10_000),
    )
    assert result[0]["verification_metadata"]["skipped"] == "below_severity"


def test_budget_exhausted_marks_remaining_possible(monkeypatch):
    findings = [
        {"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        {"file": "b.py", "line": 1, "tool": "sast", "rule": "y", "severity": "high"},
    ]

    def _fake_verify(*, finding, repo_root, llm, escalation_llm=None, critic=None, **kwargs):
        return type("R", (), {
            "verdict": "confirmed", "exploit_chain": "x", "evidence": [],
            "tokens_in": 60, "tokens_out": 60, "verification_metadata": {},
        })()

    monkeypatch.setattr(
        "runner.scanners.code_scanning.scanner.verify_finding",
        _fake_verify,
    )

    result = _maybe_verify(
        findings=findings, repo_root="/x", llm=object(),
        scan_budget=ScanBudget(scan_budget=100, daily_remaining=10_000),
    )
    assert result[0]["verdict"] == "confirmed"
    assert result[1]["verdict"] == "possible"
    assert result[1]["verification_metadata"]["skipped"] == "scan_budget"


def test_verify_findings_file_rewrites_with_verdict(tmp_path, monkeypatch):
    """Post-normalize, _verify_findings_file rewrites findings.jsonl with verdict/evidence."""
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(json.dumps({
        "file": "app.py",
        "line": 10,
        "rule": "python.lang.security.eval",
        "severity": "high",
        "snippet": "eval(user_input)",
        "engine": "semgrep",
    }) + "\n")

    def _fake_verify(*, finding, repo_root, llm, escalation_llm=None, critic=None, **kwargs):
        return type("R", (), {
            "verdict": "confirmed",
            "exploit_chain": "http_request -> eval",
            "evidence": [{"file": "app.py", "line": 10, "snippet": "eval(user_input)", "kind": "sink"}],
            "tokens_in": 200, "tokens_out": 212,
            "verification_metadata": {"tokens_used": 412},
        })()

    monkeypatch.setattr(
        "runner.scanners.code_scanning.scanner.verify_finding",
        _fake_verify,
    )

    CodeScanningScanner()._verify_findings_file(
        findings_file, repo_root=str(tmp_path), env=_env(api_key="sk-test"),
    )

    rewritten = [json.loads(l) for l in findings_file.read_text().splitlines() if l.strip()]
    assert len(rewritten) == 1
    assert rewritten[0]["verdict"] == "confirmed"
    assert rewritten[0]["evidence"][0]["snippet"] == "eval(user_input)"
    assert rewritten[0]["exploit_chain"] == "http_request -> eval"
    assert rewritten[0]["verification_metadata"]["tokens_used"] == 412


def test_verify_findings_file_no_llm_key_marks_skipped(tmp_path, monkeypatch):
    """With no LLM_API_KEY env var, every finding is marked skipped=llm_disabled."""
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(json.dumps({
        "file": "x.py", "line": 1, "rule": "x", "severity": "high", "engine": "semgrep",
    }) + "\n")

    monkeypatch.delenv("LLM_API_KEY", raising=False)

    CodeScanningScanner()._verify_findings_file(
        findings_file, repo_root=str(tmp_path), env=_env(),
    )

    rewritten = [json.loads(l) for l in findings_file.read_text().splitlines() if l.strip()]
    assert rewritten[0]["verdict"] is None
    assert rewritten[0]["verification_metadata"]["skipped"] == "llm_disabled"


def test_verify_findings_file_missing_file_is_noop(tmp_path):
    """No findings.jsonl -> _verify_findings_file silently returns."""
    CodeScanningScanner()._verify_findings_file(
        tmp_path / "nonexistent.jsonl", repo_root=str(tmp_path), env=_env(),
    )


# --- Frontier escalation client is dormant unless explicitly configured ----------

def test_build_escalation_llm_client_dormant_without_model():
    from runner.scanners._shared import build_escalation_llm_client
    env = JobEnv({"envVars": {"LLM_API_KEY": "k"}})  # no LLM_ESCALATION_MODEL
    assert build_escalation_llm_client(env) is None


def test_build_escalation_llm_client_none_without_key():
    from runner.scanners._shared import build_escalation_llm_client
    env = JobEnv({"envVars": {"LLM_ESCALATION_MODEL": "big-model"}})  # no key
    assert build_escalation_llm_client(env) is None


def test_build_escalation_llm_client_when_configured():
    from runner.scanners._shared import build_escalation_llm_client
    env = JobEnv({"envVars": {
        "LLM_API_KEY": "k",
        "LLM_API_BASE_URL": "https://default/v1",
        "LLM_ESCALATION_MODEL": "big-model",
    }})
    client = build_escalation_llm_client(env)
    assert client is not None
    assert client._model == "big-model"
    # Falls back to the default endpoint when no escalation-specific one is set.
    assert client._api_base_url == "https://default/v1"
