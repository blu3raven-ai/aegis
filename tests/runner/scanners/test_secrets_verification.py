"""Secrets scanner: LLM verification helper."""
from __future__ import annotations

import json

from runner.scanners.secrets.scanner import SecretsScanner, _maybe_verify_secrets
from runner.verification.budget import ScanBudget


def test_no_llm_marks_skipped_with_no_verdict():
    findings = [{"file": "a.py", "line": 1, "verified": False, "match": "x"}]
    out = _maybe_verify_secrets(
        findings=findings, repo_root="/x", llm=None,
        scan_budget=ScanBudget(scan_budget=100, daily_remaining=10_000),
    )
    assert out[0]["verdict"] is None
    assert out[0]["verification_metadata"]["skipped"] == "llm_disabled"


def test_verified_secrets_auto_confirmed_without_llm_calls(monkeypatch):
    findings = [{"file": "a.py", "line": 1, "verified": True, "match": "AKIA..."}]
    calls = []
    def _stub_verify(*, finding, repo_root, llm, critic=None):
        calls.append(finding)
        return type("R", (), {
            "verdict": "confirmed", "exploit_chain": "", "evidence": [],
            "tokens_in": 0, "tokens_out": 0,
            "verification_metadata": {"auto_confirmed": "provider_verified"},
        })()
    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.verify_secret_finding",
        _stub_verify,
    )
    out = _maybe_verify_secrets(
        findings=findings, repo_root="/x", llm=object(),
        scan_budget=ScanBudget(scan_budget=100, daily_remaining=10_000),
    )
    assert out[0]["verdict"] == "confirmed"
    assert len(calls) == 1


def test_budget_exhausted_marks_remaining_possible(monkeypatch):
    findings = [
        {"file": "a.py", "line": 1, "verified": False, "match": "x"},
        {"file": "b.py", "line": 1, "verified": False, "match": "y"},
    ]
    def _stub_verify(*, finding, repo_root, llm, critic=None):
        return type("R", (), {
            "verdict": "confirmed", "exploit_chain": "", "evidence": [],
            "tokens_in": 60, "tokens_out": 60,
            "verification_metadata": {},
        })()
    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.verify_secret_finding",
        _stub_verify,
    )
    out = _maybe_verify_secrets(
        findings=findings, repo_root="/x", llm=object(),
        scan_budget=ScanBudget(scan_budget=100, daily_remaining=10_000),
    )
    assert out[0]["verdict"] == "confirmed"
    assert out[1]["verdict"] == "possible"
    assert out[1]["verification_metadata"]["skipped"] == "scan_budget"


def test_verify_findings_file_rewrites_with_verdict(tmp_path, monkeypatch):
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(json.dumps({
        "file": "config.py", "line": 4,
        "rule": "trufflehog.aws", "severity": "high",
        "match": 'AKIA...', "verified": False,
    }) + "\n")

    def _fake_verify(*, finding, repo_root, llm, critic=None):
        return type("R", (), {
            "verdict": "ruled_out",
            "exploit_chain": "",
            "evidence": [{"reasoning": "value is in a test fixture"}],
            "tokens_in": 110, "tokens_out": 110,
            "verification_metadata": {"tokens_used": 220},
        })()

    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.verify_secret_finding",
        _fake_verify,
    )

    SecretsScanner()._verify_findings_file(findings_file, repo_root=str(tmp_path))

    rewritten = [json.loads(l) for l in findings_file.read_text().splitlines() if l.strip()]
    assert rewritten[0]["verdict"] == "ruled_out"
    assert rewritten[0]["evidence_json"][0]["reasoning"] == "value is in a test fixture"
    assert rewritten[0]["verification_metadata"]["tokens_used"] == 220


def test_verify_findings_file_no_llm_key_marks_skipped(tmp_path, monkeypatch):
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(json.dumps({
        "file": "x.py", "line": 1, "rule": "x", "severity": "high", "verified": False,
    }) + "\n")

    monkeypatch.delenv("LLM_API_KEY", raising=False)

    SecretsScanner()._verify_findings_file(findings_file, repo_root=str(tmp_path))

    rewritten = [json.loads(l) for l in findings_file.read_text().splitlines() if l.strip()]
    assert rewritten[0]["verdict"] is None
    assert rewritten[0]["verification_metadata"]["skipped"] == "llm_disabled"


def test_scan_depth_ai_constant_removed():
    """ai_enhanced is no longer a supported scan depth on the runner."""
    from runner.scanners.secrets import scanner as mod
    assert not hasattr(mod, "SCAN_DEPTH_AI")
    assert "ai_enhanced" not in mod.SUPPORTED_SCAN_DEPTHS


def test_scanner_module_does_not_import_classify():
    from runner.scanners.secrets import scanner as mod
    assert not hasattr(mod, "classify")
