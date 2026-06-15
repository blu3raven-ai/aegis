"""Tests for the verification scanner (aggregate pipeline runner)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.scanners.verification.scanner import VerificationScanner


def _job(**overrides) -> dict:
    base = {
        "jobId": "verif-1",
        "type": "verification",
        "envVars": {},
    }
    base.update(overrides)
    return base


def _write_findings(path: Path, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(f) for f in findings) + "\n")


def _two_scanner_inputs(input_dir: Path, repo: str = "acme__widget"):
    _write_findings(
        input_dir / "secrets" / "findings.jsonl",
        [
            {
                "id": "s1",
                "repository": repo,
                "scanner": "secrets",
                "severity": "high",
                "detectorName": "aws-secret-key",
                "redactedMatch": "AKIAxx",
                "file": "cfg.env",
                "line": 2,
            }
        ],
    )
    _write_findings(
        input_dir / "code-scanning" / "findings.jsonl",
        [
            {
                "id": "c1",
                "repository": repo,
                "scanner": "code-scanning",
                "severity": "high",
                "rule": "ssrf",
                "file": "src/api.py",
                "line": 47,
            }
        ],
    )


def test_dispatcher_registers_verification_type():
    from runner.core.dispatcher import get_scanner, supported_types

    assert "verification" in supported_types()
    assert isinstance(get_scanner("verification"), VerificationScanner)


def test_empty_input_succeeds_without_output(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    scanner = VerificationScanner()
    result = scanner.run_scan(_job(), tmp_path)
    assert result.exit_code == 0
    assert any("0 input findings" in line for line in result.log_tail)
    assert not (tmp_path / "aggregate-verification.json").exists()
    # write_done_marker appends to _manifest.jsonl
    manifest = tmp_path / "_manifest.jsonl"
    assert manifest.exists()
    assert '"file":"_done"' in manifest.read_text() or '"file": "_done"' in manifest.read_text()


def test_no_llm_runs_orchestrator_and_dedupe_only(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    input_dir = tmp_path / "input"
    _two_scanner_inputs(input_dir)
    # Duplicate the secret in a second file so dedup has work to do
    _write_findings(
        input_dir / "secrets-extra" / "findings.jsonl",
        [
            {
                "id": "s2",
                "repository": "acme__widget",
                "scanner": "secrets",
                "severity": "high",
                "detectorName": "aws-secret-key",
                "redactedMatch": "AKIAxx",
                "file": "other.env",
                "line": 5,
            }
        ],
    )

    scanner = VerificationScanner()
    result = scanner.run_scan(_job(), tmp_path)
    assert result.exit_code == 0
    assert any("correlation step skipped" in line for line in result.log_tail)

    output_path = tmp_path / "aggregate-verification.json"
    assert output_path.exists()
    payload = json.loads(output_path.read_text())
    assert payload["summary"]["input_findings"] == 3
    # The two AWS-key secrets dedup into one primary
    assert payload["summary"]["merged_findings"] == 1
    assert payload["summary"]["duplicate_groups"] == 1
    # No correlation without LLM
    assert payload["summary"]["correlated_chains"] == 0


def test_finds_repo_clone_under_input_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    input_dir = tmp_path / "input"
    _two_scanner_inputs(input_dir)
    # Place a fake clone so the scanner picks it up
    (input_dir / "acme__widget" / "_checkout").mkdir(parents=True)
    (input_dir / "acme__widget" / "_checkout" / "x.py").write_text("ok\n")

    scanner = VerificationScanner()
    result = scanner.run_scan(_job(), tmp_path)
    assert any("mapped 1 repo clones" in line for line in result.log_tail)
    assert result.exit_code == 0


def test_runs_correlator_when_llm_configured(tmp_path, monkeypatch):
    """Stub the LLM client construction so we don't need a real key."""
    from runner.verification.llm_client import LlmResponse, LlmToolResponse

    class _StubLlm:
        _model = "stub"

        def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1000):
            return LlmToolResponse(
                content=json.dumps(
                    {
                        "verdict": "chain_confirmed",
                        "chain_severity": "high",
                        "chain_description": "leak then ssrf",
                        "source_finding_ids": ["s1", "c1"],
                        "evidence": [
                            {
                                "kind": "advisory",
                                "source": "CVE-X",
                                "snippet": "vuln",
                            }
                        ],
                    }
                ),
                tool_calls=[],
                tokens_in=100,
                tokens_out=50,
                prompt_hash="h",
            )

    monkeypatch.setenv("LLM_API_KEY", "stub-key")
    monkeypatch.setattr(
        "runner.scanners.verification.scanner._build_llm_client",
        lambda: _StubLlm(),
    )

    input_dir = tmp_path / "input"
    _two_scanner_inputs(input_dir)
    (input_dir / "acme__widget" / "_checkout").mkdir(parents=True)

    scanner = VerificationScanner()
    result = scanner.run_scan(_job(), tmp_path)
    assert result.exit_code == 0

    payload = json.loads((tmp_path / "aggregate-verification.json").read_text())
    assert payload["summary"]["correlated_chains"] == 1


def test_cancel_event_short_circuits(tmp_path):
    import threading

    input_dir = tmp_path / "input"
    _two_scanner_inputs(input_dir)

    cancel = threading.Event()
    cancel.set()

    scanner = VerificationScanner()
    result = scanner.run_scan(_job(), tmp_path, cancel_event=cancel)
    assert result.exit_code == 0
    # Output should NOT exist since we exited before doing the work
    assert not (tmp_path / "aggregate-verification.json").exists()


def test_uses_budget_env_override(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    input_dir = tmp_path / "input"
    _two_scanner_inputs(input_dir)

    scanner = VerificationScanner()
    result = scanner.run_scan(
        _job(envVars={"AGGREGATE_VERIFICATION_BUDGET": "50000"}),
        tmp_path,
    )
    assert result.exit_code == 0
    payload = json.loads((tmp_path / "aggregate-verification.json").read_text())
    assert payload["plan"]["budget"]["total"] == 50_000
