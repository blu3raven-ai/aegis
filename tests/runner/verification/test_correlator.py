"""Tests for runner.verification.pipelines.multiscanner.correlate_findings."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.verification.llm_client import LlmToolResponse
from runner.verification.pipelines.multiscanner import correlate_findings
from runner.verification.schemas.correlation import (
    ChainSeverity,
    CorrelationVerdict,
)


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self._model = "stub"
        self.call_count = 0

    def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1000):
        self.call_count += 1
        return self._r.pop(0)


def _final(content: str) -> LlmToolResponse:
    return LlmToolResponse(
        content=content,
        tool_calls=[],
        tokens_in=120,
        tokens_out=80,
        prompt_hash="h-x",
    )


def _chain_json(
    verdict: str = "chain_confirmed",
    severity: str = "high",
    description: str = "credential leak then ssrf",
    src_ids: list[str] | None = None,
    evidence: list[dict] | None = None,
) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "chain_severity": severity,
            "chain_description": description,
            "source_finding_ids": src_ids or ["f1", "f2"],
            "evidence": evidence or [
                {"kind": "secret", "file": "cfg.env", "line": 2, "snippet": "AWS_KEY=AKIA..."},
                {"kind": "sink", "file": "src/api.py", "line": 47, "snippet": "requests.get(user_url)"},
            ],
        }
    )


def _findings_two_scanners(repo: str = "acme__widget") -> list[dict]:
    return [
        {
            "id": "f1",
            "repository": repo,
            "scanner": "secrets",
            "severity": "high",
            "rule": "aws-secret-key",
            "file": "cfg.env",
            "line": 2,
            "summary": "Hardcoded AWS access key",
        },
        {
            "id": "f2",
            "repository": repo,
            "scanner": "code-scanning",
            "severity": "high",
            "rule": "ssrf-request",
            "file": "src/api.py",
            "line": 47,
            "summary": "SSRF in HTTP handler",
        },
    ]


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


def test_skips_single_scanner_groups(tmp_path):
    findings = [
        {"id": "a", "repository": "x", "scanner": "code-scanning", "severity": "high",
         "rule": "r1", "file": "a.py", "line": 1, "summary": ""},
        {"id": "b", "repository": "x", "scanner": "code-scanning", "severity": "high",
         "rule": "r2", "file": "b.py", "line": 1, "summary": ""},
    ]
    (tmp_path / "anything").mkdir()
    llm = _StubLlm([_final(_chain_json())])
    results = correlate_findings(findings, repo_root_for=tmp_path, llm=llm)
    assert results == []
    assert llm.call_count == 0  # never invoked


def test_skips_too_small_groups(tmp_path):
    findings = [
        {"id": "a", "repository": "x", "scanner": "secrets", "severity": "high",
         "rule": "r1", "file": "a.py", "line": 1, "summary": ""},
    ]
    llm = _StubLlm([_final(_chain_json())])
    results = correlate_findings(findings, repo_root_for=tmp_path, llm=llm)
    assert results == []
    assert llm.call_count == 0


def test_skips_findings_without_repository(tmp_path):
    findings = [
        {"id": "a", "scanner": "secrets", "severity": "high"},
        {"id": "b", "scanner": "code-scanning", "severity": "high"},
    ]
    llm = _StubLlm([_final(_chain_json())])
    results = correlate_findings(findings, repo_root_for=tmp_path, llm=llm)
    assert results == []
    assert llm.call_count == 0


def test_groups_per_repo(tmp_path):
    findings = [
        *_findings_two_scanners("acme__a"),
        *[{**f, "id": f["id"] + "b", "repository": "acme__b"} for f in _findings_two_scanners("acme__a")],
    ]
    (tmp_path / "acme__a").mkdir()
    (tmp_path / "acme__b").mkdir()
    llm = _StubLlm([
        _final(_chain_json(src_ids=["f1", "f2"])),
        _final(_chain_json(src_ids=["f1b", "f2b"])),
    ])
    results = correlate_findings(
        findings,
        repo_root_for={"acme__a": tmp_path / "acme__a", "acme__b": tmp_path / "acme__b"},
        llm=llm,
    )
    assert len(results) == 2
    assert llm.call_count == 2


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def test_chain_confirmed_yields_correlated_finding(tmp_path):
    findings = _findings_two_scanners()
    (tmp_path / "acme__widget").mkdir()
    llm = _StubLlm([_final(_chain_json(verdict="chain_confirmed"))])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path / "acme__widget",
        llm=llm,
    )
    assert len(results) == 1
    r = results[0]
    assert r.verdict == CorrelationVerdict.CHAIN_CONFIRMED.value
    assert r.chain_severity == ChainSeverity.HIGH.value
    assert r.source_finding_ids == ["f1", "f2"]
    assert r.correlation_id.startswith("corr-")
    assert len(r.evidence) == 2


def test_no_chain_verdict_returns_no_finding(tmp_path):
    findings = _findings_two_scanners()
    llm = _StubLlm([_final(_chain_json(verdict="no_chain"))])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path,
        llm=llm,
    )
    assert results == []


def test_garbage_output_returns_no_finding(tmp_path):
    findings = _findings_two_scanners()
    llm = _StubLlm([_final("not json, not even close")])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path,
        llm=llm,
    )
    assert results == []


def test_json_wrapped_in_prose_still_parsed(tmp_path):
    findings = _findings_two_scanners()
    (tmp_path / "acme__widget").mkdir()
    wrapped = "Here is my analysis:\n" + _chain_json() + "\nLet me know if you want more."
    llm = _StubLlm([_final(wrapped)])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path / "acme__widget",
        llm=llm,
    )
    assert len(results) == 1
    assert results[0].verdict == CorrelationVerdict.CHAIN_CONFIRMED.value


def test_invalid_severity_defaults_to_medium(tmp_path):
    findings = _findings_two_scanners()
    (tmp_path / "acme__widget").mkdir()
    llm = _StubLlm([_final(_chain_json(severity="apocalyptic"))])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path / "acme__widget",
        llm=llm,
    )
    assert len(results) == 1
    assert results[0].chain_severity == ChainSeverity.MEDIUM.value


def test_malformed_evidence_items_dropped(tmp_path):
    findings = _findings_two_scanners()
    (tmp_path / "acme__widget").mkdir()
    bad_evidence = [
        {"kind": "advisory", "snippet": "no source"},  # invalid
        {"kind": "secret", "file": "x", "line": 1, "snippet": "ok"},
    ]
    llm = _StubLlm([_final(_chain_json(evidence=bad_evidence))])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path / "acme__widget",
        llm=llm,
    )
    assert len(results) == 1
    assert len(results[0].evidence) == 1


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_records_token_usage_from_agent(tmp_path):
    findings = _findings_two_scanners()
    (tmp_path / "acme__widget").mkdir()
    llm = _StubLlm([_final(_chain_json())])
    results = correlate_findings(
        findings,
        repo_root_for=tmp_path / "acme__widget",
        llm=llm,
    )
    assert results[0].tokens_in == 120
    assert results[0].tokens_out == 80
    assert results[0].metadata["stopped_reason"] == "completed"


def test_correlation_id_stable_for_same_source_set(tmp_path):
    findings = _findings_two_scanners()
    (tmp_path / "acme__widget").mkdir()
    llm1 = _StubLlm([_final(_chain_json(src_ids=["f1", "f2"]))])
    llm2 = _StubLlm([_final(_chain_json(src_ids=["f2", "f1"]))])  # reversed order

    r1 = correlate_findings(findings, repo_root_for=tmp_path / "acme__widget", llm=llm1)
    r2 = correlate_findings(findings, repo_root_for=tmp_path / "acme__widget", llm=llm2)
    assert r1[0].correlation_id == r2[0].correlation_id


def test_missing_repo_root_skipped_silently(tmp_path):
    findings = _findings_two_scanners()
    llm = _StubLlm([])  # never invoked
    results = correlate_findings(
        findings,
        repo_root_for={"acme__widget": tmp_path / "does-not-exist"},
        llm=llm,
    )
    assert results == []
    assert llm.call_count == 0
