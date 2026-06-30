"""Tests for runner.verification.pipelines.aggregate.run_aggregate_verification."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.verification.llm_client import LlmToolResponse
from runner.verification.pipelines.aggregate import run_aggregate_verification


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
        tokens_in=100,
        tokens_out=50,
        prompt_hash="h",
    )


def _chain_json(src_ids: list[str]) -> str:
    return json.dumps({
        "verdict": "chain_confirmed",
        "chain_severity": "high",
        "chain_description": "chain",
        "source_finding_ids": src_ids,
        "evidence": [
            {"kind": "advisory", "source": "CVE-X", "snippet": "vuln"}
        ],
    })


def _two_scanner_findings(repo: str = "acme__widget") -> list[dict]:
    return [
        {
            "id": "f1",
            "repository": repo,
            "scanner": "secret_scanning",
            "severity": "high",
            "detectorName": "aws-secret-key",
            "redactedMatch": "AKIAxxx",
            "file": "cfg.env",
            "line": 2,
        },
        {
            "id": "f2",
            "repository": repo,
            "scanner": "code-scanning",
            "severity": "high",
            "rule": "ssrf",
            "file": "src/api.py",
            "line": 47,
        },
    ]


# ---------------------------------------------------------------------------
# Empty / minimal input
# ---------------------------------------------------------------------------


def test_empty_findings_returns_empty_summary(tmp_path):
    result = run_aggregate_verification([], repo_root_for=tmp_path)
    assert result.summary["input_findings"] == 0
    assert result.summary["correlated_chains"] == 0
    assert result.summary["duplicate_groups"] == 0
    assert result.summary["final_primaries"] == 0


def test_no_llm_skips_correlation_but_still_dedupes(tmp_path):
    findings = _two_scanner_findings()
    # Plus a duplicate of f1 (same secret in another file)
    findings.append({**findings[0], "id": "f1_dup", "file": "other.env"})

    result = run_aggregate_verification(findings, repo_root_for=tmp_path, llm=None)

    assert result.correlated_findings == []
    assert result.summary["correlated_chains"] == 0
    # Dedup still happened: the secret dup collapsed into one primary
    assert result.summary["merged_findings"] == 1
    assert result.summary["duplicate_groups"] == 1


def test_no_correlation_eligible_groups_skips_llm_call(tmp_path):
    # Single-scanner repo — no cross-scanner angle
    findings = [
        {
            "id": "a",
            "repository": "r",
            "scanner": "code-scanning",
            "severity": "high",
            "rule": "x",
            "file": "f.py",
            "line": 1,
        },
        {
            "id": "b",
            "repository": "r",
            "scanner": "code-scanning",
            "severity": "high",
            "rule": "y",
            "file": "g.py",
            "line": 1,
        },
    ]
    llm = _StubLlm([])
    result = run_aggregate_verification(findings, repo_root_for=tmp_path, llm=llm)
    assert llm.call_count == 0
    assert result.summary["correlated_chains"] == 0


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_two_scanner_repo_runs_full_chain(tmp_path):
    findings = _two_scanner_findings()
    (tmp_path / "acme__widget").mkdir()
    llm = _StubLlm([_final(_chain_json(["f1", "f2"]))])

    result = run_aggregate_verification(
        findings,
        repo_root_for={"acme__widget": tmp_path / "acme__widget"},
        llm=llm,
        total_budget=200_000,
    )
    assert llm.call_count == 1
    assert result.summary["correlated_chains"] == 1
    # Orchestration plan ran and produced decisions
    assert len(result.plan.decisions) == 2
    # Dedup ran (no duplicates here, but it ran)
    assert result.summary["final_primaries"] == 2


def test_correlation_failure_does_not_block_dedupe(tmp_path):
    """If correlate_findings raises, we still get the orchestrator + dedupe output."""
    findings = _two_scanner_findings()
    (tmp_path / "acme__widget").mkdir()

    class _BoomLlm:
        _model = "boom"

        def chat_with_tools(self, *args, **kwargs):
            raise RuntimeError("upstream down")

    result = run_aggregate_verification(
        findings,
        repo_root_for={"acme__widget": tmp_path / "acme__widget"},
        llm=_BoomLlm(),
        total_budget=200_000,
    )
    # Correlation crashed -> empty list, but dedupe + plan still complete
    assert result.correlated_findings == []
    assert result.plan is not None
    assert result.summary["final_primaries"] == 2


def test_serialised_output_is_json_compatible(tmp_path):
    findings = _two_scanner_findings()
    (tmp_path / "acme__widget").mkdir()
    llm = _StubLlm([_final(_chain_json(["f1", "f2"]))])

    result = run_aggregate_verification(
        findings,
        repo_root_for={"acme__widget": tmp_path / "acme__widget"},
        llm=llm,
    )
    payload = result.to_dict()
    # Must be json-serialisable without custom encoder
    s = json.dumps(payload)
    assert "summary" in s
    assert "plan" in s
    assert "correlated_findings" in s
    assert "deduplication" in s


def test_budget_split_passed_to_correlator(tmp_path):
    findings = _two_scanner_findings()
    (tmp_path / "acme__widget").mkdir()
    llm = _StubLlm([_final(_chain_json(["f1", "f2"]))])

    result = run_aggregate_verification(
        findings,
        repo_root_for={"acme__widget": tmp_path / "acme__widget"},
        llm=llm,
        total_budget=10_000,
    )
    # 60/40 default split
    assert result.plan.budget.total == 10_000
    assert result.plan.budget.correlation_pool == 4_000


# ---------------------------------------------------------------------------
# correlate_fn seam (remote Argus route)
# ---------------------------------------------------------------------------


def _valid_chain_dict(ids: list[str]) -> dict:
    return {
        "correlation_id": "corr-0001",
        "verdict": "chain_confirmed",
        "chain_severity": "high",
        "chain_description": "chain",
        "source_finding_ids": ids,
    }


def test_correlate_fn_produces_parsed_findings(tmp_path):
    findings = _two_scanner_findings()
    seen = {}

    def fake_correlate(fs, budget):
        seen["findings"] = fs
        seen["budget"] = budget
        return [_valid_chain_dict(["f1", "f2"])]

    result = run_aggregate_verification(
        findings, repo_root_for=tmp_path, correlate_fn=fake_correlate
    )

    assert len(result.correlated_findings) == 1
    assert result.correlated_findings[0].source_finding_ids == ["f1", "f2"]
    assert seen["budget"] == result.plan.budget.correlation_pool
    # to_dict round-trips the parsed CorrelatedFinding
    payload = result.to_dict()
    assert json.dumps(payload)
    assert payload["correlated_findings"][0]["source_finding_ids"] == ["f1", "f2"]


def test_correlate_fn_takes_precedence_over_llm(tmp_path):
    findings = _two_scanner_findings()
    llm = _StubLlm([_final(_chain_json(["f1", "f2"]))])

    result = run_aggregate_verification(
        findings,
        repo_root_for=tmp_path,
        llm=llm,
        correlate_fn=lambda fs, b: [_valid_chain_dict(["f1", "f2"])],
    )

    # The local llm path must not be exercised when correlate_fn is supplied.
    assert llm.call_count == 0
    assert len(result.correlated_findings) == 1


def test_correlate_fn_skips_malformed_rows(tmp_path):
    findings = _two_scanner_findings()

    result = run_aggregate_verification(
        findings,
        repo_root_for=tmp_path,
        correlate_fn=lambda fs, b: [{"not": "a-chain"}, _valid_chain_dict(["f1", "f2"])],
    )

    # Bad row dropped, valid row kept — never crashes.
    assert len(result.correlated_findings) == 1


def test_correlate_fn_failure_does_not_block_dedupe(tmp_path):
    findings = _two_scanner_findings()

    def boom(fs, b):
        raise RuntimeError("argus down")

    result = run_aggregate_verification(
        findings, repo_root_for=tmp_path, correlate_fn=boom
    )

    assert result.correlated_findings == []
    assert result.summary["final_primaries"] == 2
