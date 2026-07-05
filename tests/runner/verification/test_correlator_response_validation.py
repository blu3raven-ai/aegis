"""Pydantic schema enforcement on the correlator agent LLM response."""
from __future__ import annotations

import json
from pathlib import Path

from runner.verification.llm_client import LlmToolResponse
from runner.verification.pipelines.multiscanner import correlate_findings


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


def _findings_two_scanners(repo: str = "acme__widget") -> list[dict]:
    return [
        {
            "id": "f1",
            "repository": repo,
            "scanner": "secret_scanning",
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


def test_invalid_correlator_verdict_falls_back_to_empty_list(tmp_path):
    """A correlator response with an unrecognised verdict enum falls back to empty list."""
    payload = json.dumps({
        "verdict": "TOTALLY_INVALID_VERDICT",
        "chain_severity": "high",
        "chain_description": "some chain",
        "source_finding_ids": ["f1", "f2"],
        "evidence": [],
    })
    llm = _StubLlm([_final(payload)])
    results = correlate_findings(
        _findings_two_scanners(),
        repo_root_for=tmp_path,
        llm=llm,
    )
    assert results == []


def test_unparseable_correlator_json_falls_back_to_empty_list(tmp_path):
    """Malformed JSON from the correlator agent must not crash — returns empty list."""
    llm = _StubLlm([_final("not valid json {{{")])
    results = correlate_findings(
        _findings_two_scanners(),
        repo_root_for=tmp_path,
        llm=llm,
    )
    assert results == []
