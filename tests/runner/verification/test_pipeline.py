"""Verification pipeline tests."""
from __future__ import annotations

from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import verify_finding


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = []
        self._model = "stub-model"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        content = self._r.pop(0)
        return LlmResponse(content=content, tokens_in=100, tokens_out=50,
                           prompt_hash=f"h-{len(self.calls)}")


def test_hunter_confirms_then_skeptic_agrees_yields_confirmed():
    llm = _StubLlm([
        '{"exploit_chain":"x reaches y","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.tokens_in == 200
    assert result.tokens_out == 100


def test_skeptic_finds_mitigation_yields_ruled_out():
    llm = _StubLlm([
        '{"exploit_chain":"x","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":true,"mitigation_file":"src/auth.py","mitigation_line":10,'
        '"mitigation_snippet":"if not is_authenticated: abort(401)","reasoning":"auth gate"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "ruled_out"
    assert result.verification_metadata["ruled_out_reason"]["file"] == "src/auth.py"


def test_unverified_citations_cap_at_needs_verify():
    llm = _StubLlm([
        '{"exploit_chain":"x","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":false}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: (["a.py:1 (not_found)"], []),
    )
    assert result.verdict == "needs_verify"
    assert "unverified_citations" in result.verification_metadata


def test_hunter_returns_no_chain_yields_possible():
    llm = _StubLlm(['{"exploit_chain":"","evidence":[]}'])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
    )
    assert result.verdict == "possible"
