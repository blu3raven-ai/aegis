"""Secret verification pipeline tests."""
from __future__ import annotations

from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import verify_secret_finding


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = []
        self._model = "stub-model"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        return LlmResponse(
            content=self._r.pop(0),
            tokens_in=80, tokens_out=40, prompt_hash=f"h-{len(self.calls)}",
        )


def test_provider_verified_secret_is_auto_confirmed():
    finding = {
        "file": ".env.prod", "line": 1, "detector_name": "AWS",
        "match": "AKIAIOSFODNN7EXAMPLE", "verified": True,
    }
    result = verify_secret_finding(
        finding=finding, repo_root="/x", llm=_StubLlm([]),
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.tokens_in == 0
    assert result.verification_metadata["auto_confirmed"] == "provider_verified"


def test_hunter_real_skeptic_agrees_yields_confirmed():
    llm = _StubLlm([
        '{"is_real_secret":true,"reasoning":"prod env file","evidence":[{"file":".env.prod","line":1,"snippet":"x","kind":"secret"}]}',
        '{"agree_with_hunter":true,"counter_evidence":[],"reasoning":"none"}',
    ])
    result = verify_secret_finding(
        finding={"file": ".env.prod", "line": 1, "detector_name": "Generic", "match": "x", "verified": False},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"


def test_hunter_fake_skeptic_agrees_yields_ruled_out():
    llm = _StubLlm([
        '{"is_real_secret":false,"reasoning":"in tests/ dir with mock prefix","evidence":[]}',
        '{"agree_with_hunter":true,"counter_evidence":[],"reasoning":"confirmed test fixture"}',
    ])
    result = verify_secret_finding(
        finding={"file": "tests/fixtures.py", "line": 5, "detector_name": "X", "match": "fake_xxx", "verified": False},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "ruled_out"


def test_hunter_real_skeptic_disagrees_yields_needs_verify():
    llm = _StubLlm([
        '{"is_real_secret":true,"reasoning":"looks live","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"secret"}]}',
        '{"agree_with_hunter":false,"counter_evidence":[{"file":"a.py","line":1,"snippet":"# example","kind":"doc_marker"}],"reasoning":"sample doc"}',
    ])
    result = verify_secret_finding(
        finding={"file": "a.py", "line": 1, "detector_name": "X", "match": "x", "verified": False},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
