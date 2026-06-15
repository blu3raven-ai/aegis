"""Verify that reachability data from finding.detail flows into the hunter context."""
from __future__ import annotations

from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import verify_finding


class _CapturingLlm:
    """Captures all chat calls and returns canned responses."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._model = "stub"
        self.calls: list[list[dict]] = []

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        content = self._responses.pop(0)
        return LlmResponse(content=content, tokens_in=10, tokens_out=5,
                           prompt_hash=f"h-{len(self.calls)}")


_HUNTER_NO_CHAIN = '{"exploit_chain":"","evidence":[]}'
_HUNTER_CHAIN = '{"exploit_chain":"src -> sink","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}'
_SKEPTIC_NO_MITIG = '{"mitigation_found":false,"reasoning":"none"}'


def test_hunter_receives_reachability_verdict():
    """When finding.detail contains reachability, it must appear in the hunter user message."""
    finding = {
        "file": "src/handler.py",
        "line": 10,
        "tool": "sast",
        "rule": "javascript.express.express-xss",
        "severity": "high",
        "detail": {"reachability": {"verdict": "unreachable", "reason": "no caller"}},
    }
    llm = _CapturingLlm([_HUNTER_NO_CHAIN])
    verify_finding(finding=finding, repo_root="/repo", llm=llm)

    assert llm.calls, "verify_finding did not call llm.chat"
    # Hunter call is always the first call
    hunter_messages = llm.calls[0]
    user_content = next(m["content"] for m in hunter_messages if m["role"] == "user")
    assert "unreachable" in user_content.lower(), (
        f"'unreachable' not found in hunter user message. Got:\n{user_content}"
    )


def test_hunter_omits_reachability_when_absent():
    """When finding.detail has no reachability, the hunter call still proceeds normally."""
    finding = {
        "file": "src/handler.py",
        "line": 10,
        "tool": "sast",
        "rule": "javascript.express.express-xss",
        "severity": "high",
        "detail": {},
    }
    llm = _CapturingLlm([_HUNTER_NO_CHAIN])
    result = verify_finding(finding=finding, repo_root="/repo", llm=llm)

    assert llm.calls, "verify_finding did not call llm.chat"
    assert result.verdict == "possible"


def test_hunter_omits_reachability_when_detail_missing():
    """When finding has no 'detail' key at all, the hunter call still proceeds normally."""
    finding = {
        "file": "src/handler.py",
        "line": 10,
        "tool": "sast",
        "rule": "some.rule",
        "severity": "medium",
    }
    llm = _CapturingLlm([_HUNTER_NO_CHAIN])
    result = verify_finding(finding=finding, repo_root="/repo", llm=llm)

    assert result.verdict == "possible"


def test_reachable_verdict_also_forwarded():
    """'reachable' verdict is forwarded — it's a confidence signal the hunter should see."""
    finding = {
        "file": "src/routes/user.py",
        "line": 42,
        "tool": "sast",
        "rule": "sql-injection",
        "severity": "critical",
        "detail": {"reachability": {"verdict": "reachable", "entry_point": "handle_request"}},
    }
    llm = _CapturingLlm([_HUNTER_NO_CHAIN])
    verify_finding(finding=finding, repo_root="/repo", llm=llm)

    hunter_messages = llm.calls[0]
    user_content = next(m["content"] for m in hunter_messages if m["role"] == "user")
    assert "reachable" in user_content.lower()
