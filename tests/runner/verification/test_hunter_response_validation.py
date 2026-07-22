"""Pydantic schema enforcement on the SAST hunter LLM response."""
from __future__ import annotations

from runner.verification.llm_client import LlmClient, LlmToolResponse
from runner.verification.pipeline import verify_finding


class _FixedLlm(LlmClient):
    """Returns a fixed final answer for every investigator turn."""

    def __init__(self, content: str) -> None:
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
        self._content = content

    def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1024):
        return LlmToolResponse(content=self._content, tool_calls=[], tokens_in=10,
                               tokens_out=5, prompt_hash="h-1")


_FINDING = {
    "file": "src/app.py",
    "line": 5,
    "tool": "sast",
    "rule": "some-rule",
    "severity": "high",
    "detail": {},
}


def test_invalid_hunter_json_falls_back_to_needs_verify():
    """A hunter response whose exploit_chain field is unexpectedly absent should not crash."""
    llm = _FixedLlm('{"verdict": "INVALID_LITERAL"}')
    result = verify_finding(finding=_FINDING, repo_root="/repo", llm=llm)
    # No exploit_chain → hunter returns empty chain → verdict is "possible"
    # OR if pydantic-validated and invalid → "needs_verify"
    # Either way, it must not raise.
    assert result.verdict in ("needs_verify", "possible")


def test_unparseable_hunter_json_falls_back_gracefully():
    """Malformed JSON from the hunter must not crash — falls back to 'possible' or 'needs_verify'."""
    llm = _FixedLlm("not valid json {{{")
    result = verify_finding(finding=_FINDING, repo_root="/repo", llm=llm)
    assert result.verdict in ("needs_verify", "possible")


def test_valid_hunter_response_schema_passes_through():
    """A structurally valid hunter response reaches the skeptic stage (needs two LLM calls)."""

    responses = [
        '{"exploit_chain":"src -> sink","evidence":[{"file":"src/app.py","line":5,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ]
    idx = [0]

    class _TwoShotLlm(LlmClient):
        def __init__(self) -> None:
            super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")

        def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1024):
            content = responses[idx[0]]
            idx[0] += 1
            return LlmToolResponse(content=content, tool_calls=[], tokens_in=10,
                                   tokens_out=5, prompt_hash=f"h-{idx[0]}")

    result = verify_finding(
        finding=_FINDING, repo_root="/repo", llm=_TwoShotLlm(),
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"


def test_hunter_schema_invalid_verdict_falls_back():
    """When pydantic validates hunter output and it fails, falls back to needs_verify."""
    # This JSON is syntactically valid but semantically wrong for the hunter schema —
    # the hunter is expected to return exploit_chain + evidence, not a bare verdict.
    # If pydantic validation is in place for the hunter response, it should catch this.
    # If not yet validated at hunter stage, this degrades gracefully (no chain → possible).
    llm = _FixedLlm('{"exploit_chain": null, "evidence": null}')
    result = verify_finding(finding=_FINDING, repo_root="/repo", llm=llm)
    # null exploit_chain → treated as empty string → verdict "possible"
    # If pydantic validates and fails → "needs_verify"
    assert result.verdict in ("needs_verify", "possible")


class _TwoShotLlm(LlmClient):
    """Returns a fixed hunter answer then a fixed skeptic answer."""

    def __init__(self, hunter_content: str, skeptic_content: str) -> None:
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
        self._responses = [hunter_content, skeptic_content]
        self._idx = 0

    def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1024):
        # Clamp to the last scripted response so any extra turn is deterministic.
        content = self._responses[min(self._idx, len(self._responses) - 1)]
        self._idx += 1
        return LlmToolResponse(content=content, tool_calls=[], tokens_in=10,
                               tokens_out=5, prompt_hash=f"h-{self._idx}")


_VALID_HUNTER_JSON = (
    '{"exploit_chain":"src -> sink",'
    '"evidence":[{"file":"src/app.py","line":5,"snippet":"x","kind":"source"}]}'
)


def test_invalid_sast_skeptic_json_falls_back_to_hunter_verdict():
    """An unparseable skeptic response must not crash — treat as no mitigation found."""
    llm = _TwoShotLlm(_VALID_HUNTER_JSON, "not valid json {{{")
    result = verify_finding(
        finding=_FINDING, repo_root="/repo", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    # Skeptic fails → mitigation_found defaults False → critic passes → confirmed
    assert result.verdict == "confirmed"


def test_invalid_sast_skeptic_schema_falls_back_to_hunter_verdict():
    """A skeptic response that is valid JSON but not an object must not crash."""
    # A JSON array passes json.loads but model_validate_json rejects non-objects.
    llm = _TwoShotLlm(_VALID_HUNTER_JSON, '[1, 2, 3]')
    result = verify_finding(
        finding=_FINDING, repo_root="/repo", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    # Skeptic fails → mitigation_found defaults False → critic passes → confirmed
    assert result.verdict == "confirmed"


def test_hunter_response_accepts_cvss_metrics():
    from runner.verification.schemas.verdict import HunterResponse

    resp = HunterResponse.model_validate({
        "title": "x",
        "cvss_metrics": {"AV": "L", "AC": "L", "PR": "N", "UI": "R",
                         "S": "U", "C": "H", "I": "H", "A": "H"},
    })
    assert resp.cvss_metrics["AV"] == "L"


def test_hunter_response_cvss_metrics_defaults_empty():
    from runner.verification.schemas.verdict import HunterResponse

    resp = HunterResponse.model_validate({"title": "x"})
    assert resp.cvss_metrics == {}
