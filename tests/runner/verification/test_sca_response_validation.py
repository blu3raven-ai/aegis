"""Pydantic schema enforcement on the SCA hunter and skeptic LLM responses."""
from __future__ import annotations

from runner.verification.llm_client import LlmResponse
from runner.verification.verifiers.sca import verify_sca_finding


class _FixedLlm:
    """Returns a fixed content string for every chat call."""

    def __init__(self, *contents: str) -> None:
        self._contents = list(contents)
        self._model = "stub"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        content = self._contents.pop(0) if self._contents else "{}"
        return LlmResponse(content=content, tokens_in=10, tokens_out=5, prompt_hash="h-1")


_FINDING = {
    "packageName": "requests",
    "packageVersion": "2.28.0",
    "ecosystem": "python",
    "advisoryId": "GHSA-test-0001",
    "severity": "high",
}


def test_invalid_sca_hunter_json_falls_back_to_needs_verify():
    """A hunter response with no valid JSON should fall back to needs_verify."""
    llm = _FixedLlm("not valid json {{{")
    result = verify_sca_finding(
        finding=_FINDING, repo_root="/repo", llm=llm,
        import_sites=[],
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")


def test_invalid_sca_hunter_schema_falls_back_to_needs_verify():
    """A hunter response that fails pydantic validation falls back to needs_verify."""
    # A JSON array is syntactically valid but model_validate_json rejects non-objects.
    llm = _FixedLlm('[1, 2, 3]')
    result = verify_sca_finding(
        finding=_FINDING, repo_root="/repo", llm=llm,
        import_sites=[],
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")
