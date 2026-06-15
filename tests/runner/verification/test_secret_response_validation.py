"""Pydantic schema enforcement on the secrets hunter LLM response."""
from __future__ import annotations

from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import verify_secret_finding


class _FixedLlm:
    """Returns a fixed content string for every chat call."""

    def __init__(self, *contents: str) -> None:
        self._contents = list(contents)
        self._model = "stub"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        content = self._contents.pop(0) if self._contents else "{}"
        return LlmResponse(content=content, tokens_in=10, tokens_out=5, prompt_hash="h-1")


_FINDING = {
    "file": "src/config.py",
    "line": 12,
    "detector_name": "Generic",
    "match": "AKIAIOSFODNN7EXAMPLE",
    "verified": False,
}


def test_invalid_secret_hunter_json_falls_back_to_needs_verify():
    """Unparseable JSON from the secrets hunter must fall back to needs_verify."""
    llm = _FixedLlm("not valid json {{{")
    result = verify_secret_finding(
        finding=_FINDING, repo_root="/repo", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")


def test_invalid_secret_hunter_schema_falls_back_to_needs_verify():
    """A hunter response that is not a JSON object falls back to needs_verify."""
    # SecretHunterResponse expects an object; a JSON array is invalid
    llm = _FixedLlm('[1, 2, 3]')
    result = verify_secret_finding(
        finding=_FINDING, repo_root="/repo", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")
