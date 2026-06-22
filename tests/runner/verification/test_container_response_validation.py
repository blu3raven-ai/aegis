"""Pydantic schema enforcement on the container hunter and skeptic LLM responses."""
from __future__ import annotations

from runner.verification.llm_client import LlmResponse
from runner.verification.verifiers.container import verify_container_finding


class _FixedLlm:
    """Returns a fixed content string for every chat call."""

    def __init__(self, *contents: str) -> None:
        self._contents = list(contents)
        self._model = "stub"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        content = self._contents.pop(0) if self._contents else "{}"
        return LlmResponse(
            content=content, tokens_in=10, tokens_out=5, prompt_hash="h-1"
        )


_FINDING = {
    "packageName": "openssl",
    "packageVersion": "1.1.1k-r0",
    "ecosystem": "apk",
    "advisoryId": "CVE-2023-12345",
    "severity": "high",
    "imageName": "acme-org/web",
    "imageTag": "1.2.3",
}


def test_invalid_container_hunter_json_falls_back_to_needs_verify():
    """A hunter response with no valid JSON should fall back to needs_verify."""
    llm = _FixedLlm("not valid json {{{")
    result = verify_container_finding(finding=_FINDING, llm=llm)
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")


def test_invalid_container_hunter_schema_falls_back_to_needs_verify():
    """A hunter response that fails pydantic validation falls back to needs_verify."""
    # A JSON array is syntactically valid but model_validate_json rejects non-objects.
    llm = _FixedLlm("[1, 2, 3]")
    result = verify_container_finding(finding=_FINDING, llm=llm)
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")


def test_invalid_container_skeptic_json_falls_back_to_needs_verify():
    """A skeptic response with malformed JSON should fall back to needs_verify."""
    llm = _FixedLlm(
        '{"exploit_chain": "something reachable", "evidence": []}',
        "not valid json {{{",
    )
    result = verify_container_finding(finding=_FINDING, llm=llm)
    assert result.verdict == "needs_verify"
    assert "skeptic_schema_invalid" in result.verification_metadata.get("reason", "")
