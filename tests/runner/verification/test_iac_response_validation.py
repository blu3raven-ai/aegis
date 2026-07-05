"""Pydantic schema enforcement on the IaC hunter and skeptic LLM responses."""
from __future__ import annotations

from pathlib import Path

from runner.verification.llm_client import LlmClient, LlmResponse
from runner.verification.verifiers.iac import verify_iac_finding


class _FixedLlm(LlmClient):
    def __init__(self, *contents: str) -> None:
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
        self._contents = list(contents)

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        # Repeat the final scripted content so the chat_json repair-retry sees the
        # same (still-invalid) response and exhausts its budget as intended.
        content = self._contents[0]
        if len(self._contents) > 1:
            self._contents.pop(0)
        return LlmResponse(
            content=content, tokens_in=10, tokens_out=5, prompt_hash="h-1"
        )


def _finding(tmp_path: Path) -> dict:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n')
    return {
        "tool": "iac_scanning",
        "check_id": "CKV_AWS_19",
        "title": "Ensure S3 bucket is encrypted",
        "severity": "high",
        "file": "main.tf",
        "line": 1,
        "resource": "aws_s3_bucket.x",
    }


def test_invalid_iac_hunter_json_falls_back_to_needs_verify(tmp_path):
    llm = _FixedLlm("not valid json {{{")
    result = verify_iac_finding(
        finding=_finding(tmp_path), repo_root=str(tmp_path), llm=llm
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")


def test_invalid_iac_hunter_schema_falls_back_to_needs_verify(tmp_path):
    """A JSON array is syntactically valid but pydantic rejects non-objects."""
    llm = _FixedLlm("[1, 2, 3]")
    result = verify_iac_finding(
        finding=_finding(tmp_path), repo_root=str(tmp_path), llm=llm
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")


def test_invalid_iac_skeptic_json_falls_back_to_needs_verify(tmp_path):
    llm = _FixedLlm(
        '{"exploit_chain": "something exploitable", "evidence": []}',
        "not valid json {{{",
    )
    result = verify_iac_finding(
        finding=_finding(tmp_path), repo_root=str(tmp_path), llm=llm
    )
    assert result.verdict == "needs_verify"
    assert "skeptic_schema_invalid" in result.verification_metadata.get("reason", "")
