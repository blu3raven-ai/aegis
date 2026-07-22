"""Tests that an ungrounded suppress citation downgrades verdict to needs_verify.

Recall safety: the one decision that hides a finding (ruled_out) must require
a mechanically verified citation. An LLM-only assertion is not sufficient.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from runner.verification.llm_client import LlmClient, LlmResponse, LlmToolResponse
from runner.verification.pipeline import verify_finding
from runner.verification.verifiers.iac import verify_iac_finding


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


class _ScriptedLlm(LlmClient):
    """Serves a scripted response sequence to both the IaC chat_json path and
    the agentic SAST chat_with_tools path, in call order.

    The final scripted response repeats so the verdict path stays deterministic.
    """

    def __init__(self, responses: tuple[str, ...]) -> None:
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
        self._responses = list(responses)

    def _next(self) -> str:
        content = self._responses[0]
        if len(self._responses) > 1:
            self._responses.pop(0)
        return content

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        return _make_resp(self._next())

    def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1024):
        return LlmToolResponse(content=self._next(), tool_calls=[],
                               tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> _ScriptedLlm:
    return _ScriptedLlm(responses)


_HUNTER_JSON = json.dumps({
    "exploit_chain": "Unsanitized input reaches the database query.",
    "evidence": [],
})

_MITIGATION_FILE = "src/handler.py"
_MITIGATION_LINE = 10
_MITIGATION_SNIPPET = "validate_input(user_data)"

_FINDING = {
    "title": "SQL Injection",
    "severity": "critical",
    "file": "src/handler.py",
    "line": 20,
    "detail": {},
}


def _skeptic_json(*, file: str, line: int, snippet: str) -> str:
    return json.dumps({
        "mitigation_found": True,
        "mitigation_file": file,
        "mitigation_line": line,
        "mitigation_snippet": snippet,
        "reasoning": "Input is validated before reaching the sink.",
    })


# ---------------------------------------------------------------------------
# verify_finding tests
# ---------------------------------------------------------------------------

def test_ungrounded_mitigation_downgrades_to_needs_verify() -> None:
    """Skeptic cites a file/snippet absent from the repo → needs_verify, not ruled_out."""
    with tempfile.TemporaryDirectory() as repo_root:
        # The cited file does not exist in the repo — critic will flag it.
        llm = _mock_llm(
            _HUNTER_JSON,
            _skeptic_json(file=_MITIGATION_FILE, line=_MITIGATION_LINE, snippet=_MITIGATION_SNIPPET),
        )
        result = verify_finding(finding=_FINDING, repo_root=repo_root, llm=llm)

    assert result.verdict == "needs_verify", (
        f"Ungrounded mitigation must not rule out finding; got {result.verdict!r}"
    )
    assert "suppression_downgraded" in result.verification_metadata


def test_grounded_mitigation_returns_ruled_out() -> None:
    """Skeptic cites a snippet that IS present in the repo file → ruled_out is kept."""
    with tempfile.TemporaryDirectory() as repo_root:
        src_dir = Path(repo_root) / "src"
        src_dir.mkdir()
        handler = src_dir / "handler.py"
        # Write 20 lines; place the cited snippet on line 10 (1-based).
        file_lines = [f"# line {i + 1}\n" for i in range(20)]
        file_lines[9] = f"{_MITIGATION_SNIPPET}  # guards input\n"
        handler.write_text("".join(file_lines))

        llm = _mock_llm(
            _HUNTER_JSON,
            _skeptic_json(file=_MITIGATION_FILE, line=_MITIGATION_LINE, snippet=_MITIGATION_SNIPPET),
        )
        result = verify_finding(finding=_FINDING, repo_root=repo_root, llm=llm)

    assert result.verdict == "ruled_out", (
        f"Grounded mitigation must keep ruled_out; got {result.verdict!r}"
    )


# ---------------------------------------------------------------------------
# verify_iac_finding tests
# ---------------------------------------------------------------------------

_IAC_FINDING = {
    "title": "S3 bucket is publicly readable",
    "severity": "high",
    "file": "infra/main.tf",
    "line": 5,
    "detail": {},
}

_IAC_HUNTER_JSON = json.dumps({
    "exploit_chain": "Bucket ACL allows public read access to sensitive objects.",
    "evidence": [],
})


def _iac_skeptic_json(*, snippet: str) -> str:
    return json.dumps({
        "mitigation_found": True,
        "mitigation_file": "infra/main.tf",
        "mitigation_line": 8,
        "mitigation_snippet": snippet,
        "reasoning": "Bucket policy denies public access via bucket policy.",
    })


def test_iac_empty_snippet_downgrades_to_needs_verify() -> None:
    """IaC skeptic claims mitigation but provides no snippet → needs_verify."""
    with tempfile.TemporaryDirectory() as repo_root:
        llm = _mock_llm(_IAC_HUNTER_JSON, _iac_skeptic_json(snippet=""))
        result = verify_iac_finding(finding=_IAC_FINDING, repo_root=repo_root, llm=llm)

    assert result.verdict == "needs_verify", (
        f"Empty mitigation snippet must not rule out finding; got {result.verdict!r}"
    )
    assert result.verification_metadata.get("suppression_downgraded") == "empty_mitigation_citation"


def test_iac_non_empty_snippet_returns_ruled_out() -> None:
    """IaC skeptic cites a snippet that actually exists in the repo → ruled_out."""
    with tempfile.TemporaryDirectory() as repo_root:
        # The citation must be real — write the snippet at the cited line so the
        # grounding check (file exists + snippet within ±2 lines) passes.
        f = Path(repo_root) / "infra" / "main.tf"
        f.parent.mkdir(parents=True, exist_ok=True)
        lines = [""] * 7 + ['acl = "private"']
        f.write_text("\n".join(lines) + "\n")
        llm = _mock_llm(_IAC_HUNTER_JSON, _iac_skeptic_json(snippet='acl = "private"'))
        result = verify_iac_finding(finding=_IAC_FINDING, repo_root=repo_root, llm=llm)

    assert result.verdict == "ruled_out", (
        f"Repo-grounded mitigation snippet must keep ruled_out; got {result.verdict!r}"
    )


def test_iac_snippet_not_in_repo_downgrades_to_needs_verify() -> None:
    """IaC skeptic cites a snippet that isn't in the repo → needs_verify.

    A prompt-injected repo can claim a mitigation that doesn't exist; the
    grounding check must catch it and refuse to suppress.
    """
    with tempfile.TemporaryDirectory() as repo_root:
        llm = _mock_llm(_IAC_HUNTER_JSON, _iac_skeptic_json(snippet='acl = "private"'))
        result = verify_iac_finding(finding=_IAC_FINDING, repo_root=repo_root, llm=llm)

    assert result.verdict == "needs_verify", (
        f"Mitigation snippet absent from repo must not rule out; got {result.verdict!r}"
    )
    assert "mitigation_citation_unverified" in (
        result.verification_metadata.get("suppression_downgraded") or ""
    )
