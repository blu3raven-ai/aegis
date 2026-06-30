"""Tests that an ungrounded suppress citation downgrades verdict to needs_verify.

Recall safety: the one decision that hides a finding (ruled_out) must require
a mechanically verified citation. An LLM-only assertion is not sufficient.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import verify_finding
from runner.verification.verifiers.iac import verify_iac_finding


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> MagicMock:
    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
    return llm


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
    """IaC skeptic cites a non-empty snippet → ruled_out is kept."""
    with tempfile.TemporaryDirectory() as repo_root:
        llm = _mock_llm(_IAC_HUNTER_JSON, _iac_skeptic_json(snippet='acl = "private"'))
        result = verify_iac_finding(finding=_IAC_FINDING, repo_root=repo_root, llm=llm)

    assert result.verdict == "ruled_out", (
        f"Non-empty mitigation snippet must keep ruled_out; got {result.verdict!r}"
    )
