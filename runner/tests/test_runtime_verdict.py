"""needs_runtime_verification: a grounded chain that hinges on a runtime fact."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import verify_finding
from runner.verification.schemas.verdict import Verdict


def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> MagicMock:
    from runner.verification.llm_client import LlmClient
    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
    llm.chat_json.side_effect = lambda *a, **kw: LlmClient.chat_json(llm, *a, **kw)
    return llm


def _skeptic(**kw) -> str:
    base = {"mitigation_found": False, "mitigation_file": None, "mitigation_line": None,
            "mitigation_snippet": None, "reasoning": "n/a",
            "carve_out_matched": False, "carve_out_ref": None, "carve_out_source": None}
    base.update(kw)
    return json.dumps(base)


_FINDING = {"title": "SSRF", "severity": "high", "file": "app/api.py", "line": 5, "detail": {}}


def _hunter(**kw) -> str:
    base = {"exploit_chain": "user input reaches urllib.request in app/api.py", "evidence": [],
            "needs_runtime": False, "runtime_question": ""}
    base.update(kw)
    return json.dumps(base)


def test_runtime_flag_routes_confirmed_to_needs_runtime_verification():
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "app").mkdir()
        (Path(repo_root) / "app" / "api.py").write_text("x=1\n" * 10)
        llm = _mock_llm(
            _hunter(needs_runtime=True, runtime_question="Confirm /fetch is served without auth in prod config"),
            _skeptic(),
        )
        result = verify_finding(finding=_FINDING, repo_root=repo_root, llm=llm)
    assert result.verdict == "needs_runtime_verification"
    assert "without auth" in result.verification_metadata["runtime_question"]


def test_no_runtime_flag_stays_confirmed():
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "app").mkdir()
        (Path(repo_root) / "app" / "api.py").write_text("x=1\n" * 10)
        llm = _mock_llm(_hunter(needs_runtime=False), _skeptic())
        result = verify_finding(finding=_FINDING, repo_root=repo_root, llm=llm)
    assert result.verdict == "confirmed"


def test_runtime_flag_without_question_stays_confirmed():
    # needs_runtime True but empty question → cannot carry an actionable check → stay confirmed
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "app").mkdir()
        (Path(repo_root) / "app" / "api.py").write_text("x=1\n" * 10)
        llm = _mock_llm(_hunter(needs_runtime=True, runtime_question="  "), _skeptic())
        result = verify_finding(finding=_FINDING, repo_root=repo_root, llm=llm)
    assert result.verdict == "confirmed"
