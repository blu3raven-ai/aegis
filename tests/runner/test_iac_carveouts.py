"""Ground-truth carve-outs applied to the IaC (checkov) verifier.

Mirrors the SAST carve-out tests: a user-declared accepted-risk is authoritative
(rules the finding out), the LLM cannot invent an undeclared risk id, and a
grounded baseline citation only downgrades a confirmed finding to needs_verify.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from runner.verification.llm_client import LlmResponse
from runner.verification.schemas.verdict import GroundTruth
from runner.verification.verifiers.iac import verify_iac_finding


def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> MagicMock:
    from runner.verification.llm_client import LlmClient
    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
    llm.chat_json.side_effect = lambda *a, **kw: LlmClient.chat_json(llm, *a, **kw)
    llm._min_completion_tokens = 0  # impersonating LlmClient: state chat_json reads
    return llm


_IAC_FINDING = {
    "title": "S3 bucket is publicly readable",
    "severity": "high",
    "file": "infra/main.tf",
    "line": 5,
    "scanner": "iac_scanning",
    "detail": {},
}

_HUNTER = json.dumps({
    "exploit_chain": "Bucket ACL allows public read access to sensitive objects.",
    "evidence": [],
})


def _skeptic(**kw) -> str:
    base = {"mitigation_found": False, "mitigation_file": None, "mitigation_line": None,
            "mitigation_snippet": None, "reasoning": "n/a",
            "carve_out_matched": False, "carve_out_ref": None, "carve_out_source": None}
    base.update(kw)
    return json.dumps(base)


def test_user_declared_carveout_rules_out() -> None:
    risks = [{"id": "r-1", "statement": "public asset bucket is intentional"}]
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "infra").mkdir()
        (Path(repo_root) / "infra" / "main.tf").write_text("x = 1\n" * 10)
        llm = _mock_llm(_HUNTER, _skeptic(
            carve_out_matched=True, carve_out_ref="r-1", carve_out_source="accepted_risk"))
        result = verify_iac_finding(
            finding=_IAC_FINDING, repo_root=repo_root, llm=llm, accepted_risks=risks)
    assert result.verdict == "ruled_out"
    assert result.verification_metadata["ruled_out_reason"]["source"] == "accepted_risk"
    assert result.verification_metadata["ruled_out_reason"]["risk_id"] == "r-1"


def test_llm_cannot_invent_undeclared_accepted_risk() -> None:
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "infra").mkdir()
        (Path(repo_root) / "infra" / "main.tf").write_text("x = 1\n" * 10)
        llm = _mock_llm(_HUNTER, _skeptic(
            carve_out_matched=True, carve_out_ref="ghost", carve_out_source="accepted_risk"))
        result = verify_iac_finding(
            finding=_IAC_FINDING, repo_root=repo_root, llm=llm, accepted_risks=[])
    assert result.verdict == "confirmed"


def test_grounded_baseline_downgrades_confirmed_to_needs_verify() -> None:
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "infra").mkdir()
        base = Path(repo_root) / "infra" / "baseline.tf"
        lines = [f"# line {i + 1}\n" for i in range(10)]
        lines[2] = 'acl = "private"  # baseline module\n'
        base.write_text("".join(lines))
        (Path(repo_root) / "infra" / "main.tf").write_text("x = 1\n" * 10)
        gt = GroundTruth(baseline_refs=[
            {"file": "infra/baseline.tf", "line": 3, "why": "hardened baseline"}])
        llm = _mock_llm(_HUNTER, _skeptic(
            carve_out_matched=True, carve_out_ref="infra/baseline.tf:3", carve_out_source="baseline",
            mitigation_found=True, mitigation_file="infra/baseline.tf", mitigation_line=3,
            mitigation_snippet='acl = "private"  # baseline module'))
        result = verify_iac_finding(
            finding=_IAC_FINDING, repo_root=repo_root, llm=llm, ground_truth=gt)
    assert result.verdict == "needs_verify"
    assert result.verification_metadata["carve_out_source"] == "baseline"
