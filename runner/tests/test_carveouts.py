"""Ground-truth carve-out verdict spine: schema, scope match, and tiered effect."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from runner.verification.llm_client import LlmResponse
from runner.verification.schemas.verdict import GroundTruth, SkepticResponse


def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> MagicMock:
    from runner.verification.llm_client import LlmClient
    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
    llm.chat_json.side_effect = lambda *a, **kw: LlmClient.chat_json(llm, *a, **kw)
    return llm


def test_skeptic_schema_has_carveout_fields() -> None:
    s = SkepticResponse(carve_out_matched=True, carve_out_ref="risk-1", carve_out_source="accepted_risk")
    assert s.carve_out_matched is True
    assert s.carve_out_ref == "risk-1"
    assert s.carve_out_source == "accepted_risk"


def test_skeptic_schema_carveout_defaults() -> None:
    s = SkepticResponse()
    assert s.carve_out_matched is False
    assert s.carve_out_ref is None
    assert s.carve_out_source is None


def test_ground_truth_model_shape() -> None:
    gt = GroundTruth(
        baseline_refs=[{"file": "app/auth.py", "line": 12, "why": "central gateway auth"}],
        accepted_behaviors=[{"statement": "debug endpoint gated by env", "anchor": "app/debug.py"}],
    )
    assert gt.baseline_refs[0]["file"] == "app/auth.py"
    assert gt.accepted_behaviors[0]["statement"].startswith("debug")


from runner.verification.carveouts import accepted_risks_for_finding


_RISKS = [
    {"id": "r-glob", "statement": "handlers validate at gateway", "path_glob": "app/handlers/*.py"},
    {"id": "r-rule", "statement": "eval is a sandboxed plugin loader", "rule_id": "python.lang.eval"},
    {"id": "r-scanner", "statement": "iac public buckets are intentional", "scanner": "iac_scanning"},
    {"id": "r-all", "statement": "applies everywhere"},
]


def test_scope_match_by_path_glob() -> None:
    f = {"file": "app/handlers/user.py", "rule": "x", "scanner": "code_scanning"}
    ids = {r["id"] for r in accepted_risks_for_finding(f, _RISKS)}
    assert "r-glob" in ids and "r-rule" not in ids


def test_scope_match_by_rule_and_scanner() -> None:
    f = {"file": "app/x.py", "rule": "python.lang.eval", "scanner": "iac_scanning"}
    ids = {r["id"] for r in accepted_risks_for_finding(f, _RISKS)}
    assert {"r-rule", "r-scanner", "r-all"} <= ids
    assert "r-glob" not in ids


def test_unscoped_risk_matches_everything() -> None:
    f = {"file": "whatever.py", "rule": "y", "scanner": "code_scanning"}
    ids = {r["id"] for r in accepted_risks_for_finding(f, _RISKS)}
    assert "r-all" in ids


from runner.verification.ground_truth import build_ground_truth


_GT_JSON = json.dumps({
    "baseline_refs": [{"file": "app/auth.py", "line": 3, "why": "central auth"}],
    "accepted_behaviors": [{"statement": "health endpoint is public by design", "anchor": "app/health.py"}],
})


def test_build_ground_truth_parses_recon() -> None:
    with tempfile.TemporaryDirectory() as repo_root:
        (Path(repo_root) / "app").mkdir()
        (Path(repo_root) / "app" / "auth.py").write_text("def auth(): ...\n")
        gt = build_ground_truth(repo_root=repo_root, findings=[{"file": "app/auth.py", "line": 3}], llm=_mock_llm(_GT_JSON))
    assert gt is not None
    assert gt.baseline_refs[0]["file"] == "app/auth.py"


def test_build_ground_truth_fails_open_on_llm_error() -> None:
    llm = MagicMock()
    llm.chat.side_effect = RuntimeError("provider down")
    with tempfile.TemporaryDirectory() as repo_root:
        gt = build_ground_truth(repo_root=repo_root, findings=[{"file": "x.py", "line": 1}], llm=llm)
    assert gt is None  # fail-open — recon failure must not raise


def test_build_ground_truth_none_when_llm_disabled() -> None:
    assert build_ground_truth(repo_root="/tmp", findings=[], llm=None) is None


from runner.verification.prompts.sast import skeptic_user_message


def test_skeptic_message_includes_accepted_risks_and_baseline() -> None:
    msg = skeptic_user_message(
        {"file": "app/x.py", "line": 5, "rule": "r"},
        "hunter chain here",
        "code context here",
        accepted_risks=[{"id": "r-1", "statement": "auth at gateway"}],
        ground_truth=GroundTruth(baseline_refs=[{"file": "app/auth.py", "line": 3, "why": "central auth"}]),
    )
    assert "auth at gateway" in msg
    assert "r-1" in msg
    assert "app/auth.py" in msg


def test_skeptic_message_omits_blocks_when_empty() -> None:
    msg = skeptic_user_message({"file": "a", "line": 1, "rule": "r"}, "chain", "ctx")
    assert "Declared accepted-risks" not in msg
    assert "Baseline references" not in msg
