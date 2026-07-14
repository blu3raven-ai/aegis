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
    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
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
