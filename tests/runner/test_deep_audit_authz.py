"""Authz deep-audit engine: the hunter is new, but every verdict is decided by the
shared verifier (skeptic + citation critic + carve-outs)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from runner.scanners.deep_audit.engine import audit_repo
from runner.scanners.deep_audit.targets import select_files
from runner.verification.llm_client import LlmResponse


def _make_resp(content: str) -> LlmResponse:
    return LlmResponse(content=content, tokens_in=10, tokens_out=20, prompt_hash="x")


def _mock_llm(*responses: str) -> MagicMock:
    from runner.verification.llm_client import LlmClient

    llm = MagicMock()
    llm.chat.side_effect = [_make_resp(r) for r in responses]
    llm.chat_json.side_effect = lambda *a, **kw: LlmClient.chat_json(llm, *a, **kw)
    return llm


class _Budget:
    skip_reason = "budget"

    def allow(self):
        return True

    def record(self, **kw):
        pass


def _repo_with_handler() -> str:
    d = tempfile.mkdtemp()
    routes = Path(d) / "app" / "routes.py"
    routes.parent.mkdir(parents=True)
    routes.write_text(
        "@router.delete('/invoice/{id}')\n"
        "def delete_invoice(id):\n"
        "    db.delete(id)\n"
    )
    return d


_HUNTER = json.dumps({"findings": [{
    "title": "Any user can delete another user's invoice",
    "endpoint": "DELETE /invoice/{id}", "file": "app/routes.py", "line": 1,
    "severity": "high", "weakness": "missing_object_scope",
    "exploit_chain": "The handler deletes by id with no ownership check [R1]",
    "evidence": [{"kind": "sink", "file": "app/routes.py", "line": 3, "snippet": "db.delete(id)"}],
    "reproduction": "Call DELETE with another user's invoice id",
    "fix": "Scope the delete to the caller",
}]})


def _skeptic(**kw) -> str:
    base = {"mitigation_found": False, "mitigation_file": None, "mitigation_line": None,
            "mitigation_snippet": None, "reasoning": "n/a",
            "carve_out_matched": False, "carve_out_ref": None, "carve_out_source": None}
    base.update(kw)
    return json.dumps(base)


def test_confirmed_when_grounded_and_no_mitigation():
    repo = _repo_with_handler()
    rows = audit_repo(repo, llm=_mock_llm(_HUNTER, _skeptic()), scan_budget=_Budget(), max_workers=1)
    assert len(rows) == 1
    assert rows[0]["verdict"] == "confirmed"
    assert rows[0]["cwe"] == "CWE-639"
    assert rows[0]["check_id"] == "deep_audit.authz.missing_object_scope"


def test_ruled_out_when_skeptic_cites_grounded_control():
    repo = _repo_with_handler()
    # cite a real line in the handler file as the (spurious but grounded) control
    skeptic = _skeptic(mitigation_found=True, mitigation_file="app/routes.py",
                       mitigation_line=2, mitigation_snippet="def delete_invoice(id):")
    rows = audit_repo(repo, llm=_mock_llm(_HUNTER, skeptic), scan_budget=_Budget(), max_workers=1)
    assert rows[0]["verdict"] == "ruled_out"


def test_user_declared_accepted_risk_rules_out():
    repo = _repo_with_handler()
    risks = [{"id": "r-1", "statement": "invoice access is enforced at the API gateway"}]
    skeptic = _skeptic(carve_out_matched=True, carve_out_ref="r-1", carve_out_source="accepted_risk")
    rows = audit_repo(repo, llm=_mock_llm(_HUNTER, skeptic), scan_budget=_Budget(),
                      accepted_risks=risks, max_workers=1)
    assert rows[0]["verdict"] == "ruled_out"
    assert rows[0]["verification_metadata"]["ruled_out_reason"]["source"] == "accepted_risk"


def test_no_llm_is_noop():
    assert audit_repo(_repo_with_handler(), llm=None, scan_budget=_Budget()) == []


def test_select_files_picks_handlers_skips_tests():
    d = tempfile.mkdtemp()
    (Path(d) / "app").mkdir()
    (Path(d) / "app" / "routes.py").write_text("@router.get('/x')\ndef x(): ...\n")
    (Path(d) / "tests").mkdir()
    (Path(d) / "tests" / "test_routes.py").write_text("@router.get('/y')\ndef y(): ...\n")
    picked = {p for p, _ in select_files(d, max_files=40, max_chars=8000)}
    assert "app/routes.py" in picked
    assert "tests/test_routes.py" not in picked
