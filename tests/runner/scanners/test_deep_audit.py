"""Deep-audit engine: hunter -> skeptic -> critic produces backend-shaped findings."""
from __future__ import annotations

from pathlib import Path

from runner.scanners.deep_audit.engine import run_lens
from runner.scanners.deep_audit.lenses.base import get_lens
from runner.scanners.deep_audit.schemas import (
    AuditEvidence,
    AuditFinding,
    AuditHunterResponse,
    AuditSkepticResponse,
)
from runner.scanners.deep_audit.targets import select_files
from runner.verification.budget import ScanBudget

AUTHZ = get_lens("authz")


def _budget():
    return ScanBudget(scan_budget=1_000_000, daily_remaining=1_000_000)


class _Result:
    def __init__(self, parsed):
        self.parsed = parsed
        self.tokens_in = 10
        self.tokens_out = 5


class _FakeLlm:
    """Returns a canned hunter finding, and a skeptic verdict driven by `refute`."""
    _model = "fake-model"

    def __init__(self, *, refute=False):
        self._refute = refute

    def chat_json(self, messages, model, **kw):
        if model is AuditHunterResponse:
            return _Result(AuditHunterResponse(findings=[
                AuditFinding(
                    title="Any user can read another user's record",
                    endpoint="GET /api/records/{id}",
                    file="app/routes.py",
                    line=3,
                    severity="high",
                    weakness="missing_object_scope",
                    exploit_chain="The id comes from the path [R1] and the query is not scoped [R1].",
                    evidence=[AuditEvidence(kind="sink", file="app/routes.py", line=3, snippet="return db.get(Record, id)")],
                    reproduction="GET /api/records/2 as user 1",
                    fix="--- a/app/routes.py\n+++ b/app/routes.py\n@@\n- db.get(Record, id)\n+ db.query(Record).filter_by(id=id, owner=current_user).one()",
                ),
            ]))
        return _Result(AuditSkepticResponse(refuted=self._refute, reason="control found" if self._refute else "none"))


def _seed_repo(tmp_path: Path) -> str:
    routes = tmp_path / "app" / "routes.py"
    routes.parent.mkdir(parents=True)
    # The cited snippet must exist near the cited line for the critic to ground it.
    routes.write_text(
        "@app.get('/api/records/{id}')\n"
        "def get_record(id: int):\n"
        "    return db.get(Record, id)\n",
        encoding="utf-8",
    )
    return str(tmp_path)


def test_targets_selects_handler_files(tmp_path):
    repo = _seed_repo(tmp_path)
    (tmp_path / "app" / "helpers.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    files = select_files(repo, AUTHZ, max_files=10, max_chars=5000)
    picked = {f[0] for f in files}
    assert "app/routes.py" in picked  # route marker present
    assert "app/helpers.py" not in picked  # no handler / route marker


def test_confirmed_authz_finding_is_backend_shaped(tmp_path):
    repo = _seed_repo(tmp_path)
    out = run_lens(
        repo, AUTHZ, llm=_FakeLlm(refute=False), escalation_llm=None,
        scan_budget=_budget(), max_files=10, max_chars=5000, max_workers=2,
        model_name="fake-model",
    )
    assert len(out) == 1
    f = out[0]
    assert f["check_id"] == "AUTHZ_MISSING_OBJECT_SCOPE"
    assert f["verdict"] == "confirmed"  # skeptic didn't refute, citation grounds
    assert f["cwe"] == "CWE-639"
    assert f["recommended_fix"].startswith("--- a/app/routes.py")  # concrete diff
    meta = f["verification_metadata"]
    assert meta["lens"] == "authz" and meta["owasp"].startswith("A01")
    assert meta["reproduction"]
    assert f["evidence"][0]["kind"] == "sink"


def test_skeptic_refutation_rules_it_out(tmp_path):
    repo = _seed_repo(tmp_path)
    out = run_lens(
        repo, AUTHZ, llm=_FakeLlm(refute=True), escalation_llm=None,
        scan_budget=_budget(), max_files=10, max_chars=5000, max_workers=2,
        model_name="fake-model",
    )
    assert out[0]["verdict"] == "ruled_out"
    assert out[0]["verification_metadata"]["ruled_out_reason"]["reasoning"] == "control found"
