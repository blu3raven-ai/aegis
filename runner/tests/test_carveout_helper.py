"""Unit tests for the shared carveout_verdict helper (used by SCA + IaC verifiers)."""
from __future__ import annotations

from runner.verification.carveouts import carveout_verdict
from runner.verification.schemas.verdict import SkepticResponse

_FINDING = {"file": "app/x.py", "rule": "r", "scanner": "iac_scanning"}


def _grounded(evidence, repo_root):
    return ([], [])  # nothing unverified — citation grounds


def _ungrounded(evidence, repo_root):
    return (["app/ghost.py:9"], [])  # citation not found in repo


def _call(sk, **kw):
    base = dict(
        accepted_risks=None, chain="c", evidence=[], metadata={},
        critic=_grounded, repo_root="/tmp", tokens_in=0, tokens_out=0,
    )
    base.update(kw)
    return carveout_verdict(_FINDING, sk, **base)


def test_user_declared_rules_out():
    sk = SkepticResponse(carve_out_matched=True, carve_out_ref="r-1", carve_out_source="accepted_risk")
    res = _call(sk, accepted_risks=[{"id": "r-1", "statement": "ok"}])
    assert res is not None and res.verdict == "ruled_out"
    assert res.verification_metadata["ruled_out_reason"]["source"] == "accepted_risk"


def test_cannot_invent_undeclared_risk():
    sk = SkepticResponse(carve_out_matched=True, carve_out_ref="ghost", carve_out_source="accepted_risk")
    assert _call(sk, accepted_risks=[]) is None


def test_grounded_baseline_downgrades():
    sk = SkepticResponse(
        carve_out_matched=True, carve_out_ref="app/a.py:3", carve_out_source="baseline",
        mitigation_found=True, mitigation_file="app/a.py", mitigation_line=3, mitigation_snippet="x",
    )
    res = _call(sk, critic=_grounded)
    assert res is not None and res.verdict == "needs_verify"
    assert res.verification_metadata["carve_out_source"] == "baseline"


def test_ungrounded_baseline_returns_none_and_clears_mitigation():
    sk = SkepticResponse(
        carve_out_matched=True, carve_out_ref="app/ghost.py:9", carve_out_source="baseline",
        mitigation_found=True, mitigation_file="app/ghost.py", mitigation_line=9, mitigation_snippet="nope",
    )
    assert _call(sk, critic=_ungrounded) is None
    assert sk.mitigation_found is False  # cleared so caller won't re-consume it


def test_no_carveout_returns_none():
    assert _call(SkepticResponse()) is None
