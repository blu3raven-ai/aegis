"""Tests for runner.verification.pipelines.orchestrator."""
from __future__ import annotations

import pytest

from runner.verification.pipelines.orchestrator import (
    BudgetSplit,
    InvestigationTier,
    plan_investigation,
    score_finding,
    split_budget,
)


def _f(
    *,
    id="f1",
    severity="high",
    repository="acme__widget",
    scanner="code-scanning",
    verdict=None,
    kev=False,
    epss=None,
    **extras,
) -> dict:
    base = {
        "id": id,
        "severity": severity,
        "repository": repository,
        "scanner": scanner,
    }
    if verdict is not None:
        base["verdict"] = verdict
    if kev:
        base["kev"] = True
    if epss is not None:
        base["epss"] = epss
    base.update(extras)
    return base


# ---------------------------------------------------------------------------
# split_budget
# ---------------------------------------------------------------------------


def test_split_budget_default_fraction():
    s = split_budget(1000)
    assert s.total == 1000
    assert s.deep_verification_pool == 600
    assert s.correlation_pool == 400


def test_split_budget_zero():
    s = split_budget(0)
    assert s == BudgetSplit(total=0, deep_verification_pool=0, correlation_pool=0)


def test_split_budget_negative_treated_as_zero():
    s = split_budget(-100)
    assert s.total == 0


def test_split_budget_clamps_fraction():
    assert split_budget(1000, deep_fraction=2.0).deep_verification_pool == 1000
    assert split_budget(1000, deep_fraction=-0.5).deep_verification_pool == 0


# ---------------------------------------------------------------------------
# score_finding
# ---------------------------------------------------------------------------


def test_severity_drives_baseline_score():
    finding = _f(severity="critical")
    assert score_finding(finding, all_findings=[finding]) >= 80
    finding = _f(severity="low")
    assert score_finding(finding, all_findings=[finding]) < 30


def test_kev_adds_bonus():
    plain = _f(severity="medium", kev=False)
    kev = _f(severity="medium", kev=True)
    assert score_finding(kev, all_findings=[kev]) > score_finding(plain, all_findings=[plain])


def test_epss_percentile_adds_bonus():
    low = _f(epss=0.01)
    high = _f(epss=0.95)
    diff = score_finding(high, all_findings=[high]) - score_finding(low, all_findings=[low])
    assert diff >= 15  # epss bonus range is 0-20


def test_confirmed_verdict_bonus():
    bare = _f(severity="medium")
    confirmed = _f(severity="medium", verdict="confirmed")
    assert score_finding(confirmed, all_findings=[confirmed]) > score_finding(bare, all_findings=[bare])


def test_cross_scanner_bonus_only_when_multiple_scanners_in_same_repo():
    solo = _f(id="a", scanner="code-scanning")
    assert score_finding(solo, all_findings=[solo]) == score_finding(solo, all_findings=[solo, solo])

    findings = [
        _f(id="a", scanner="code-scanning"),
        _f(id="b", scanner="secrets"),
    ]
    cross_scorer = score_finding(findings[0], all_findings=findings)
    solo_scorer = score_finding(_f(id="a"), all_findings=[_f(id="a")])
    assert cross_scorer > solo_scorer


def test_score_bounded_to_max():
    monster = _f(severity="critical", kev=True, epss=1.0, verdict="confirmed")
    findings = [monster, _f(id="b", scanner="secrets"), _f(id="c", scanner="sca")]
    assert score_finding(monster, all_findings=findings) <= 150


# ---------------------------------------------------------------------------
# plan_investigation
# ---------------------------------------------------------------------------


def test_empty_findings_returns_empty_plan():
    plan = plan_investigation([], total_budget=10_000)
    assert plan.decisions == []
    assert plan.expected_deep_count == 0
    assert plan.expected_correlation_groups == 0
    assert plan.summary == {}


def test_high_severity_promoted_to_deep_tier():
    findings = [_f(severity="critical")]
    plan = plan_investigation(findings, total_budget=10_000, deep_cost_per_finding=1_000)
    assert plan.decisions[0].tier == InvestigationTier.DEEP


def test_low_severity_without_verdict_deferred():
    findings = [_f(severity="low")]
    plan = plan_investigation(findings, total_budget=10_000)
    assert plan.decisions[0].tier == InvestigationTier.DEFERRED


def test_low_severity_with_verdict_kept_standard():
    findings = [_f(severity="low", verdict="confirmed")]
    plan = plan_investigation(findings, total_budget=10_000)
    assert plan.decisions[0].tier == InvestigationTier.STANDARD


def test_deep_capacity_caps_promoted_count():
    # 10 critical findings, budget room for only 2 deep slots
    findings = [_f(id=f"f{i}", severity="critical") for i in range(10)]
    plan = plan_investigation(
        findings,
        total_budget=4_000,           # 60% = 2400
        deep_cost_per_finding=1_200,  # 2 fit in 2400
    )
    deep_count = sum(1 for d in plan.decisions if d.tier == InvestigationTier.DEEP)
    assert deep_count == 2
    # The remaining 8 must land somewhere
    assert plan.summary["deep"] == 2
    assert plan.summary.get("deferred", 0) + plan.summary.get("standard", 0) == 8


def test_deep_tier_processes_highest_score_first():
    findings = [
        _f(id="low", severity="low"),
        _f(id="critical", severity="critical"),
        _f(id="medium", severity="medium"),
    ]
    plan = plan_investigation(
        findings,
        total_budget=5_000,           # 60% = 3000
        deep_cost_per_finding=3_000,  # only 1 deep slot fits in 3000
    )
    deep_decisions = [d for d in plan.decisions if d.tier == InvestigationTier.DEEP]
    assert len(deep_decisions) == 1
    assert deep_decisions[0].finding_id == "critical"


def test_correlation_group_count_matches_cross_scanner_repos():
    findings = [
        _f(id="a", scanner="code-scanning", repository="r1"),
        _f(id="b", scanner="secrets", repository="r1"),
        _f(id="c", scanner="code-scanning", repository="r2"),  # solo scanner
        _f(id="d", scanner="code-scanning", repository="r3"),
        _f(id="e", scanner="sca", repository="r3"),
    ]
    plan = plan_investigation(findings, total_budget=10_000)
    assert plan.expected_correlation_groups == 2  # r1 + r3, not r2


def test_summary_counts_every_decision():
    findings = [
        _f(id="x", severity="critical"),
        _f(id="y", severity="low"),
        _f(id="z", severity="low", verdict="confirmed"),
    ]
    plan = plan_investigation(findings, total_budget=10_000, deep_cost_per_finding=1_000)
    assert sum(plan.summary.values()) == 3


def test_decisions_carry_reason_string():
    findings = [_f(severity="critical")]
    plan = plan_investigation(findings, total_budget=10_000, deep_cost_per_finding=1_000)
    assert "critical" in plan.decisions[0].reason or "score" in plan.decisions[0].reason


def test_zero_budget_yields_no_deep_promotions():
    findings = [_f(severity="critical")]
    plan = plan_investigation(findings, total_budget=0)
    assert all(d.tier != InvestigationTier.DEEP for d in plan.decisions)


def test_kev_finding_promoted_even_if_severity_moderate():
    findings = [_f(severity="medium", kev=True), _f(id="b", severity="medium")]
    plan = plan_investigation(findings, total_budget=10_000, deep_cost_per_finding=2_000)
    kev_decision = next(d for d in plan.decisions if d.finding_id == "f1")
    other_decision = next(d for d in plan.decisions if d.finding_id == "b")
    # KEV-tagged one scores higher, so it lands in deep ahead of the plain medium
    assert kev_decision.priority_score > other_decision.priority_score
