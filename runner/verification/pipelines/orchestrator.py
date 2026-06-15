"""Triage + budget allocation for the verification pipelines. No LLM calls."""
from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Sequence
from enum import Enum


class InvestigationTier(str, Enum):
    DEEP = "deep"
    STANDARD = "standard"
    DEFERRED = "deferred"


_DEFAULT_DEEP_FRACTION = 0.6  # deep verification gets 60% of orchestrator budget
_DEFAULT_DEEP_PER_FINDING = 4_000  # ~2 hunter + 1 skeptic + a few tools


@dataclasses.dataclass(frozen=True)
class TierDecision:
    """One finding's place in the investigation queue."""

    finding_id: str
    tier: InvestigationTier
    priority_score: int
    reason: str


@dataclasses.dataclass(frozen=True)
class BudgetSplit:
    """How the orchestrator divides a top-level token budget."""

    total: int
    deep_verification_pool: int
    correlation_pool: int


@dataclasses.dataclass
class OrchestrationPlan:
    decisions: list[TierDecision]
    budget: BudgetSplit
    expected_deep_count: int
    expected_correlation_groups: int
    summary: dict[str, int]


_SEVERITY_BASE = {
    "critical": 80,
    "high": 60,
    "medium": 35,
    "low": 15,
    "negligible": 0,
    "info": 0,
    "unknown": 5,
}


def _finding_id(f: dict) -> str:
    return str(f.get("id") or f.get("findingId") or f.get("advisoryId") or "?")


def _severity_score(f: dict) -> int:
    return _SEVERITY_BASE.get((f.get("severity") or "").lower(), 5)


def _kev_bonus(f: dict) -> int:
    return 15 if (f.get("kev") or f.get("isKev")) else 0


def _epss_bonus(f: dict) -> int:
    epss = f.get("epss") or 0.0
    try:
        epss_f = float(epss)
    except (TypeError, ValueError):
        return 0
    # 0.00-1.00 percentile → 0-20 bonus, matching backend risk_score weighting
    return round(max(0.0, min(epss_f, 1.0)) * 20)


def _confirmed_bonus(f: dict) -> int:
    return 10 if (f.get("verdict") or "").lower() == "confirmed" else 0


def _cross_scanner_bonus(findings: Sequence[dict], f: dict) -> int:
    repo = (f.get("repository") or "").strip()
    if not repo:
        return 0
    scanners_in_repo = {
        (g.get("scanner") or g.get("tool") or "?")
        for g in findings
        if (g.get("repository") or "").strip() == repo
    }
    return 15 if len(scanners_in_repo) >= 2 else 0


def score_finding(f: dict, *, all_findings: Sequence[dict]) -> int:
    """Composite priority score in [0, 150]."""
    raw = (
        _severity_score(f)
        + _kev_bonus(f)
        + _epss_bonus(f)
        + _confirmed_bonus(f)
        + _cross_scanner_bonus(all_findings, f)
    )
    return max(0, min(150, raw))


def split_budget(
    total: int,
    *,
    deep_fraction: float = _DEFAULT_DEEP_FRACTION,
) -> BudgetSplit:
    """Divide a token budget into deep-verification and correlation pools."""
    if total <= 0:
        return BudgetSplit(total=0, deep_verification_pool=0, correlation_pool=0)
    deep_fraction = max(0.0, min(1.0, deep_fraction))
    deep_pool = int(total * deep_fraction)
    return BudgetSplit(
        total=total,
        deep_verification_pool=deep_pool,
        correlation_pool=total - deep_pool,
    )


def plan_investigation(
    findings: Sequence[dict],
    *,
    total_budget: int,
    deep_fraction: float = _DEFAULT_DEEP_FRACTION,
    deep_cost_per_finding: int = _DEFAULT_DEEP_PER_FINDING,
) -> OrchestrationPlan:
    """Score findings, allocate budget, and triage each finding into a tier."""
    if not findings:
        return OrchestrationPlan(
            decisions=[],
            budget=split_budget(total_budget, deep_fraction=deep_fraction),
            expected_deep_count=0,
            expected_correlation_groups=0,
            summary={},
        )

    budget = split_budget(total_budget, deep_fraction=deep_fraction)
    deep_capacity = (
        budget.deep_verification_pool // deep_cost_per_finding
        if deep_cost_per_finding > 0
        else 0
    )

    scored: list[tuple[int, dict]] = [
        (score_finding(f, all_findings=findings), f) for f in findings
    ]
    scored.sort(key=lambda x: x[0], reverse=True)

    decisions: list[TierDecision] = []
    deep_used = 0
    for score, f in scored:
        fid = _finding_id(f)
        if deep_used < deep_capacity and score >= 60:
            decisions.append(
                TierDecision(
                    finding_id=fid,
                    tier=InvestigationTier.DEEP,
                    priority_score=score,
                    reason=_tier_reason(score, f),
                )
            )
            deep_used += 1
        elif (f.get("verdict") or "").lower() in {"confirmed", "needs_verify", "ruled_out"}:
            decisions.append(
                TierDecision(
                    finding_id=fid,
                    tier=InvestigationTier.STANDARD,
                    priority_score=score,
                    reason="per_scanner_verifier_already_produced_verdict",
                )
            )
        else:
            decisions.append(
                TierDecision(
                    finding_id=fid,
                    tier=InvestigationTier.DEFERRED,
                    priority_score=score,
                    reason="below_deep_threshold_and_no_prior_verdict",
                )
            )

    summary = dict(Counter(d.tier.value for d in decisions))
    expected_correlation_groups = _count_eligible_correlation_groups(findings)

    return OrchestrationPlan(
        decisions=decisions,
        budget=budget,
        expected_deep_count=deep_used,
        expected_correlation_groups=expected_correlation_groups,
        summary=summary,
    )


def _tier_reason(score: int, f: dict) -> str:
    if (f.get("kev") or f.get("isKev")):
        return f"score={score}; kev-listed"
    if (f.get("severity") or "").lower() == "critical":
        return f"score={score}; critical severity"
    if (f.get("verdict") or "").lower() == "confirmed":
        return f"score={score}; per-scanner verifier confirmed"
    return f"score={score}; high priority"


def _count_eligible_correlation_groups(findings: Sequence[dict]) -> int:
    """Same eligibility rule as multiscanner.correlate_findings —
    mirrored here so the plan can preview the expected group count
    without importing the pipeline (avoids a circular import)."""
    from collections import defaultdict

    by_repo: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        repo = (f.get("repository") or "").strip()
        if repo:
            by_repo[repo].append(f)
    count = 0
    for group in by_repo.values():
        if len(group) < 2:
            continue
        scanners = {g.get("scanner") or g.get("tool") or "?" for g in group}
        if len(scanners) >= 2:
            count += 1
    return count
