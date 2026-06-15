"""Chain orchestrator -> correlator -> dedupe in one call."""
from __future__ import annotations

import dataclasses
import logging
from collections.abc import Sequence
from pathlib import Path

from runner.verification.budget import ScanBudget
from runner.verification.pipelines.dedupe import DedupResult, deduplicate_findings
from runner.verification.pipelines.multiscanner import correlate_findings
from runner.verification.pipelines.orchestrator import (
    OrchestrationPlan,
    plan_investigation,
)
from runner.verification.schemas.correlation import CorrelatedFinding

logger = logging.getLogger(__name__)


_DEFAULT_TOTAL_BUDGET = 200_000
_DEFAULT_DAILY_REMAINING = 1_000_000


@dataclasses.dataclass
class AggregateVerificationResult:
    plan: OrchestrationPlan
    correlated_findings: list[CorrelatedFinding]
    deduplication: DedupResult
    summary: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "plan": {
                "expected_deep_count": self.plan.expected_deep_count,
                "expected_correlation_groups": self.plan.expected_correlation_groups,
                "summary": self.plan.summary,
                "budget": {
                    "total": self.plan.budget.total,
                    "deep_pool": self.plan.budget.deep_verification_pool,
                    "correlation_pool": self.plan.budget.correlation_pool,
                },
                "decisions": [
                    {
                        "finding_id": d.finding_id,
                        "tier": d.tier.value if hasattr(d.tier, "value") else d.tier,
                        "priority_score": d.priority_score,
                        "reason": d.reason,
                    }
                    for d in self.plan.decisions
                ],
            },
            "correlated_findings": [c.model_dump() for c in self.correlated_findings],
            "deduplication": {
                "duplicate_groups": self.deduplication.duplicate_groups,
                "merged_count": self.deduplication.merged_count,
                "primaries": self.deduplication.primaries,
            },
        }


def run_aggregate_verification(
    findings: Sequence[dict],
    *,
    repo_root_for: dict[str, Path] | Path,
    llm=None,
    total_budget: int = _DEFAULT_TOTAL_BUDGET,
    daily_remaining: int = _DEFAULT_DAILY_REMAINING,
) -> AggregateVerificationResult:
    """Run orchestrator -> correlator -> dedupe. Correlation skipped when ``llm`` is None."""
    plan = plan_investigation(findings, total_budget=total_budget)

    correlated: list[CorrelatedFinding] = []
    if llm is not None and plan.expected_correlation_groups > 0:
        correlation_budget = ScanBudget(
            scan_budget=plan.budget.correlation_pool,
            daily_remaining=daily_remaining,
        )
        try:
            correlated = correlate_findings(
                list(findings),
                repo_root_for=repo_root_for,
                llm=llm,
                budget=correlation_budget,
            )
        except Exception:  # noqa: BLE001
            # Correlation is best-effort — never block dedup on its failure.
            logger.exception("aggregate verification: correlation step failed")
            correlated = []
    elif llm is None:
        logger.info("aggregate verification: llm not configured, skipping correlation")

    dedupe = deduplicate_findings(findings)

    summary = {
        "input_findings": len(findings),
        "deep_tier": plan.summary.get("deep", 0),
        "standard_tier": plan.summary.get("standard", 0),
        "deferred_tier": plan.summary.get("deferred", 0),
        "correlated_chains": len(correlated),
        "duplicate_groups": dedupe.duplicate_groups,
        "merged_findings": dedupe.merged_count,
        "final_primaries": len(dedupe.primaries),
    }

    return AggregateVerificationResult(
        plan=plan,
        correlated_findings=correlated,
        deduplication=dedupe,
        summary=summary,
    )
