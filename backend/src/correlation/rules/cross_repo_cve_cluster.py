"""Rule 7: Cross-repo CVE cluster — same CVE in N+ repos → portfolio_cve chain.

When the same CVE appears in 3+ repos (configurable via
AEGIS_CORRELATION_CVE_CLUSTER_THRESHOLD), the issue is systemic. A single chain
groups all affected repos so the team can triage the blast radius in one place
rather than working through per-repo findings individually.

The cluster chain is emitted once per (org, CVE). Subsequent findings that push
the count above the threshold are added as edges to the existing chain.
"""
from __future__ import annotations

import logging
import os

from src.correlation.rule import RuleContext

logger = logging.getLogger(__name__)

_CHAIN_TYPE = "portfolio_cve"
_DEFAULT_THRESHOLD = 3
_CONFIDENCE = 0.7


def _threshold() -> int:
    return int(os.environ.get("AEGIS_CORRELATION_CVE_CLUSTER_THRESHOLD", _DEFAULT_THRESHOLD))


class CrossRepoCveClusterRule:
    """Rule 7: Cross-repo CVE cluster."""

    triggers: list[str] = ["scan.finding"]
    name: str = "cross_repo_cve_cluster"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        finding = payload.get("finding", {})
        scanner_type = finding.get("tool") or finding.get("scanner_type", "")
        org = finding.get("org") or event.get("org_id", "")
        finding_id = finding.get("id") or finding.get("finding_id")

        if not org or finding_id is None:
            return
        if scanner_type not in ("dependencies", "container_scanning"):
            return

        cve_id = (
            finding.get("detail", {}).get("cve_id")
            or finding.get("cve_id")
        )
        if not cve_id:
            return

        # Count distinct repos with open findings for this CVE across the org
        all_cve_findings = ctx.state.lookup_open_findings(
            org_id=org,
            cve_id=cve_id,
        )

        repos_affected = {f.get("repo") for f in all_cve_findings if f.get("repo")}
        if len(repos_affected) < _threshold():
            return

        logger.info(
            "cross_repo_cve_cluster: CVE %s affects %d repos in org %s; emitting cluster chain",
            cve_id, len(repos_affected), org,
        )

        # Use the CVE as the stable dedup anchor rather than the triggering event
        # so replaying the same event does not produce a second chain.
        cluster_event_id = f"cve_cluster:{org}:{cve_id}"

        chain_id = ctx.emit.emit_chain(
            {
                "org_id": org,
                "chain_type": _CHAIN_TYPE,
                "severity": "high",
            },
            source_event_id=cluster_event_id,
            rule_name=self.name,
        )
        if chain_id is None:
            # Chain exists but the idempotency entry was not returned — look it
            # up via the same anchor so edges can still be recorded.
            chain_id = ctx.emit.lookup_chain(
                org_id=org,
                chain_type=_CHAIN_TYPE,
                source_event_id=cluster_event_id,
                rule_name=self.name,
            )
        if chain_id is None:
            logger.warning(
                "cross_repo_cve_cluster: chain not found for org=%s cve=%s; skipping edges",
                org, cve_id,
            )
            return

        # Add an edge for every affected finding → the triggering finding acts as
        # the cluster root. All findings point inward to represent shared exposure.
        for affected in all_cve_findings:
            if affected["id"] == finding_id:
                continue
            ctx.emit.emit_chain_edge(
                chain_id,
                affected["id"],
                finding_id,
                "shares_cve_across_repos",
                confidence=_CONFIDENCE,
                rule_name=self.name,
            )
