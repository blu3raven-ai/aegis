"""Rule 2: Reachable CVE — dep finding + SAST taint in same repo → chain.

If a dep finding arrives for package P, we check whether any SAST finding in
the same repo has a sink inside P. If yes, the CVE is reachable from user-
controlled input and we emit a "reachable_cve" chain.

Handles both arrival orders: dep-first and SAST-first. The second arrival
checks for the first and completes the chain.
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext

logger = logging.getLogger(__name__)

_CHAIN_TYPE = "reachable_cve"


class ReachableCveRule:
    """Rule 2: Reachable CVE chain."""

    triggers: list[str] = ["scan.finding"]
    name: str = "reachable_cve"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        finding = payload.get("finding", {})
        scanner_type = finding.get("tool") or finding.get("scanner_type", "")
        repo = finding.get("repo")
        org = finding.get("org") or event.get("org_id", "")
        finding_id = finding.get("id") or finding.get("finding_id")

        if not repo or finding_id is None:
            return

        if scanner_type in ("dependencies", "container_scanning"):
            self._handle_dep_finding(event, finding, org, repo, finding_id, ctx)
        elif scanner_type == "code_scanning":
            self._handle_sast_finding(event, finding, org, repo, finding_id, ctx)

    def _handle_dep_finding(
        self,
        event: dict,
        finding: dict,
        org: str,
        repo: str,
        dep_finding_id: int,
        ctx: RuleContext,
    ) -> None:
        """Dep finding arrived — look for existing SAST findings that taint into this package."""
        package = (
            finding.get("detail", {}).get("package")
            or finding.get("package_name")
            or finding.get("identity_key", "").split(":")[0]
        )
        if not package:
            return

        sast_findings = ctx.state.lookup_open_findings(
            org_id=org,
            repo_id=repo,
            scanner_type="code_scanning",
        )

        # SAST findings whose detail.sink_package matches the vulnerable dep
        matching = [
            f for f in sast_findings
            if f.get("detail", {}).get("sink_package") == package
        ]
        if not matching:
            return

        for sast_finding in matching:
            self._emit_chain(event, dep_finding_id, sast_finding["id"], org, ctx)

    def _handle_sast_finding(
        self,
        event: dict,
        finding: dict,
        org: str,
        repo: str,
        sast_finding_id: int,
        ctx: RuleContext,
    ) -> None:
        """SAST finding arrived — look for dep findings for the same package."""
        sink_package = finding.get("detail", {}).get("sink_package")
        if not sink_package:
            return

        dep_findings = ctx.state.lookup_open_findings(
            org_id=org,
            repo_id=repo,
            scanner_type="dependencies",
        )

        # Dep findings whose package name matches the SAST sink
        matching = [
            f for f in dep_findings
            if (f.get("detail", {}).get("package") or "") == sink_package
        ]
        if not matching:
            return

        for dep_finding in matching:
            self._emit_chain(event, dep_finding["id"], sast_finding_id, org, ctx)

    def _emit_chain(
        self,
        event: dict,
        dep_finding_id: int,
        sast_finding_id: int,
        org: str,
        ctx: RuleContext,
    ) -> None:
        chain_id = ctx.emit.emit_chain(
            {
                "org_id": org,
                "chain_type": _CHAIN_TYPE,
                "severity": "high",
            },
            source_event_id=event["event_id"],
            rule_name=self.name,
        )
        if chain_id is None:
            return  # duplicate chain suppressed

        ctx.emit.emit_chain_edge(
            chain_id,
            dep_finding_id,
            sast_finding_id,
            "taint_reaches_vulnerable_dep",
            confidence=0.8,
            rule_name=self.name,
        )
