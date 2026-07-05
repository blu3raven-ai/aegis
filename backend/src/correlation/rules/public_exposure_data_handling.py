"""Rule 6: Public exposure + sensitive data handling → public_data_exposure chain.

When the same repo has a SAST finding marked as publicly reachable AND another
SAST finding that handles sensitive data (PII / secrets), the combination is a
high-confidence data-exposure risk that warrants a chain.

Both markers are set by SAST rules at scan time so the confidence is high — we
are not inferring anything; we are joining two explicit signals.
"""
from __future__ import annotations

import logging

from src.correlation.rule import RuleContext

logger = logging.getLogger(__name__)

_CHAIN_TYPE = "public_data_exposure"
_CONFIDENCE = 0.85


class PublicExposureDataHandlingRule:
    """Rule 6: Public-facing path + sensitive data handling → chain."""

    triggers: list[str] = ["scan.finding"]
    name: str = "public_exposure_data_handling"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        finding = payload.get("finding", {})
        scanner_type = finding.get("tool") or finding.get("scanner_type", "")
        org = finding.get("org") or event.get("org_id", "")
        repo = finding.get("repo")
        finding_id = finding.get("id") or finding.get("finding_id")

        if not org or not repo or finding_id is None:
            return
        if scanner_type != "code_scanning":
            return

        detail = finding.get("detail", {})
        is_public_facing = bool(detail.get("is_public_facing"))
        handles_sensitive_data = bool(detail.get("handles_sensitive_data"))

        if is_public_facing:
            self._check_for_sensitive_partner(event, finding, org, repo, finding_id, ctx)
        elif handles_sensitive_data:
            self._check_for_public_partner(event, finding, org, repo, finding_id, ctx)

    def _check_for_sensitive_partner(
        self,
        event: dict,
        finding: dict,
        org: str,
        repo: str,
        public_finding_id: int,
        ctx: RuleContext,
    ) -> None:
        """Public-facing finding arrived — look for any sensitive-data findings in the same repo."""
        sensitive = [
            f for f in ctx.state.lookup_open_findings(
                org_id=org,
                repo_id=repo,
                scanner_type="code_scanning",
            )
            if f.get("detail", {}).get("handles_sensitive_data")
            and f["id"] != public_finding_id
        ]
        for s in sensitive:
            self._emit_chain(event, public_finding_id, s["id"], org, ctx)

    def _check_for_public_partner(
        self,
        event: dict,
        finding: dict,
        org: str,
        repo: str,
        sensitive_finding_id: int,
        ctx: RuleContext,
    ) -> None:
        """Sensitive-data finding arrived — look for any public-facing findings in the same repo."""
        public = [
            f for f in ctx.state.lookup_open_findings(
                org_id=org,
                repo_id=repo,
                scanner_type="code_scanning",
            )
            if f.get("detail", {}).get("is_public_facing")
            and f["id"] != sensitive_finding_id
        ]
        for p in public:
            self._emit_chain(event, p["id"], sensitive_finding_id, org, ctx)

    def _emit_chain(
        self,
        event: dict,
        public_finding_id: int,
        sensitive_finding_id: int,
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
            return

        ctx.emit.emit_chain_edge(
            chain_id,
            public_finding_id,
            sensitive_finding_id,
            "public_path_reaches_sensitive_data",
            confidence=_CONFIDENCE,
            rule_name=self.name,
        )
