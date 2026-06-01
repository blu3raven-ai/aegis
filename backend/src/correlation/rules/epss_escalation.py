"""Rule 5: EPSS escalation — EPSS crosses threshold → severity bump.

When Argus or an intel source reports that a CVE's EPSS probability crosses a
configurable threshold, all existing findings for that CVE get their severity
bumped to 'critical'. An alert is logged for ops teams.

The threshold is configurable via env var AEGIS_CORRELATION_EPSS_THRESHOLD
(default 0.7 = 70th percentile exploitation probability).
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext
from src.correlation.state import max_severity

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLD = 0.7
_ESCALATED_SEVERITY = "critical"


class EpssEscalationRule:
    """Rule 5: EPSS escalation."""

    triggers: list[str] = ["intel.epss_changed"]
    name: str = "epss_escalation"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        cve_id = payload.get("cve_id")
        if not cve_id:
            return

        new_epss = float(payload.get("new_epss", 0.0))
        old_epss = float(payload.get("old_epss", 0.0))

        threshold = float(
            ctx.state.get_setting("epss_threshold", _DEFAULT_THRESHOLD)
        )

        # Only act on crossings from below to above threshold, not repeated
        # notifications that are already above it.
        if not (new_epss >= threshold and old_epss < threshold):
            return

        # Find all findings for this CVE across all orgs
        findings = ctx.state.lookup_findings(cve_id=cve_id, status=["open", "deferred"])

        if not findings:
            logger.debug("epss_escalation: no findings for %s", cve_id)
            return

        logger.warning(
            "epss_escalation: CVE %s EPSS crossed threshold %.2f (%.3f → %.3f); "
            "escalating %d findings",
            cve_id, threshold, old_epss, new_epss, len(findings),
        )

        for finding in findings:
            # Only bump; never downgrade severity via this rule
            bumped = max_severity(finding.get("severity"), _ESCALATED_SEVERITY)
            if bumped == finding.get("severity"):
                continue  # already at critical or higher

            # Re-score with updated EPSS so the risk score reflects the escalation.
            risk = ctx.argus.score_finding({
                "cve_id": cve_id,
                "severity": bumped,
                "epss_score": new_epss,
            })
            logger.debug(
                "epss_escalation: finding %s rescored to %.1f (source=%s)",
                finding["id"], risk.score, risk.source,
            )

            ctx.emit.emit_severity_change(
                finding["id"],
                bumped,
                reason=f"EPSS crossed threshold: {new_epss:.3f} >= {threshold}",
                rule_name=self.name,
            )
