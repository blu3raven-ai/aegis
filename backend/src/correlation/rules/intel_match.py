"""Rule 1: Intel match — intel.cve_published → SBOM join → findings.

When a new CVE is published, look up all repos whose SBOM contains the affected
package@version and emit a finding for each match. Dedup is handled by the
Finding's unique constraint on (tool, org, identity_key).
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext
from src.correlation.state import max_severity

logger = logging.getLogger(__name__)

# Tool label for correlation-derived dependency findings
_TOOL = "correlation"

# EPSS threshold above which we bump severity to critical
_EPSS_CRITICAL_THRESHOLD = 0.7


class IntelMatchRule:
    """Rule 1: Intel match."""

    triggers: list[str] = ["intel.cve_published"]
    name: str = "intel_match"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        cve_id = payload.get("cve_id")
        if not cve_id:
            return

        package_name = payload.get("affected_package")
        package_version = payload.get("affected_version")
        advisory_severity = payload.get("severity", "medium")
        epss_score = payload.get("epss_score", 0.0)

        if not package_name:
            return

        # Determine effective severity — bump to critical if EPSS is high
        effective_severity = advisory_severity
        if epss_score and float(epss_score) >= _EPSS_CRITICAL_THRESHOLD:
            effective_severity = max_severity(advisory_severity, "critical")

        # Look up repos whose SBOM contains the affected package
        matches = ctx.state.lookup_sboms_containing(
            package_name, version=package_version
        )

        if not matches:
            logger.debug("intel_match: no SBOM match for %s@%s", package_name, package_version)
            return

        for match in matches:
            org = match["org"]
            repo = match["repo"]
            repo_id = f"{org}/{repo}"
            # Stable key: same CVE in same repo produces the same finding regardless
            # of how many times the intel event is replayed.
            identity_key = f"intel_match::{repo_id}::{cve_id}"

            # Score the finding via Argus (or heuristic fallback when unconfigured).
            risk = ctx.argus.score_finding({
                "cve_id": cve_id,
                "severity": effective_severity,
                "package": package_name,
                "version": match.get("version"),
                "purl": match.get("purl"),
                "epss_score": epss_score,
                "org": org,
                "repo": repo,
                "identity_key": identity_key,
            })

            ctx.emit.emit_finding(
                {
                    "tool": _TOOL,
                    "org": org,
                    "repo": repo,
                    "identity_key": identity_key,
                    "severity": effective_severity,
                    "detail": {
                        "cve_id": cve_id,
                        "package": package_name,
                        "version": match.get("version"),
                        "purl": match.get("purl"),
                        "advisory_severity": advisory_severity,
                        "epss_score": epss_score,
                        "risk_score": risk.score,
                        "risk_source": risk.source,
                        "source": "intel_match",
                    },
                },
                source_event_id=event["event_id"],
                rule_name=self.name,
            )
