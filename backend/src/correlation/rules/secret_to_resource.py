"""Rule 3: Secret-to-resource chain — verified secret + SSRF/network → chain.

If a verified secret finding points to resource R AND a SAST finding in the
same org can reach R via SSRF or a network call, the combination is a data
exfiltration chain.

Handles both arrival orders.
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext

logger = logging.getLogger(__name__)

_CHAIN_TYPE = "data_exfil"
_SSRF_RULE_IDS = frozenset({
    "ssrf", "server_side_request_forgery", "unvalidated_redirect",
    "network_call", "http_request_forgery",
})


class SecretToResourceRule:
    """Rule 3: Secret-to-resource chain."""

    triggers: list[str] = ["scan.finding"]
    name: str = "secret_to_resource"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        finding = payload.get("finding", {})
        scanner_type = finding.get("tool") or finding.get("scanner_type", "")
        org = finding.get("org") or event.get("org_id", "")
        finding_id = finding.get("id") or finding.get("finding_id")

        if not org or finding_id is None:
            return

        if scanner_type == "secrets":
            self._handle_secret_finding(event, finding, org, finding_id, ctx)
        elif scanner_type == "code_scanning":
            self._handle_sast_finding(event, finding, org, finding_id, ctx)

    def _handle_secret_finding(
        self,
        event: dict,
        finding: dict,
        org: str,
        secret_finding_id: int,
        ctx: RuleContext,
    ) -> None:
        """Secret finding arrived — check if any SAST finding can reach the same resource."""
        detail = finding.get("detail", {})
        target_resource = detail.get("target_resource") or detail.get("resource_url")
        verified = detail.get("verification_status") == "verified"

        if not target_resource or not verified:
            # Only correlate verified secrets — unverified ones are noise
            return

        sast_findings = ctx.state.lookup_open_findings(
            org_id=org,
            scanner_type="code_scanning",
        )

        matching = [
            f for f in sast_findings
            if self._is_ssrf_reaching(f, target_resource)
        ]
        if not matching:
            return

        for sast_finding in matching:
            self._emit_chain(event, secret_finding_id, sast_finding["id"], org, ctx)

    def _handle_sast_finding(
        self,
        event: dict,
        finding: dict,
        org: str,
        sast_finding_id: int,
        ctx: RuleContext,
    ) -> None:
        """SAST SSRF/network finding arrived — check for verified secrets targeting same resource."""
        detail = finding.get("detail", {})
        rule_id = (detail.get("rule_id") or "").lower()

        if rule_id not in _SSRF_RULE_IDS:
            return

        sink_resource = detail.get("sink_resource") or detail.get("target_url")
        if not sink_resource:
            return

        # Look up verified secrets in the org that target the same resource
        secret_findings = ctx.state.lookup_open_findings(
            org_id=org,
            scanner_type="secrets",
        )

        matching = [
            f for f in secret_findings
            if self._secret_targets_resource(f, sink_resource)
        ]
        if not matching:
            return

        for secret_finding in matching:
            self._emit_chain(event, secret_finding["id"], sast_finding_id, org, ctx)

    def _emit_chain(
        self,
        event: dict,
        secret_finding_id: int,
        sast_finding_id: int,
        org: str,
        ctx: RuleContext,
    ) -> None:
        chain_id = ctx.emit.emit_chain(
            {
                "org_id": org,
                "chain_type": _CHAIN_TYPE,
                "severity": "critical",
            },
            source_event_id=event["event_id"],
            rule_name=self.name,
        )
        if chain_id is None:
            return

        ctx.emit.emit_chain_edge(
            chain_id,
            secret_finding_id,
            sast_finding_id,
            "secret_exposed_via_network_path",
            confidence=0.7,
            rule_name=self.name,
        )

    @staticmethod
    def _is_ssrf_reaching(sast_finding: dict, target_resource: str) -> bool:
        detail = sast_finding.get("detail", {})
        rule_id = (detail.get("rule_id") or "").lower()
        if rule_id not in _SSRF_RULE_IDS:
            return False
        sink = detail.get("sink_resource") or detail.get("target_url") or ""
        # Treat as a match when the resource hostnames overlap (prefix match on
        # protocol+host so we don't require exact path equality).
        return bool(sink) and _resource_host(sink) == _resource_host(target_resource)

    @staticmethod
    def _secret_targets_resource(secret_finding: dict, sink_resource: str) -> bool:
        detail = secret_finding.get("detail", {})
        if detail.get("verification_status") != "verified":
            return False
        target = detail.get("target_resource") or detail.get("resource_url") or ""
        return bool(target) and _resource_host(target) == _resource_host(sink_resource)


def _resource_host(url: str) -> str:
    """Extract scheme+host from a URL for coarse comparison.

    We avoid importing urllib at rule evaluate time by using simple string
    splitting — good enough for resource matching without adding latency.
    """
    # strip fragment, query, path
    stripped = url.split("?")[0].split("#")[0]
    if "://" in stripped:
        parts = stripped.split("://", 1)
        host_path = parts[1].split("/")[0]
        return f"{parts[0]}://{host_path}".lower()
    return stripped.split("/")[0].lower()
