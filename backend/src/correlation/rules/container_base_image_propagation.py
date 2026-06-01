"""Rule 8: Container base image propagation — vuln in base layer → sibling containers.

When a container scan finding is tagged with affected_layer: "base", the
vulnerability lives in the OS/runtime layer shared by every container built from
the same base image. All other containers with the same base_image_digest are
therefore also affected, even if their own scans haven't reported the CVE yet.

Confidence is very high (0.9) because shared digest = identical bytes — there is
no inference involved.
"""
from __future__ import annotations

import logging

from src.correlation.rule import RuleContext

logger = logging.getLogger(__name__)

_CHAIN_TYPE = "base_image_inheritance"
_CONFIDENCE = 0.9


class ContainerBaseImagePropagationRule:
    """Rule 8: Base image vuln propagates to all sibling containers."""

    triggers: list[str] = ["scan.finding"]
    name: str = "container_base_image_propagation"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        finding = payload.get("finding", {})
        scanner_type = finding.get("tool") or finding.get("scanner_type", "")
        org = finding.get("org") or event.get("org_id", "")
        finding_id = finding.get("id") or finding.get("finding_id")

        if not org or finding_id is None:
            return
        if scanner_type != "container_scanning":
            return

        detail = finding.get("detail", {})
        if detail.get("affected_layer") != "base":
            return

        base_image_digest = detail.get("base_image_digest")
        if not base_image_digest:
            return

        # Find all other container findings sharing the same base image digest.
        # These represent containers that inherit the same vulnerable layer.
        sibling_findings = [
            f for f in ctx.state.lookup_open_findings(
                org_id=org,
                scanner_type="container_scanning",
            )
            if f["id"] != finding_id
            and f.get("detail", {}).get("base_image_digest") == base_image_digest
        ]

        if not sibling_findings:
            logger.debug(
                "container_base_image_propagation: no siblings share digest %s",
                base_image_digest,
            )
            return

        logger.info(
            "container_base_image_propagation: base vuln (finding %d, digest %s) "
            "propagates to %d sibling container(s) in org %s",
            finding_id, base_image_digest, len(sibling_findings), org,
        )

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

        # Each sibling inherits from the base image vuln finding
        for sibling in sibling_findings:
            ctx.emit.emit_chain_edge(
                chain_id,
                finding_id,
                sibling["id"],
                "base_image_vuln_inherited_by_container",
                confidence=_CONFIDENCE,
                rule_name=self.name,
            )
