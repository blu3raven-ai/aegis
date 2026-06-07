"""Read-side compliance service.

Exposes aggregate and detail queries consumed by the REST router.
All functions are async coroutines meant to run inside run_db().
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import false as sa_false, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import (
    ComplianceControlMapping,
    ControlSummaryItem,
    FindingBrief,
    FrameworkControl,
)
from src.db.models import Finding

logger = logging.getLogger(__name__)

SUPPORTED_FRAMEWORKS = ["soc2", "iso27001", "pci-dss"]

FRAMEWORK_LABELS = {
    "soc2": "SOC 2",
    "iso27001": "ISO 27001",
    "pci-dss": "PCI DSS",
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _highest(severities: list[str | None]) -> str | None:
    non_null = [s for s in severities if s]
    if not non_null:
        return None
    return min(non_null, key=lambda s: _SEV_RANK.get(s.lower(), 99))


async def list_frameworks() -> list[dict[str, str]]:
    """Return the static list of supported frameworks."""
    return [
        {"id": fw, "label": FRAMEWORK_LABELS[fw]}
        for fw in SUPPORTED_FRAMEWORKS
    ]


async def list_controls_for_framework(
    session: AsyncSession,
    framework: str,
) -> list[FrameworkControl]:
    """Return all reference controls for a framework."""
    result = await session.execute(
        select(FrameworkControl)
        .where(FrameworkControl.framework == framework)
        .order_by(FrameworkControl.control_id)
    )
    return list(result.scalars().all())


async def get_framework_summary(
    session: AsyncSession,
    framework: str,
    org_id: str | None = None,
    *,
    asset_ids: list[str] | None = None,
) -> list[ControlSummaryItem]:
    """Return per-control finding counts.

    Supply either ``org_id`` (legacy path) or ``asset_ids`` (asset-identity path).
    """
    if asset_ids is None and org_id is None:
        raise ValueError("either org_id or asset_ids is required")

    if asset_ids is not None and not asset_ids:
        controls = await list_controls_for_framework(session, framework)
        return [
            ControlSummaryItem(
                framework=framework,
                control_id=ctrl.control_id,
                title=ctrl.title,
                category=ctrl.category,
                finding_count=0,
                highest_severity=None,
            )
            for ctrl in controls
        ]

    if asset_ids is not None:
        finding_scope = Finding.asset_id.in_(asset_ids)
    else:
        # Org-only callers no longer have a scope after Plan D; fail closed.
        finding_scope = sa_false()

    finding_rows = await session.execute(
        select(
            ComplianceControlMapping.control_id,
            func.count(ComplianceControlMapping.id).label("cnt"),
        )
        .join(Finding, ComplianceControlMapping.finding_id == Finding.id)
        .where(
            ComplianceControlMapping.framework == framework,
            ComplianceControlMapping.finding_id.isnot(None),
            finding_scope,
            Finding.state.in_(("open", "deferred")),
        )
        .group_by(ComplianceControlMapping.control_id)
    )
    finding_counts: dict[str, int] = {r.control_id: r.cnt for r in finding_rows.all()}

    sev_rows = await session.execute(
        select(ComplianceControlMapping.control_id, Finding.severity)
        .join(Finding, ComplianceControlMapping.finding_id == Finding.id)
        .where(
            ComplianceControlMapping.framework == framework,
            ComplianceControlMapping.finding_id.isnot(None),
            finding_scope,
            Finding.state.in_(("open", "deferred")),
        )
    )
    sev_by_control: dict[str, list[str | None]] = {}
    for row in sev_rows.all():
        sev_by_control.setdefault(row.control_id, []).append(row.severity)

    controls = await list_controls_for_framework(session, framework)

    return [
        ControlSummaryItem(
            framework=framework,
            control_id=ctrl.control_id,
            title=ctrl.title,
            category=ctrl.category,
            finding_count=finding_counts.get(ctrl.control_id, 0),
            highest_severity=_highest(sev_by_control.get(ctrl.control_id, [])),
        )
        for ctrl in controls
    ]


async def get_controls_for_finding(
    session: AsyncSession,
    finding_id: int,
) -> list[dict[str, Any]]:
    """Return all control mappings for a single finding, with control metadata."""
    rows = await session.execute(
        select(ComplianceControlMapping, FrameworkControl)
        .join(
            FrameworkControl,
            (ComplianceControlMapping.framework == FrameworkControl.framework)
            & (ComplianceControlMapping.control_id == FrameworkControl.control_id),
        )
        .where(ComplianceControlMapping.finding_id == finding_id)
        .order_by(ComplianceControlMapping.framework, ComplianceControlMapping.control_id)
    )
    results = []
    for mapping, ctrl in rows.all():
        results.append({
            "mapping_id": mapping.id,
            "framework": mapping.framework,
            "control_id": mapping.control_id,
            "confidence": mapping.confidence,
            "rationale": mapping.rationale,
            "title": ctrl.title,
            "category": ctrl.category,
            "created_at": mapping.created_at.isoformat(),
        })
    return results


async def get_findings_for_control(
    session: AsyncSession,
    framework: str,
    control_id: str,
    org_id: str | None = None,
    *,
    asset_ids: list[str] | None = None,
) -> list[FindingBrief]:
    """Return open findings mapped to a specific control.

    Supply either ``org_id`` (legacy path) or ``asset_ids`` (asset-identity path).
    """
    if asset_ids is None and org_id is None:
        raise ValueError("either org_id or asset_ids is required")

    if asset_ids is not None and not asset_ids:
        return []

    if asset_ids is not None:
        finding_scope = Finding.asset_id.in_(asset_ids)
    else:
        # Org-only callers no longer have a scope after Plan D; fail closed.
        finding_scope = sa_false()

    rows = await session.execute(
        select(ComplianceControlMapping, Finding)
        .join(Finding, ComplianceControlMapping.finding_id == Finding.id)
        .where(
            ComplianceControlMapping.framework == framework,
            ComplianceControlMapping.control_id == control_id,
            finding_scope,
            Finding.state.in_(("open", "deferred")),
        )
        .order_by(Finding.severity.asc().nullslast(), Finding.id.desc())
    )
    briefs = []
    for mapping, finding in rows.all():
        briefs.append(FindingBrief(
            id=finding.id,
            tool=finding.tool,
            org=finding.org,
            repo=finding.repo,
            severity=finding.severity,
            state=finding.state,
            identity_key=finding.identity_key,
            confidence=mapping.confidence,
            rationale=mapping.rationale,
        ))
    return briefs
