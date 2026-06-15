"""Read-side compliance service.

Exposes aggregate and detail queries consumed by the REST router.
All functions are async coroutines meant to run inside run_db().
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import (
    ComplianceControlMapping,
    ControlSummaryItem,
    FindingBrief,
    Framework,
    FrameworkControl,
)
from src.db.models import Finding

logger = logging.getLogger(__name__)


class FrameworkNotFound(Exception):
    pass


class FrameworkAlreadyExists(Exception):
    pass


class FrameworkNotCustom(Exception):
    pass


class ControlAlreadyExists(Exception):
    pass


class ControlNotFound(Exception):
    pass


_FRAMEWORK_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")


def _validate_framework_id(framework_id: str) -> None:
    if not _FRAMEWORK_ID_PATTERN.fullmatch(framework_id or ""):
        raise ValueError(
            "framework id must be lowercase alphanumeric with optional hyphens, max 64 chars"
        )


def _validate_control_id(control_id: str) -> None:
    if not control_id or not control_id.strip():
        raise ValueError("control_id is required")
    if len(control_id) > 64:
        raise ValueError("control_id must be 64 chars or fewer")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _highest(severities: list[str | None]) -> str | None:
    non_null = [s for s in severities if s]
    if not non_null:
        return None
    return min(non_null, key=lambda s: _SEV_RANK.get(s.lower(), 99))


async def list_frameworks(session: AsyncSession) -> list[dict[str, str]]:
    """Return all registered frameworks (bundled + custom)."""
    rows = await session.execute(select(Framework).order_by(Framework.id))
    return [{"id": fw.id, "label": fw.label} for fw in rows.scalars().all()]


async def get_framework(session: AsyncSession, framework_id: str) -> Framework | None:
    return await session.get(Framework, framework_id)


async def framework_exists(session: AsyncSession, framework_id: str) -> bool:
    return (await get_framework(session, framework_id)) is not None


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
    *,
    asset_ids: list[str],
) -> list[ControlSummaryItem]:
    """Return per-control finding counts scoped to ``asset_ids``.

    Empty ``asset_ids`` yields the reference control list with zero counts —
    the caller has no team access and there's nothing to surface.
    """
    if not asset_ids:
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

    finding_scope = Finding.asset_id.in_(asset_ids)

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
    *,
    asset_ids: list[str],
) -> list[FindingBrief]:
    """Return open findings mapped to a specific control, scoped to ``asset_ids``."""
    if not asset_ids:
        return []

    finding_scope = Finding.asset_id.in_(asset_ids)

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


def _derive_control_status(item: ControlSummaryItem) -> str:
    if item.finding_count == 0:
        return "met"
    sev = (item.highest_severity or "").lower()
    if sev in ("critical", "high"):
        return "unmet"
    return "partial"


def _finding_title(brief: FindingBrief) -> str:
    # FindingBrief has no title field; surface tool + truncated identity_key
    # so the attestation gives auditors something they can pivot on.
    short_key = brief.identity_key[:80]
    return f"{brief.tool}: {short_key}"


def _finding_source_label(brief: FindingBrief) -> str:
    if brief.repo:
        return f"{brief.tool}:{brief.org}/{brief.repo}"
    return f"{brief.tool}:{brief.org}"


async def build_attestation_payload(
    session: AsyncSession,
    framework: str,
    *,
    asset_ids: list[str],
) -> dict[str, Any]:
    """Aggregate the data the attestation PDF template needs into a single dict.

    Scoped to the caller's accessible ``asset_ids`` — empty list yields the
    reference control list with zero finding evidence (consistent with
    get_framework_summary).
    """
    framework_obj = await get_framework(session, framework)
    if framework_obj is None:
        raise ValueError(f"Unknown framework: {framework}")

    summary_items = await get_framework_summary(session, framework, asset_ids=asset_ids)

    statuses = [_derive_control_status(c) for c in summary_items]
    total = len(summary_items)
    met = sum(1 for s in statuses if s == "met")
    unmet = sum(1 for s in statuses if s == "unmet")
    partial = sum(1 for s in statuses if s == "partial")
    critical_gaps = sum(
        1 for c, s in zip(summary_items, statuses)
        if s != "met" and (c.highest_severity or "").lower() == "critical"
    )
    high_gaps = sum(
        1 for c, s in zip(summary_items, statuses)
        if s != "met" and (c.highest_severity or "").lower() == "high"
    )
    pass_pct = round((met / total) * 100) if total else 0

    reference_controls = await list_controls_for_framework(session, framework)
    descriptions_by_id = {c.control_id: (c.description or "") for c in reference_controls}

    controls: list[dict[str, Any]] = []
    for item, status in zip(summary_items, statuses):
        briefs = await get_findings_for_control(
            session, framework, item.control_id, asset_ids=asset_ids,
        )
        controls.append({
            "control_id": item.control_id,
            "title": item.title,
            "description": descriptions_by_id.get(item.control_id, ""),
            "status": status,
            "findings": [
                {
                    "severity": (b.severity or "info").lower(),
                    "title": _finding_title(b),
                    "source_label": _finding_source_label(b),
                }
                for b in briefs
            ],
        })

    return {
        "framework": {"id": framework_obj.id, "label": framework_obj.label},
        "summary": {
            "total_controls": total,
            "met_controls": met,
            "unmet_controls": unmet,
            "partial_controls": partial,
            "critical_gaps": critical_gaps,
            "high_gaps": high_gaps,
            "pass_pct": pass_pct,
        },
        "controls": controls,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---------------------------------------------------------------------------
# Write-side CRUD helpers (custom frameworks + custom controls)
# ---------------------------------------------------------------------------


async def create_framework(
    session: AsyncSession,
    *,
    framework_id: str,
    label: str,
    description: str | None,
    created_by_user_id: str,
) -> Framework:
    _validate_framework_id(framework_id)
    if not label or not label.strip():
        raise ValueError("label is required")
    existing = await session.get(Framework, framework_id)
    if existing is not None:
        raise FrameworkAlreadyExists(framework_id)
    fw = Framework(
        id=framework_id,
        label=label.strip(),
        description=(description.strip() if description else None) or None,
        is_custom=True,
        created_by_user_id=created_by_user_id,
    )
    session.add(fw)
    await session.flush()
    return fw


async def update_framework(
    session: AsyncSession,
    framework_id: str,
    *,
    label: str | None,
    description: str | None,
) -> Framework:
    fw = await session.get(Framework, framework_id)
    if fw is None:
        raise FrameworkNotFound(framework_id)
    if not fw.is_custom:
        raise FrameworkNotCustom(framework_id)
    if label is not None:
        if not label.strip():
            raise ValueError("label is required")
        fw.label = label.strip()
    if description is not None:
        fw.description = description.strip() or None
    await session.flush()
    return fw


async def delete_framework(session: AsyncSession, framework_id: str) -> None:
    fw = await session.get(Framework, framework_id)
    if fw is None:
        raise FrameworkNotFound(framework_id)
    if not fw.is_custom:
        raise FrameworkNotCustom(framework_id)
    await session.delete(fw)
    await session.flush()


async def add_control(
    session: AsyncSession,
    framework_id: str,
    *,
    control_id: str,
    title: str,
    description: str | None,
    category: str | None,
    created_by_user_id: str,
) -> FrameworkControl:
    _validate_control_id(control_id)
    if not title or not title.strip():
        raise ValueError("title is required")
    fw = await session.get(Framework, framework_id)
    if fw is None:
        raise FrameworkNotFound(framework_id)
    if not fw.is_custom:
        raise FrameworkNotCustom(framework_id)
    existing_q = await session.execute(
        select(FrameworkControl).where(
            FrameworkControl.framework == framework_id,
            FrameworkControl.control_id == control_id,
        )
    )
    if existing_q.scalar_one_or_none() is not None:
        raise ControlAlreadyExists(control_id)
    ctrl = FrameworkControl(
        framework=framework_id,
        control_id=control_id,
        title=title.strip(),
        description=(description.strip() if description else None) or None,
        category=(category.strip() if category else None) or None,
        is_custom=True,
        created_by_user_id=created_by_user_id,
    )
    session.add(ctrl)
    await session.flush()
    return ctrl


async def update_control(
    session: AsyncSession,
    framework_id: str,
    control_id: str,
    *,
    title: str | None,
    description: str | None,
    category: str | None,
) -> FrameworkControl:
    fw = await session.get(Framework, framework_id)
    if fw is None:
        raise FrameworkNotFound(framework_id)
    if not fw.is_custom:
        raise FrameworkNotCustom(framework_id)
    row_q = await session.execute(
        select(FrameworkControl).where(
            FrameworkControl.framework == framework_id,
            FrameworkControl.control_id == control_id,
        )
    )
    ctrl = row_q.scalar_one_or_none()
    if ctrl is None:
        raise ControlNotFound(control_id)
    if title is not None:
        if not title.strip():
            raise ValueError("title is required")
        ctrl.title = title.strip()
    if description is not None:
        ctrl.description = description.strip() or None
    if category is not None:
        ctrl.category = category.strip() or None
    await session.flush()
    return ctrl


async def delete_control(
    session: AsyncSession,
    framework_id: str,
    control_id: str,
) -> None:
    fw = await session.get(Framework, framework_id)
    if fw is None:
        raise FrameworkNotFound(framework_id)
    if not fw.is_custom:
        raise FrameworkNotCustom(framework_id)
    row_q = await session.execute(
        select(FrameworkControl).where(
            FrameworkControl.framework == framework_id,
            FrameworkControl.control_id == control_id,
        )
    )
    ctrl = row_q.scalar_one_or_none()
    if ctrl is None:
        raise ControlNotFound(control_id)
    await session.delete(ctrl)
    await session.flush()
