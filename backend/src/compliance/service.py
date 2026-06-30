"""Read-side compliance service.

Exposes aggregate and detail queries consumed by the REST router.
All functions are async coroutines meant to run inside run_db().
"""
from __future__ import annotations

import logging
import re
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import (
    ASSESSMENT_STATUSES,
    ComplianceControlAssessment,
    ComplianceControlMapping,
    ControlSummaryItem,
    FindingBrief,
    Framework,
    FrameworkControl,
    MappableFindingItem,
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


def _org_repo_from_asset(asset) -> tuple[str, str | None]:
    """Derive (owner, name) from an asset's canonical external_ref.

    "github:acme/api" -> ("acme", "api"); "ghcr:acme/img:tag" -> ("acme", "img").
    Findings carry neither field — they belong to the asset.
    """
    ext = asset.external_ref or ""
    if ":" not in ext:
        return "", (asset.display_name or None)
    _src, rest = ext.split(":", 1)
    if "/" in rest:
        owner, name = rest.split("/", 1)
        return owner or "", (name.split(":")[0] or None)
    return "", (rest.split(":")[0] or None)


# How a manual attestation maps onto the three-state {met, partial, unmet} the
# UI and PDF roll up. "not_applicable" counts as met (it's not a gap).
_MANUAL_STATUS_TO_STATE = {
    "compliant": "met",
    "not_applicable": "met",
    "in_progress": "partial",
    "non_compliant": "unmet",
}


async def get_assessments_for_framework(
    session: AsyncSession, framework: str
) -> dict[str, ComplianceControlAssessment]:
    """All control assessments for a framework, keyed by control_id."""
    rows = await session.execute(
        select(ComplianceControlAssessment).where(
            ComplianceControlAssessment.framework == framework
        )
    )
    return {a.control_id: a for a in rows.scalars().all()}


def _parse_due_date(value: str | None) -> date | None:
    s = (value or "").strip()
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except ValueError as exc:
        raise ValueError(f"due_date must be an ISO date (YYYY-MM-DD): {value!r}") from exc


async def _user_exists(session: AsyncSession, user_id: str) -> bool:
    from src.db.models import User
    return (
        await session.execute(select(User.id).where(User.id == user_id))
    ).scalar_one_or_none() is not None


def _apply_assessment(item: ControlSummaryItem, assessment: ComplianceControlAssessment | None) -> None:
    """Overlay a control's manual attestation + remediation onto its summary item."""
    if assessment is None:
        return
    item.manual_status = assessment.status
    item.evidence_note = assessment.evidence_note
    item.evidence_url = assessment.evidence_url
    item.assessed_by = assessment.assessed_by_user_id
    item.assessed_at = assessment.assessed_at.isoformat() if assessment.assessed_at else None
    item.owner_user_id = assessment.owner_user_id
    item.due_date = assessment.due_date.isoformat() if assessment.due_date else None


async def _finalize_remediation(session: AsyncSession, items: list[ControlSummaryItem]) -> None:
    """Resolve owner display labels (one batch query) and compute `overdue`
    (a due date in the past on a control that isn't met), in place."""
    today = datetime.now(timezone.utc).date()
    owner_ids = {i.owner_user_id for i in items if i.owner_user_id}
    labels: dict[str, str] = {}
    if owner_ids:
        from src.db.models import User
        rows = (await session.execute(
            select(User.id, User.username).where(User.id.in_(owner_ids))
        )).all()
        labels = {uid: uname for uid, uname in rows}
    for item in items:
        if item.owner_user_id:
            item.owner_label = labels.get(item.owner_user_id, item.owner_user_id)
        if item.due_date:
            try:
                due = date.fromisoformat(item.due_date)
            except ValueError:
                due = None
            item.overdue = bool(due and due < today and _derive_control_status(item) != "met")


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
    assessments = await get_assessments_for_framework(session, framework)

    if not asset_ids:
        controls = await list_controls_for_framework(session, framework)
        items = []
        for ctrl in controls:
            item = ControlSummaryItem(
                framework=framework,
                control_id=ctrl.control_id,
                title=ctrl.title,
                category=ctrl.category,
                finding_count=0,
                highest_severity=None,
            )
            _apply_assessment(item, assessments.get(ctrl.control_id))
            items.append(item)
        await _finalize_remediation(session, items)
        return items

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
            ComplianceControlMapping.suppressed.is_(False),
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
            ComplianceControlMapping.suppressed.is_(False),
            finding_scope,
            Finding.state.in_(("open", "deferred")),
        )
    )
    sev_by_control: dict[str, list[str | None]] = {}
    for row in sev_rows.all():
        sev_by_control.setdefault(row.control_id, []).append(row.severity)

    controls = await list_controls_for_framework(session, framework)

    items = []
    for ctrl in controls:
        item = ControlSummaryItem(
            framework=framework,
            control_id=ctrl.control_id,
            title=ctrl.title,
            category=ctrl.category,
            finding_count=finding_counts.get(ctrl.control_id, 0),
            highest_severity=_highest(sev_by_control.get(ctrl.control_id, [])),
        )
        _apply_assessment(item, assessments.get(ctrl.control_id))
        items.append(item)
    await _finalize_remediation(session, items)
    return items


async def get_controls_for_finding(
    session: AsyncSession,
    finding_id: int,
    *,
    asset_ids: list[str],
) -> list[dict[str, Any]]:
    """Return all control mappings for a single finding, with control metadata.

    Scoped to the caller's accessible ``asset_ids`` — empty list yields no
    mappings. Findings with ``asset_id IS NULL`` (e.g. secrets findings) are
    also out of scope here, mirroring the ``get_findings_for_control`` posture.
    """
    if not asset_ids:
        return []
    rows = await session.execute(
        select(ComplianceControlMapping, FrameworkControl)
        .join(
            FrameworkControl,
            (ComplianceControlMapping.framework == FrameworkControl.framework)
            & (ComplianceControlMapping.control_id == FrameworkControl.control_id),
        )
        .join(Finding, ComplianceControlMapping.finding_id == Finding.id)
        .where(
            ComplianceControlMapping.finding_id == finding_id,
            ComplianceControlMapping.suppressed.is_(False),
            Finding.asset_id.in_(asset_ids),
        )
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
    include_suppressed: bool = False,
) -> list[FindingBrief]:
    """Return open findings mapped to a control, scoped to ``asset_ids``.

    By default excludes suppressed mappings (so attestations and the PDF only
    count live evidence). The control-detail UI passes ``include_suppressed`` so
    it can render suppressed mappings greyed-out with a restore action — active
    mappings sort first.
    """
    if not asset_ids:
        return []

    from src.db.models import Asset

    where = [
        ComplianceControlMapping.framework == framework,
        ComplianceControlMapping.control_id == control_id,
        Finding.asset_id.in_(asset_ids),
        Finding.state.in_(("open", "deferred")),
    ]
    if not include_suppressed:
        where.append(ComplianceControlMapping.suppressed.is_(False))

    # Join the asset so org/repo can be derived from its external_ref — the
    # Finding row carries neither (they live on the asset it belongs to).
    rows = await session.execute(
        select(ComplianceControlMapping, Finding, Asset)
        .join(Finding, ComplianceControlMapping.finding_id == Finding.id)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(*where)
        .order_by(
            ComplianceControlMapping.suppressed.asc(),
            Finding.severity.asc().nullslast(),
            Finding.id.desc(),
        )
    )
    briefs = []
    for mapping, finding, asset in rows.all():
        org, repo = _org_repo_from_asset(asset)
        briefs.append(FindingBrief(
            id=finding.id,
            tool=finding.tool,
            org=org,
            repo=repo,
            severity=finding.severity,
            state=finding.state,
            identity_key=finding.identity_key,
            confidence=mapping.confidence,
            rationale=mapping.rationale,
            mapping_id=mapping.id,
            suppressed=mapping.suppressed,
            manual=mapping.manual,
        ))
    return briefs


def _derive_control_status(item: ControlSummaryItem) -> str:
    """Effective control status. A human attestation, when present, wins over the
    finding-derived signal — the analyst has explicitly reviewed the control."""
    if item.manual_status and item.manual_status in _MANUAL_STATUS_TO_STATE:
        return _MANUAL_STATUS_TO_STATE[item.manual_status]
    if item.finding_count == 0:
        return "met"
    sev = (item.highest_severity or "").lower()
    if sev in ("critical", "high"):
        return "unmet"
    return "partial"


async def upsert_control_assessment(
    session: AsyncSession,
    framework: str,
    control_id: str,
    *,
    status: str | None,
    evidence_note: str | None,
    evidence_url: str | None,
    owner_user_id: str | None = None,
    due_date: str | None = None,
    user_id: str,
) -> ComplianceControlAssessment:
    """Set (or clear) a control's manual attestation + remediation overlay.

    ``status`` of ``"auto"``/``None`` clears the override while keeping the
    evidence/owner/due fields. ``due_date`` is an ISO date string (or empty to
    clear). Validates that the framework and control both exist.
    """
    if status in (None, "auto", ""):
        status = None
    elif status not in ASSESSMENT_STATUSES:
        raise ValueError(
            f"status must be one of {sorted(ASSESSMENT_STATUSES)} or 'auto' to clear"
        )

    parsed_due = _parse_due_date(due_date)
    owner = (owner_user_id or "").strip() or None
    if owner is not None and not await _user_exists(session, owner):
        raise ValueError(f"unknown owner_user_id: {owner}")

    if await get_framework(session, framework) is None:
        raise FrameworkNotFound(framework)
    ctrl_q = await session.execute(
        select(FrameworkControl).where(
            FrameworkControl.framework == framework,
            FrameworkControl.control_id == control_id,
        )
    )
    if ctrl_q.scalar_one_or_none() is None:
        raise ControlNotFound(control_id)

    existing_q = await session.execute(
        select(ComplianceControlAssessment).where(
            ComplianceControlAssessment.framework == framework,
            ComplianceControlAssessment.control_id == control_id,
        )
    )
    row = existing_q.scalar_one_or_none()
    note = (evidence_note or "").strip() or None
    url = (evidence_url or "").strip() or None
    if row is None:
        row = ComplianceControlAssessment(
            framework=framework,
            control_id=control_id,
            status=status,
            evidence_note=note,
            evidence_url=url,
            owner_user_id=owner,
            due_date=parsed_due,
            assessed_by_user_id=user_id,
        )
        session.add(row)
    else:
        row.status = status
        row.evidence_note = note
        row.evidence_url = url
        row.owner_user_id = owner
        row.due_date = parsed_due
        row.assessed_by_user_id = user_id
    await session.flush()
    return row


async def set_mapping_suppressed(
    session: AsyncSession,
    mapping_id: int,
    *,
    suppressed: bool,
    reason: str | None,
    user_id: str,
    asset_ids: list[str],
) -> ComplianceControlMapping | None:
    """Suppress or restore an auto-generated mapping.

    BOLA: returns None (→ 404, no enumeration) unless the mapping's finding is on
    an asset in the caller's scope. Suppressing excludes the mapping from a
    control's status/counts while keeping the row for the audit trail.
    """
    row = await session.get(ComplianceControlMapping, mapping_id)
    if row is None or row.finding_id is None:
        return None
    finding = await session.get(Finding, row.finding_id)
    if finding is None or finding.asset_id is None or finding.asset_id not in set(asset_ids):
        return None

    row.suppressed = suppressed
    if suppressed:
        row.suppressed_reason = (reason or "").strip() or None
        row.suppressed_by_user_id = user_id
        row.suppressed_at = datetime.now(timezone.utc)
    else:
        row.suppressed_reason = None
        row.suppressed_by_user_id = None
        row.suppressed_at = None
    await session.flush()
    return row


# Manual mappings assert a link the rule-based mapper missed. Its heuristic
# scores top out below 1.0, so a manual map is recorded at full confidence — but
# the `manual` column, not the score, is the source of truth for the distinction.
_MANUAL_MAPPING_CONFIDENCE = 1.0
_MANUAL_MAPPING_RATIONALE = "Mapped manually by an analyst"


async def create_manual_mapping(
    session: AsyncSession,
    framework: str,
    control_id: str,
    finding_id: int,
    *,
    asset_ids: list[str],
) -> tuple[ComplianceControlMapping, bool] | None:
    """Manually map a finding to a control.

    Returns ``(mapping, created)`` where ``created`` is False when an active
    mapping already existed (idempotent). A previously-suppressed mapping is
    restored and re-flagged manual. Raises FrameworkNotFound/ControlNotFound for
    an unknown target. BOLA: returns None (→ 404) when the finding is absent or
    on an asset outside the caller's scope, so ids can't be enumerated.
    """
    if await get_framework(session, framework) is None:
        raise FrameworkNotFound(framework)
    ctrl_q = await session.execute(
        select(FrameworkControl).where(
            FrameworkControl.framework == framework,
            FrameworkControl.control_id == control_id,
        )
    )
    if ctrl_q.scalar_one_or_none() is None:
        raise ControlNotFound(control_id)

    finding = await session.get(Finding, finding_id)
    if finding is None or finding.asset_id is None or finding.asset_id not in set(asset_ids):
        return None
    # Only live findings are evidence — mapping a dismissed/fixed one would
    # create a row that never displays or counts.
    if finding.state not in ("open", "deferred"):
        raise ValueError(
            f"finding {finding_id} is {finding.state}; only open or deferred findings can be mapped"
        )

    existing_q = await session.execute(
        select(ComplianceControlMapping).where(
            ComplianceControlMapping.finding_id == finding_id,
            ComplianceControlMapping.framework == framework,
            ComplianceControlMapping.control_id == control_id,
        )
    )
    row = existing_q.scalar_one_or_none()
    if row is not None:
        if not row.suppressed:
            return row, False
        # Re-adding a previously-suppressed mapping clears the suppression and
        # promotes it to a uniform manual row (matching the create path).
        row.suppressed = False
        row.suppressed_reason = None
        row.suppressed_by_user_id = None
        row.suppressed_at = None
        row.manual = True
        row.confidence = _MANUAL_MAPPING_CONFIDENCE
        row.rationale = _MANUAL_MAPPING_RATIONALE
        await session.flush()
        return row, True

    # Atomic insert-or-skip on the unique constraint: a concurrent map of the
    # same finding↔control can't produce a duplicate (which would double-count
    # the control). ON CONFLICT keeps the loser's request a clean idempotent
    # no-op instead of a 500.
    insert_stmt = (
        pg_insert(ComplianceControlMapping)
        .values(
            finding_id=finding_id,
            framework=framework,
            control_id=control_id,
            confidence=_MANUAL_MAPPING_CONFIDENCE,
            rationale=_MANUAL_MAPPING_RATIONALE,
            manual=True,
            suppressed=False,
        )
        .on_conflict_do_nothing(constraint="uq_compliance_mapping_finding_control")
        .returning(ComplianceControlMapping.id)
    )
    inserted_id = (await session.execute(insert_stmt)).scalar_one_or_none()
    if inserted_id is None:
        existing = (await session.execute(
            select(ComplianceControlMapping).where(
                ComplianceControlMapping.finding_id == finding_id,
                ComplianceControlMapping.framework == framework,
                ComplianceControlMapping.control_id == control_id,
            )
        )).scalar_one()
        return existing, False
    new_row = await session.get(ComplianceControlMapping, inserted_id)
    return new_row, True


async def search_mappable_findings(
    session: AsyncSession,
    framework: str,
    control_id: str,
    *,
    q: str | None,
    asset_ids: list[str],
    limit: int = 20,
) -> list[MappableFindingItem]:
    """Open, in-scope findings not already actively mapped to the control — the
    candidates the analyst can manually map. Free-text ``q`` matches the finding
    title or identity key (case-insensitive)."""
    if not asset_ids:
        return []

    from src.db.models import Asset

    # Exclude findings already actively mapped so the picker only offers
    # additions (a suppressed mapping is re-addable, so it isn't excluded).
    mapped_subq = (
        select(ComplianceControlMapping.finding_id)
        .where(
            ComplianceControlMapping.framework == framework,
            ComplianceControlMapping.control_id == control_id,
            ComplianceControlMapping.suppressed.is_(False),
            ComplianceControlMapping.finding_id.is_not(None),
        )
    )

    where = [
        Finding.asset_id.in_(asset_ids),
        Finding.state.in_(("open", "deferred")),
        Finding.id.not_in(mapped_subq),
    ]
    term = (q or "").strip()
    if term:
        # Escape LIKE wildcards so a literal "%" or "_" in the query matches
        # itself rather than acting as a pattern.
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{escaped}%"
        where.append(or_(
            Finding.title.ilike(like, escape="\\"),
            Finding.identity_key.ilike(like, escape="\\"),
        ))

    # Rank by real severity order (the column is a free string, so a plain sort
    # would misorder), surfacing the worst findings within the row limit.
    sev_rank = case(
        *((Finding.severity == sev, rank) for sev, rank in _SEV_RANK.items()),
        else_=99,
    )
    rows = await session.execute(
        select(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(*where)
        .order_by(sev_rank.asc(), Finding.id.desc())
        .limit(limit)
    )
    items = []
    for finding, asset in rows.all():
        org, repo = _org_repo_from_asset(asset)
        items.append(MappableFindingItem(
            id=finding.id,
            tool=finding.tool,
            title=finding.title,
            severity=finding.severity,
            org=org,
            repo=repo,
            identity_key=finding.identity_key,
        ))
    return items


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
            "manual_status": item.manual_status,
            "evidence_note": item.evidence_note,
            "evidence_url": item.evidence_url,
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


# Write-side CRUD helpers (custom frameworks + custom controls)


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


async def create_framework_with_controls(
    session: AsyncSession,
    *,
    framework_id: str,
    label: str,
    description: str | None,
    controls: list[dict],
    created_by_user_id: str,
) -> Framework:
    """Create a custom framework and its controls in a single transaction.

    Atomic: the whole batch is validated up front and added in one session, so any
    error (bad/duplicate control id, existing framework) leaves nothing persisted
    and a corrected resubmit is clean — no orphaned half-created framework.
    """
    _validate_framework_id(framework_id)
    if not label or not label.strip():
        raise ValueError("label is required")
    if await session.get(Framework, framework_id) is not None:
        raise FrameworkAlreadyExists(framework_id)

    # Validate + dedupe the control batch before inserting anything.
    seen: set[str] = set()
    cleaned: list[tuple[str, str, str | None, str | None]] = []
    for c in controls:
        cid = (c.get("control_id") or "").strip()
        ctitle = (c.get("title") or "").strip()
        _validate_control_id(cid)
        if not ctitle:
            raise ValueError(f"control {cid}: title is required")
        if cid in seen:
            raise ControlAlreadyExists(cid)
        seen.add(cid)
        cleaned.append((cid, ctitle, c.get("description"), c.get("category")))

    fw = Framework(
        id=framework_id,
        label=label.strip(),
        description=(description.strip() if description else None) or None,
        is_custom=True,
        created_by_user_id=created_by_user_id,
    )
    session.add(fw)
    for cid, ctitle, cdesc, ccat in cleaned:
        session.add(FrameworkControl(
            framework=framework_id,
            control_id=cid,
            title=ctitle,
            description=(cdesc.strip() if cdesc else None) or None,
            category=(ccat.strip() if ccat else None) or None,
            is_custom=True,
            created_by_user_id=created_by_user_id,
        ))
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
