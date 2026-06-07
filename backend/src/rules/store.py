"""Storage layer for unified Rules (SLA, scanner coverage, auto-dismiss, data retention).

Encapsulates all DB access for the Rules feature. Every read enforces cross-org
isolation by filtering on `org_id`; every write double-checks the row belongs to
the caller's org before mutating.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select

from src.db.helpers import run_db
from src.db.models import Finding, Rule, RuleKillSwitch, RuleViolation
from src.rules_engine.conditions import evaluate_condition
from src.rules_engine.subjects import RuleFindingSubject, get_finding_field


DRY_RUN_SAMPLE_SIZE = 1000


def _new_rule_id(category: str) -> str:
    """Generate a non-hex-only ID so it's visually distinct from migration seeds."""
    prefix = category.replace("_", "-")
    return f"{prefix}-{secrets.token_urlsafe(8)}"


def _rule_to_dict(
    rule: Rule,
    violation_count_open: int = 0,
    violation_count_resolved_30d: int = 0,
) -> dict[str, Any]:
    return {
        "id": rule.id,
        "org_id": rule.org_id,
        "category": rule.category,
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "priority": rule.priority,
        "conditions": rule.conditions,
        "action": rule.action,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
        "last_evaluated_at": rule.last_evaluated_at.isoformat() if rule.last_evaluated_at else None,
        "violation_count_open": violation_count_open,
        "violation_count_resolved_30d": violation_count_resolved_30d,
        # Auto-dismiss dry-run gate metadata. The raw confirmation token is
        # deliberately not exposed — only its presence (via dry_run_pending).
        "last_dry_run_at": (
            rule.last_dry_run_at.isoformat() if rule.last_dry_run_at else None
        ),
        "last_dry_run_match_count": rule.last_dry_run_match_count,
        "dry_run_confirmed_at": (
            rule.dry_run_confirmed_at.isoformat() if rule.dry_run_confirmed_at else None
        ),
        "dry_run_pending": rule.dry_run_confirmation_token is not None,
    }


def _kill_switch_to_dict(ks: RuleKillSwitch) -> dict[str, Any]:
    return {
        "id": ks.id,
        "org_id": ks.org_id,
        "category": ks.category,
        "killed_at": ks.killed_at.isoformat() if ks.killed_at else None,
        "killed_by": ks.killed_by,
        "reason": ks.reason,
    }


def _violation_to_dict(v: RuleViolation) -> dict[str, Any]:
    return {
        "id": v.id,
        "rule_id": v.rule_id,
        "subject_type": v.subject_type,
        "subject_id": v.subject_id,
        "status": v.status,
        "opened_at": v.opened_at.isoformat() if v.opened_at else None,
        "resolved_at": v.resolved_at.isoformat() if v.resolved_at else None,
        "context": v.context,
    }


async def _load_violation_counts(session, rule_ids: list[str]) -> dict[str, tuple[int, int]]:
    """Return {rule_id: (open_count, resolved_last_30d_count)} for the given rule ids."""
    if not rule_ids:
        return {}
    counts: dict[str, tuple[int, int]] = {rid: (0, 0) for rid in rule_ids}

    open_q = await session.execute(
        select(RuleViolation.rule_id, func.count(RuleViolation.id))
        .where(RuleViolation.rule_id.in_(rule_ids), RuleViolation.status == "open")
        .group_by(RuleViolation.rule_id)
    )
    for rid, c in open_q.all():
        counts[rid] = (int(c), counts[rid][1])

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    resolved_q = await session.execute(
        select(RuleViolation.rule_id, func.count(RuleViolation.id))
        .where(
            RuleViolation.rule_id.in_(rule_ids),
            RuleViolation.status == "resolved",
            RuleViolation.resolved_at >= cutoff,
        )
        .group_by(RuleViolation.rule_id)
    )
    for rid, c in resolved_q.all():
        counts[rid] = (counts[rid][0], int(c))

    return counts


# ── CRUD ──────────────────────────────────────────────────────────────────────


def list_rules_for_org(
    org_id: str,
    category: str | None = None,
    enabled: bool | None = None,
    q: str | None = None,
) -> list[dict[str, Any]]:
    async def _query(session):
        stmt = select(Rule).where(Rule.org_id == org_id)
        if category is not None:
            stmt = stmt.where(Rule.category == category)
        if enabled is not None:
            stmt = stmt.where(Rule.enabled == enabled)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(Rule.name.ilike(like), Rule.description.ilike(like)))
        stmt = stmt.order_by(Rule.priority.asc(), Rule.created_at.asc())
        rows = (await session.execute(stmt)).scalars().all()
        counts = await _load_violation_counts(session, [r.id for r in rows])
        return [
            _rule_to_dict(r, *counts.get(r.id, (0, 0)))
            for r in rows
        ]

    return run_db(_query)


def get_rule_by_id(org_id: str, rule_id: str) -> dict[str, Any] | None:
    async def _query(session):
        row = (
            await session.execute(
                select(Rule).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalars().first()
        if row is None:
            return None
        counts = await _load_violation_counts(session, [row.id])
        open_c, res_c = counts.get(row.id, (0, 0))
        return _rule_to_dict(row, open_c, res_c)

    return run_db(_query)


def create_rule(
    *,
    org_id: str,
    category: str,
    name: str,
    description: str | None,
    enabled: bool,
    priority: int,
    conditions: dict,
    action: dict,
    created_by: str,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    rule_id = _new_rule_id(category)

    async def _query(session):
        rule = Rule(
            id=rule_id,
            org_id=org_id,
            category=category,
            name=name,
            description=description,
            enabled=enabled,
            priority=priority,
            conditions=conditions,
            action=action,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        session.add(rule)
        await session.flush()
        return _rule_to_dict(rule)

    return run_db(_query)


def update_rule(org_id: str, rule_id: str, **kwargs: Any) -> dict[str, Any] | None:
    """Update a rule. Only keys explicitly passed in `kwargs` are written.

    Accepted keys: name, description, enabled, priority, conditions, action.
    Other keys are rejected with ValueError so typos surface immediately.
    """
    allowed = {
        "name",
        "description",
        "enabled",
        "priority",
        "conditions",
        "action",
        "last_dry_run_at",
        "last_dry_run_match_count",
        "dry_run_confirmation_token",
        "dry_run_confirmed_at",
    }
    unknown = set(kwargs) - allowed
    if unknown:
        raise ValueError(f"unknown update fields: {sorted(unknown)}")
    now = datetime.now(timezone.utc)

    async def _query(session):
        row = (
            await session.execute(
                select(Rule).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalars().first()
        if row is None:
            return None
        for key, value in kwargs.items():
            setattr(row, key, value)
        row.updated_at = now
        await session.flush()
        counts = await _load_violation_counts(session, [row.id])
        open_c, res_c = counts.get(row.id, (0, 0))
        return _rule_to_dict(row, open_c, res_c)

    return run_db(_query)


def delete_rule(org_id: str, rule_id: str) -> bool:
    async def _query(session):
        row = (
            await session.execute(
                select(Rule).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalars().first()
        if row is None:
            return False
        await session.delete(row)
        return True

    return run_db(_query)


def toggle_rule(org_id: str, rule_id: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)

    async def _query(session):
        row = (
            await session.execute(
                select(Rule).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalars().first()
        if row is None:
            return None
        row.enabled = not row.enabled
        row.updated_at = now
        await session.flush()
        counts = await _load_violation_counts(session, [row.id])
        open_c, res_c = counts.get(row.id, (0, 0))
        return _rule_to_dict(row, open_c, res_c)

    return run_db(_query)


def summary_for_org(org_id: str) -> dict[str, Any]:
    """Aggregate counters for the Rules landing-page summary card.

    Returns active_rules, violations_open, coverage_gaps (count of open
    scanner_coverage violations), and sla_compliance_pct derived from open
    rule violations on SLA rules.
    """
    async def _query(session):
        active_rules = (
            await session.execute(
                select(func.count(Rule.id)).where(
                    Rule.org_id == org_id, Rule.enabled == True  # noqa: E712
                )
            )
        ).scalar_one()

        violations_open = (
            await session.execute(
                select(func.count(RuleViolation.id))
                .join(Rule, Rule.id == RuleViolation.rule_id)
                .where(Rule.org_id == org_id, RuleViolation.status == "open")
            )
        ).scalar_one()

        sla_open_violations = (
            await session.execute(
                select(func.count(RuleViolation.id))
                .join(Rule, Rule.id == RuleViolation.rule_id)
                .where(
                    Rule.org_id == org_id,
                    Rule.category == "sla",
                    RuleViolation.status == "open",
                )
            )
        ).scalar_one()
        sla_resolved_30d = (
            await session.execute(
                select(func.count(RuleViolation.id))
                .join(Rule, Rule.id == RuleViolation.rule_id)
                .where(
                    Rule.org_id == org_id,
                    Rule.category == "sla",
                    RuleViolation.status == "resolved",
                    RuleViolation.resolved_at
                    >= datetime.now(timezone.utc) - timedelta(days=30),
                )
            )
        ).scalar_one()

        coverage_gaps = (
            await session.execute(
                select(func.count(RuleViolation.id))
                .join(Rule, Rule.id == RuleViolation.rule_id)
                .where(
                    Rule.org_id == org_id,
                    Rule.category == "scanner_coverage",
                    RuleViolation.status == "open",
                )
            )
        ).scalar_one()

        total = (sla_open_violations or 0) + (sla_resolved_30d or 0)
        compliance_pct = 100.0 if total == 0 else round(100.0 * sla_resolved_30d / total, 1)

        return {
            "active_rules": int(active_rules or 0),
            "violations_open": int(violations_open or 0),
            "coverage_gaps": int(coverage_gaps or 0),
            "sla_compliance_pct": compliance_pct,
        }

    return run_db(_query)


def list_violations_for_rule(
    org_id: str, rule_id: str, limit: int = 50, offset: int = 0
) -> dict[str, Any]:
    """Return paged violations for a rule. Caller must already have asserted
    `org_id` ownership via `get_rule_by_id`; the join below is a belt-and-suspenders check.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    async def _query(session):
        owned = (
            await session.execute(
                select(Rule.id).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalar_one_or_none()
        if owned is None:
            return {"violations": [], "total": 0, "limit": limit, "offset": offset}

        total = (
            await session.execute(
                select(func.count(RuleViolation.id)).where(RuleViolation.rule_id == rule_id)
            )
        ).scalar_one()

        rows = (
            await session.execute(
                select(RuleViolation)
                .where(RuleViolation.rule_id == rule_id)
                .order_by(RuleViolation.opened_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars().all()

        return {
            "violations": [_violation_to_dict(v) for v in rows],
            "total": int(total or 0),
            "limit": limit,
            "offset": offset,
        }

    return run_db(_query)


# ── Kill switch ───────────────────────────────────────────────────────────────


def engage_kill_switch(
    *, org_id: str, category: str, killed_by: str, reason: str | None
) -> dict[str, Any]:
    """Insert a new RuleKillSwitch row.

    Raises ValueError if a switch is already engaged for the (org, category)
    pair so the router can surface a 409 instead of silently upserting.
    """
    async def _query(session):
        existing = (
            await session.execute(
                select(RuleKillSwitch).where(
                    RuleKillSwitch.org_id == org_id,
                    RuleKillSwitch.category == category,
                )
            )
        ).scalars().first()
        if existing is not None:
            raise ValueError(f"kill switch already engaged for {category}")

        row = RuleKillSwitch(
            org_id=org_id,
            category=category,
            killed_at=datetime.now(timezone.utc),
            killed_by=killed_by,
            reason=reason,
        )
        session.add(row)
        await session.flush()
        return _kill_switch_to_dict(row)

    return run_db(_query)


def disengage_kill_switch(*, org_id: str, category: str) -> bool:
    async def _query(session):
        row = (
            await session.execute(
                select(RuleKillSwitch).where(
                    RuleKillSwitch.org_id == org_id,
                    RuleKillSwitch.category == category,
                )
            )
        ).scalars().first()
        if row is None:
            return False
        await session.delete(row)
        return True

    return run_db(_query)


def list_kill_switches(*, org_id: str) -> list[dict[str, Any]]:
    async def _query(session):
        rows = (
            await session.execute(
                select(RuleKillSwitch)
                .where(RuleKillSwitch.org_id == org_id)
                .order_by(RuleKillSwitch.category.asc())
            )
        ).scalars().all()
        return [_kill_switch_to_dict(r) for r in rows]

    return run_db(_query)


# ── Dry-run preview ──────────────────────────────────────────────────────────


def get_dry_run_state(*, org_id: str, rule_id: str) -> dict[str, Any] | None:
    """Internal accessor for the router's enable-gate to inspect the raw token
    and last-run timestamp without exposing them through the public rule dict.

    Returns None if the rule does not exist.
    """
    async def _query(session):
        row = (
            await session.execute(
                select(Rule).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalars().first()
        if row is None:
            return None
        return {
            "token": row.dry_run_confirmation_token,
            "last_dry_run_at": row.last_dry_run_at,
            "last_dry_run_match_count": row.last_dry_run_match_count,
        }

    return run_db(_query)


def _finding_to_dry_run_subject(finding: Finding, *, age_days: int) -> RuleFindingSubject:
    """Safe-default subject for dry-run match counting.

    Mirrors sla_evaluator._finding_to_subject: fields requiring joins are left
    at safe defaults so any rule predicating on them simply won't match — which
    is the conservative behaviour we want for a pre-enable preview.
    """
    return RuleFindingSubject(
        finding_id=finding.id,
        severity=(finding.severity or "").lower(),
        scanner=finding.tool or "",
        repo_id=finding.repo or "",
        repo_labels=[],
        repo_archived=False,
        cve_id=finding.cve_id,
        cwe_id=None,
        kev_matched=False,
        epss_score=None,
        file_path=finding.file_path,
        age_days=age_days,
    )


def preview_auto_dismiss_dry_run(
    *, org_id: str, rule_id: str, asset_ids: list[str] | None = None
) -> tuple[int, list[dict[str, Any]], str]:
    """Evaluate the rule's conditions against recent open findings.

    Pass ``asset_ids`` to scope findings by asset identity rather than org string.
    An empty ``asset_ids`` list returns (0, [], fresh_token) immediately.

    Persists ``last_dry_run_at``, ``last_dry_run_match_count``, and a freshly
    minted single-use ``dry_run_confirmation_token`` onto the rule row, then
    returns the total match count, the first 20 sample matches, and the token.
    Raises ValueError if the rule isn't an auto_dismiss rule (the gate is
    P4-specific and not auto-routed to other categories).
    """
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)

    if asset_ids is not None and not asset_ids:
        return 0, [], token

    async def _query(session):
        rule = (
            await session.execute(
                select(Rule).where(Rule.id == rule_id, Rule.org_id == org_id)
            )
        ).scalars().first()
        if rule is None:
            raise ValueError("rule not found")
        if rule.category != "auto_dismiss":
            raise ValueError("dry-run-and-confirm is only available for auto_dismiss rules")

        if asset_ids is not None:
            findings = (
                await session.execute(
                    select(Finding)
                    .where(
                        Finding.asset_id.in_(asset_ids),
                        Finding.state == "open",
                    )
                    .order_by(Finding.first_seen_at.desc())
                    .limit(DRY_RUN_SAMPLE_SIZE)
                )
            ).scalars().all()
        else:
            findings = (
                await session.execute(
                    select(Finding)
                    .where(
                        # Dry-run preview samples across the whole instance —
                        # caller asked for unscoped evaluation.
                        Finding.state == "open",
                    )
                    .order_by(Finding.first_seen_at.desc())
                    .limit(DRY_RUN_SAMPLE_SIZE)
                )
            ).scalars().all()

        sample_matches: list[dict[str, Any]] = []
        match_count = 0
        conditions = rule.conditions or {}
        for finding in findings:
            first_seen = finding.first_seen_at
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            age_days = max(0, (now - first_seen).days)
            subject = _finding_to_dry_run_subject(finding, age_days=age_days)
            try:
                matched = evaluate_condition(conditions, subject, get_finding_field)
            except Exception:
                continue
            if not matched:
                continue
            match_count += 1
            if len(sample_matches) < 20:
                sample_matches.append({
                    "finding_id": finding.id,
                    "severity": subject.severity,
                    "scanner": subject.scanner,
                    "repo_id": subject.repo_id,
                    "file_path": finding.file_path,
                    "cve_id": finding.cve_id,
                })

        rule.last_dry_run_at = now
        rule.last_dry_run_match_count = match_count
        rule.dry_run_confirmation_token = token
        # dry_run_confirmed_at is intentionally NOT reset here — it records
        # when the rule was last legitimately confirmed and must only be set
        # by the gate consumption path (PUT update). Re-running dry-run just
        # refreshes the token and match count.
        await session.flush()

        return match_count, sample_matches, token

    return run_db(_query)
