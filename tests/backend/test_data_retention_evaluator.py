"""Integration tests for the data-retention rule evaluator.

These tests exercise ``evaluate_data_retention_for_org`` against the test
Postgres container because the evaluator mutates ScanRun rows, writes
AuditEvent rows, and relies on the archived-filter SQL helpers — all of
which are clunky to mock.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import AuditEvent, Finding, Rule, ScanRun
from src.rules.data_retention_evaluator import evaluate_data_retention_for_org


_ORG = "org-dataret-evaluator"


# ── Cleanup fixture ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(delete(AuditEvent).where(AuditEvent.org_id == _ORG))
        await session.execute(delete(Rule).where(Rule.org_id == _ORG))
        await session.execute(delete(ScanRun).where(ScanRun.org == _ORG))
        await session.execute(delete(Finding).where(Finding.org == _ORG))

    run_db(_del)
    yield
    run_db(_del)


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_data_retention_rule(
    *,
    org_id: str = _ORG,
    rule_id: str | None = None,
    action: dict,
    conditions: dict | None = None,
    enabled: bool = True,
    name: str | None = None,
) -> str:
    rid = rule_id or f"dr-{action.get('type', 'rule')}-{abs(hash(repr(action))) % 10_000_000}"
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(Rule(
            id=rid,
            org_id=org_id,
            category="data_retention",
            name=name or rid,
            description=None,
            enabled=enabled,
            priority=100,
            conditions=conditions or {},
            action=action,
            created_by="test-user",
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)
    return rid


def _seed_scan_run(
    *,
    org_id: str = _ORG,
    tool: str = "dependencies",
    status: str = "completed",
    finished_at: datetime | None = None,
    archived: bool = False,
    scan_id: str | None = None,
    metadata: dict | None = None,
) -> str:
    sid = scan_id or f"sr-{tool}-{datetime.now(timezone.utc).timestamp()}"

    async def _insert(session):
        session.add(ScanRun(
            id=sid,
            tool=tool,
            org=org_id,
            status=status,
            finished_at=finished_at,
            archived=archived,
            metadata_json=metadata,
        ))

    run_db(_insert)
    return sid


def _seed_finding(
    *,
    org_id: str = _ORG,
    tool: str = "dependencies",
    identity_key: str | None = None,
    archived: bool = False,
) -> int:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        f = Finding(
            tool=tool,
            org=org_id,
            repo="repo-1",
            identity_key=identity_key or f"key-{now.timestamp()}",
            state="open",
            severity="high",
            first_seen_at=now,
            last_seen_at=now,
            detail={},
            archived=archived,
            created_at=now,
            updated_at=now,
        )
        session.add(f)
        await session.flush()
        return f.id

    return run_db(_insert)


def _get_scan_run(scan_id: str) -> ScanRun | None:
    async def _q(session):
        row = await session.get(ScanRun, scan_id)
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _get_finding(finding_id: int) -> Finding | None:
    async def _q(session):
        row = await session.get(Finding, finding_id)
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _get_rule(rule_id: str) -> Rule | None:
    async def _q(session):
        row = await session.get(Rule, rule_id)
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _audit_events_for(resource_id: str) -> list[AuditEvent]:
    async def _q(session):
        rows = (
            await session.execute(
                select(AuditEvent).where(
                    AuditEvent.org_id == _ORG,
                    AuditEvent.resource_type == "scan_run",
                    AuditEvent.resource_id == resource_id,
                )
            )
        ).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)

    return run_db(_q)


# ── archive ──────────────────────────────────────────────────────────────────


def test_archive_rule_archives_scan_run_after_threshold():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=400))
    rule_id = _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.archived == 1
    assert result.deleted == 0
    assert result.rules_evaluated == 1
    assert result.scans_checked == 1

    row = _get_scan_run(scan_id)
    assert row is not None
    assert row.archived is True
    assert row.archived_at is not None
    assert row.archived_by_rule_id == rule_id


def test_archive_rule_does_not_archive_below_threshold():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=400))
    _seed_data_retention_rule(
        action={"type": "archive", "after_days": 500},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.archived == 0
    row = _get_scan_run(scan_id)
    assert row is not None
    assert row.archived is False
    assert row.archived_at is None


def test_archive_does_not_cascade_to_findings():
    """V1 decision: archive on a ScanRun does NOT flip Finding.archived."""
    now = datetime.now(timezone.utc)
    _seed_scan_run(finished_at=now - timedelta(days=400))
    finding_id = _seed_finding()
    _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
    )

    evaluate_data_retention_for_org(_ORG, now=now)

    finding = _get_finding(finding_id)
    assert finding is not None
    assert finding.archived is False
    assert finding.archived_at is None
    assert finding.archived_by_rule_id is None


def test_archive_logs_audit_event():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=400))
    rule_id = _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
    )

    evaluate_data_retention_for_org(_ORG, now=now)

    events = _audit_events_for(scan_id)
    assert len(events) == 1
    ev = events[0]
    assert ev.action == "rule.data_retention.archived"
    assert ev.org_id == _ORG
    assert ev.resource_type == "scan_run"
    assert ev.resource_id == scan_id
    assert ev.actor_role == "system"
    assert ev.actor_username == f"auto-rule:{rule_id}"
    assert ev.metadata_json["rule_id"] == rule_id


# ── delete ───────────────────────────────────────────────────────────────────


def test_delete_rule_deletes_scan_run_after_threshold():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=400))
    _seed_data_retention_rule(
        action={"type": "delete", "after_days": 365},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.deleted == 1
    assert result.archived == 0
    assert _get_scan_run(scan_id) is None


def test_delete_preserves_findings():
    """V1 decision: delete on a ScanRun does NOT touch Finding rows."""
    now = datetime.now(timezone.utc)
    _seed_scan_run(finished_at=now - timedelta(days=400))
    finding_id = _seed_finding()
    _seed_data_retention_rule(
        action={"type": "delete", "after_days": 365},
    )

    evaluate_data_retention_for_org(_ORG, now=now)

    finding = _get_finding(finding_id)
    assert finding is not None
    assert finding.archived is False


def test_delete_logs_audit_event_before_deletion():
    """Audit row must survive the same-transaction delete of the ScanRun."""
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=400))
    rule_id = _seed_data_retention_rule(
        action={"type": "delete", "after_days": 365},
    )

    evaluate_data_retention_for_org(_ORG, now=now)

    assert _get_scan_run(scan_id) is None  # row is gone
    events = _audit_events_for(scan_id)
    assert len(events) == 1
    ev = events[0]
    assert ev.action == "rule.data_retention.deleted"
    assert ev.org_id == _ORG
    assert ev.resource_type == "scan_run"
    assert ev.resource_id == scan_id
    assert ev.metadata_json["rule_id"] == rule_id
    assert "deleted_at" in ev.metadata_json


# ── prefilter & skip behaviour ───────────────────────────────────────────────


def test_evaluator_skips_already_archived_runs():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(
        finished_at=now - timedelta(days=400),
        archived=True,
    )
    _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.archived == 0
    assert result.scans_checked == 0
    # No fresh audit event for an already-archived run.
    assert _audit_events_for(scan_id) == []


def test_evaluator_skips_disabled_rule():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=400))
    _seed_data_retention_rule(
        enabled=False,
        action={"type": "archive", "after_days": 365},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.rules_evaluated == 0
    assert result.archived == 0
    row = _get_scan_run(scan_id)
    assert row is not None
    assert row.archived is False


def test_evaluator_returns_zero_when_no_rules():
    now = datetime.now(timezone.utc)
    _seed_scan_run(finished_at=now - timedelta(days=400))

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.rules_evaluated == 0
    assert result.scans_checked == 0
    assert result.archived == 0
    assert result.deleted == 0


def test_evaluator_respects_prefilter_30d_minimum():
    """ScanRuns younger than 30 days are not loaded by the evaluator.

    The action schema enforces after_days >= 30 for archive (and >= 90 for
    delete) so a recent ScanRun cannot satisfy any well-formed rule. The
    evaluator uses this fact for a coarse prefilter that keeps the working
    set small.
    """
    now = datetime.now(timezone.utc)
    fresh_scan = _seed_scan_run(finished_at=now - timedelta(days=10))
    old_scan = _seed_scan_run(finished_at=now - timedelta(days=400))
    _seed_data_retention_rule(
        action={"type": "archive", "after_days": 30},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    # Prefilter cutoff is at least 30d — fresh_scan must be excluded.
    assert result.scans_checked == 1
    fresh = _get_scan_run(fresh_scan)
    assert fresh is not None
    assert fresh.archived is False
    old = _get_scan_run(old_scan)
    assert old is not None
    assert old.archived is True


def test_archive_rule_fires_at_exact_after_days_boundary():
    """A scan finished exactly after_days ago must match.

    Guards against an off-by-one in the SQL prefilter: ``finished_at`` equal
    to ``now - after_days`` produces ``age_days == after_days``, which the
    in-loop check (``age_days < after_days → continue``) admits.
    """
    now = datetime.now(timezone.utc)
    boundary_days = 30
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=boundary_days))
    rule_id = _seed_data_retention_rule(
        action={"type": "archive", "after_days": boundary_days},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.scans_checked == 1
    assert result.archived == 1
    row = _get_scan_run(scan_id)
    assert row is not None
    assert row.archived is True
    assert row.archived_by_rule_id == rule_id


def test_evaluator_only_runs_on_completed_scans():
    now = datetime.now(timezone.utc)
    running = _seed_scan_run(
        finished_at=now - timedelta(days=400),
        status="running",
    )
    failed = _seed_scan_run(
        finished_at=now - timedelta(days=400),
        status="failed",
    )
    completed = _seed_scan_run(
        finished_at=now - timedelta(days=400),
        status="completed",
    )
    _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.scans_checked == 1
    assert result.archived == 1
    assert _get_scan_run(running).archived is False
    assert _get_scan_run(failed).archived is False
    assert _get_scan_run(completed).archived is True


def test_evaluator_rule_priority_first_match_wins():
    """Break after first matching rule fires — exactly one action per scan."""
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(finished_at=now - timedelta(days=500))
    _seed_data_retention_rule(
        rule_id="rule-archive",
        action={"type": "archive", "after_days": 365},
    )
    _seed_data_retention_rule(
        rule_id="rule-delete",
        action={"type": "delete", "after_days": 400},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    # Both rules match by age. Exactly ONE action fires per scan.
    assert result.archived + result.deleted == 1
    events = _audit_events_for(scan_id)
    assert len(events) == 1


def test_evaluator_skips_non_matching_conditions():
    now = datetime.now(timezone.utc)
    scan_id = _seed_scan_run(
        finished_at=now - timedelta(days=400),
        tool="dependencies_scanning",
    )
    _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
        conditions={"field": "tool", "op": "eq", "value": "secrets"},
    )

    result = evaluate_data_retention_for_org(_ORG, now=now)

    assert result.archived == 0
    row = _get_scan_run(scan_id)
    assert row is not None
    assert row.archived is False


def test_evaluator_last_evaluated_at_updated():
    now = datetime.now(timezone.utc)
    _seed_scan_run(finished_at=now - timedelta(days=400))
    rule_id = _seed_data_retention_rule(
        action={"type": "archive", "after_days": 365},
    )
    assert _get_rule(rule_id).last_evaluated_at is None

    evaluate_data_retention_for_org(_ORG, now=now)

    rule_after = _get_rule(rule_id)
    assert rule_after is not None
    assert rule_after.last_evaluated_at is not None
    last_eval = rule_after.last_evaluated_at
    if last_eval.tzinfo is None:
        last_eval = last_eval.replace(tzinfo=timezone.utc)
    assert last_eval == now
