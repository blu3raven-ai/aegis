"""Integration tests for the scanner coverage rule evaluator.

These tests exercise ``evaluate_scanner_coverage_for_org`` against the test
Postgres container because the evaluator's behaviour depends on real
partial-unique-index upserts, JSONB roundtrips, and condition evaluation
against rows from the ``repos`` + ``scan_runs`` tables.

Event bus dispatch is patched via ``src.shared.event_bus.get_event_bus`` —
the evaluator imports it lazily inside ``_dispatch_stale_alert`` so the
patch resolves at call time.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import Repo, Rule, RuleViolation, ScanRun
from src.rules.scanner_coverage_evaluator import evaluate_scanner_coverage_for_org


_ORG = "org-scov-evaluator"


# ── Cleanup fixture ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(
            delete(RuleViolation).where(
                RuleViolation.rule_id.in_(
                    select(Rule.id).where(Rule.org_id == _ORG)
                )
            )
        )
        await session.execute(delete(Rule).where(Rule.org_id == _ORG))
        await session.execute(delete(Repo).where(Repo.org == _ORG))
        await session.execute(delete(ScanRun).where(ScanRun.org == _ORG))

    run_db(_del)
    yield
    run_db(_del)


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_repo(
    *,
    org_id: str = _ORG,
    repo: str,
    tier: str | None = None,
    archived: bool = False,
    labels: list[str] | None = None,
    image_registry: str | None = None,
) -> None:
    async def _insert(session):
        session.add(Repo(
            org=org_id,
            repo=repo,
            tier=tier,
            archived=archived,
            labels=labels,
            image_registry=image_registry,
        ))

    run_db(_insert)


def _seed_scanner_coverage_rule(
    *,
    org_id: str = _ORG,
    rule_id: str | None = None,
    action: dict,
    conditions: dict | None = None,
    enabled: bool = True,
    name: str | None = None,
) -> str:
    rid = rule_id or f"scov-{action.get('type', 'rule')}-{abs(hash(repr(action))) % 10_000_000}"
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(Rule(
            id=rid,
            org_id=org_id,
            category="scanner_coverage",
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
    tool: str,
    status: str = "completed",
    finished_at: datetime | None = None,
) -> None:
    async def _insert(session):
        session.add(ScanRun(
            id=f"sr-{tool}-{datetime.now(timezone.utc).timestamp()}",
            tool=tool,
            org=org_id,
            status=status,
            finished_at=finished_at or datetime.now(timezone.utc),
        ))

    run_db(_insert)


def _open_violations_for(rule_id: str) -> list[RuleViolation]:
    async def _q(session):
        rows = (
            await session.execute(
                select(RuleViolation).where(
                    RuleViolation.rule_id == rule_id,
                    RuleViolation.status == "open",
                )
            )
        ).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)

    return run_db(_q)


def _all_violations_for(rule_id: str) -> list[RuleViolation]:
    async def _q(session):
        rows = (
            await session.execute(
                select(RuleViolation).where(RuleViolation.rule_id == rule_id)
            )
        ).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)

    return run_db(_q)


def _get_rule(rule_id: str) -> Rule:
    async def _q(session):
        r = await session.get(Rule, rule_id)
        if r is not None:
            session.expunge(r)
        return r

    return run_db(_q)


def _update_repo(*, repo: str, **fields) -> None:
    async def _u(session):
        row = (
            await session.execute(
                select(Repo).where(Repo.org == _ORG, Repo.repo == repo)
            )
        ).scalar_one()
        for k, v in fields.items():
            setattr(row, k, v)

    run_db(_u)


# ── require_scanners ─────────────────────────────────────────────────────────


def test_require_scanners_opens_violation_when_missing():
    _seed_repo(repo="api", tier="production")
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "require_scanners",
            "required_scanners": ["dependencies", "secrets"],
        },
    )

    result = evaluate_scanner_coverage_for_org(_ORG)

    assert result.violations_opened == 1
    violations = _open_violations_for(rule_id)
    assert len(violations) == 1
    assert violations[0].subject_type == "repo"
    assert violations[0].subject_id == f"{_ORG}/api"
    assert violations[0].context["missing_scanners"] == ["dependencies", "secrets"]


def test_require_scanners_resolves_violation_when_coverage_added():
    _seed_repo(repo="api", tier="production")
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "require_scanners",
            "required_scanners": ["dependencies", "secrets"],
        },
    )

    evaluate_scanner_coverage_for_org(_ORG)
    assert len(_open_violations_for(rule_id)) == 1

    _seed_scan_run(tool="dependencies")
    _seed_scan_run(tool="secrets")

    result = evaluate_scanner_coverage_for_org(_ORG)
    assert result.violations_resolved == 1
    assert _open_violations_for(rule_id) == []

    all_v = _all_violations_for(rule_id)
    assert len(all_v) == 1
    assert all_v[0].status == "resolved"
    assert all_v[0].resolved_at is not None


def test_require_scanners_no_match_resolves_violation():
    _seed_repo(repo="api", tier="production")
    _seed_repo(repo="docs", tier="production")
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "require_scanners",
            "required_scanners": ["dependencies"],
        },
        conditions={"field": "tier", "op": "eq", "value": "production"},
    )

    evaluate_scanner_coverage_for_org(_ORG)
    assert len(_open_violations_for(rule_id)) == 2

    _update_repo(repo="api", tier="staging")

    result = evaluate_scanner_coverage_for_org(_ORG)
    assert result.violations_resolved == 1

    open_v = _open_violations_for(rule_id)
    assert len(open_v) == 1
    assert open_v[0].subject_id == f"{_ORG}/docs"


# ── stale_alert ──────────────────────────────────────────────────────────────


def test_stale_alert_dispatches_once_per_fresh_open():
    _seed_repo(repo="api", tier="production")
    _seed_scan_run(
        tool="dependencies",
        finished_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "stale_alert",
            "stale_after_days": 7,
            "alert_channel_id": 1,
            "auto_retrigger": False,
        },
    )

    mock_bus = MagicMock()
    with patch("src.shared.event_bus.get_event_bus", return_value=mock_bus):
        result = evaluate_scanner_coverage_for_org(_ORG)

    assert result.violations_opened == 1
    assert result.stale_alerts_dispatched == 1
    assert len(_open_violations_for(rule_id)) == 1

    stale_calls = [
        c for c in mock_bus.publish_sync.call_args_list
        if c.args[0].event_type == "rule.scanner_coverage.stale_alert"
    ]
    assert len(stale_calls) == 1

    # Second run with no state change — no new event.
    mock_bus.reset_mock()
    with patch("src.shared.event_bus.get_event_bus", return_value=mock_bus):
        result2 = evaluate_scanner_coverage_for_org(_ORG)

    assert result2.violations_opened == 0
    assert result2.stale_alerts_dispatched == 0
    assert mock_bus.publish_sync.call_count == 0


def test_stale_alert_does_not_dispatch_on_subsequent_runs():
    _seed_repo(repo="api", tier="production")
    _seed_scan_run(
        tool="dependencies",
        finished_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    _seed_scanner_coverage_rule(
        action={
            "type": "stale_alert",
            "stale_after_days": 7,
            "alert_channel_id": 1,
        },
    )

    mock_bus = MagicMock()
    with patch("src.shared.event_bus.get_event_bus", return_value=mock_bus):
        evaluate_scanner_coverage_for_org(_ORG)
        evaluate_scanner_coverage_for_org(_ORG)
        evaluate_scanner_coverage_for_org(_ORG)

    stale_calls = [
        c for c in mock_bus.publish_sync.call_args_list
        if c.args[0].event_type == "rule.scanner_coverage.stale_alert"
    ]
    assert len(stale_calls) == 1


def test_stale_alert_auto_retrigger_enqueues_scan():
    _seed_repo(repo="api", tier="production")
    _seed_scan_run(
        tool="dependencies",
        finished_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "stale_alert",
            "stale_after_days": 7,
            "alert_channel_id": 1,
            "auto_retrigger": True,
        },
    )

    mock_bus = MagicMock()
    with patch("src.shared.event_bus.get_event_bus", return_value=mock_bus):
        evaluate_scanner_coverage_for_org(_ORG)

    event_types = [c.args[0].event_type for c in mock_bus.publish_sync.call_args_list]
    assert event_types.count("rule.scanner_coverage.stale_alert") == 1
    assert event_types.count("rule.scanner_coverage.retrigger_scan") == 1

    retrigger_event = next(
        c.args[0] for c in mock_bus.publish_sync.call_args_list
        if c.args[0].event_type == "rule.scanner_coverage.retrigger_scan"
    )
    assert retrigger_event.data["rule_id"] == rule_id
    assert retrigger_event.data["repo_id"] == f"{_ORG}/api"
    assert retrigger_event.data["source"] == "rule.stale_alert"


# ── Edge cases ───────────────────────────────────────────────────────────────


def test_archived_repos_excluded():
    _seed_repo(repo="legacy", tier="production", archived=True)
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "require_scanners",
            "required_scanners": ["dependencies"],
        },
    )

    result = evaluate_scanner_coverage_for_org(_ORG)

    assert result.violations_opened == 0
    assert _open_violations_for(rule_id) == []


def test_evaluator_skips_disabled_rule():
    _seed_repo(repo="api", tier="production")
    rule_id = _seed_scanner_coverage_rule(
        enabled=False,
        action={
            "type": "require_scanners",
            "required_scanners": ["dependencies"],
        },
    )

    result = evaluate_scanner_coverage_for_org(_ORG)

    assert result.violations_opened == 0
    assert _open_violations_for(rule_id) == []


def test_evaluator_marks_last_evaluated_at():
    _seed_repo(repo="api", tier="production")
    rule_id = _seed_scanner_coverage_rule(
        action={
            "type": "require_scanners",
            "required_scanners": ["dependencies"],
        },
    )

    assert _get_rule(rule_id).last_evaluated_at is None
    before = datetime.now(timezone.utc) - timedelta(seconds=1)

    evaluate_scanner_coverage_for_org(_ORG)

    rule_after = _get_rule(rule_id)
    assert rule_after.last_evaluated_at is not None
    last_eval = rule_after.last_evaluated_at
    if last_eval.tzinfo is None:
        last_eval = last_eval.replace(tzinfo=timezone.utc)
    assert last_eval >= before
