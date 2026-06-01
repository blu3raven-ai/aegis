"""Unit tests for ActivityService.list_recent.

All DB calls are mocked so no real Postgres is required.
Tests cover: empty result, type filter, repo filter, scan/finding/audit
union, pagination (has_more + next_cursor), and cursor decode robustness.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from src.activity.service import (  # noqa: E402
    ActivityService,
    ActivityEvent,
    SUPPORTED_TYPES,
    _encode_cursor,
    _decode_cursor,
    _finding_event_type,
    _scan_summary,
    _audit_event_type,
    _wants,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(delta_hours: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=delta_hours)


def _make_activity_event(id_: str, evt_type: str, hours_ago: int = 1) -> ActivityEvent:
    return ActivityEvent(
        id=id_,
        type=evt_type,
        occurred_at=_ts(hours_ago),
        actor="system",
        repo_id="acme-org/api",
        summary="test event",
        payload={},
    )


# ── _finding_event_type ───────────────────────────────────────────────────────

def test_finding_event_type_dismissed():
    assert _finding_event_type(None, "dismissed") == "finding.dismissed"


def test_finding_event_type_fixed():
    assert _finding_event_type("open", "fixed") == "finding.fixed"


def test_finding_event_type_reopened():
    assert _finding_event_type("dismissed", "open") == "finding.reopened"


def test_finding_event_type_created():
    assert _finding_event_type(None, "open") == "finding.created"


# ── _scan_summary ─────────────────────────────────────────────────────────────

def test_scan_summary_completed_with_findings():
    assert "3 new finding" in _scan_summary("dependencies", "completed", {"new_findings": 3})


def test_scan_summary_completed_no_findings():
    summary = _scan_summary("code_scanning", "completed", {})
    assert "completed" in summary


def test_scan_summary_failed():
    assert "failed" in _scan_summary("secrets", "failed", {})


# ── _audit_event_type ─────────────────────────────────────────────────────────

def test_audit_event_type_integration_connected():
    assert _audit_event_type("integration.connected") == "integration.connected"


def test_audit_event_type_integration_removed():
    assert _audit_event_type("integration.removed") == "integration.disconnected"


def test_audit_event_type_sla_breached():
    assert _audit_event_type("sla.breached") == "sla.breached"


def test_audit_event_type_kev_added():
    assert _audit_event_type("kev.added") == "kev.added"


def test_audit_event_type_unknown():
    assert _audit_event_type("user.login") == "unknown"


# ── _wants ────────────────────────────────────────────────────────────────────

def test_wants_none_types_returns_true():
    assert _wants(None, {"finding.created"}) is True


def test_wants_matching_type():
    assert _wants(["finding.created", "scan.completed"], {"finding.created"}) is True


def test_wants_no_match():
    assert _wants(["scan.completed"], {"finding.created"}) is False


# ── cursor encode/decode ──────────────────────────────────────────────────────

def test_cursor_roundtrip():
    ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    encoded = _encode_cursor(ts, 42, "activity")
    decoded_ts, decoded_id, decoded_src = _decode_cursor(encoded)
    assert decoded_ts == ts
    assert decoded_id == "42"
    assert decoded_src == "activity"


def test_cursor_decode_invalid_returns_none():
    ts, row_id, src = _decode_cursor("not-valid-base64!!!")
    assert ts is None
    assert row_id is None


# ── ActivityService.list_recent ───────────────────────────────────────────────

def _patch_service_query(events: list[ActivityEvent]):
    """Patch the internal _query coroutine to return the given events."""
    async def _fake_query(session, **kwargs):
        return events

    return patch.object(ActivityService, "_query", new=_fake_query)


def test_list_recent_empty():
    with _patch_service_query([]):
        with patch("src.activity.service.run_db", return_value=[]):
            svc = ActivityService()
            events, cursor = svc.list_recent("acme-org")
    assert events == []
    assert cursor is None


def test_list_recent_returns_events():
    fake_events = [
        _make_activity_event("fe-1", "finding.created", 1),
        _make_activity_event("fe-2", "scan.completed", 2),
    ]

    def fake_run_db(coro_fn):
        import asyncio
        return asyncio.get_event_loop().run_until_complete(_run_coro(coro_fn))

    async def _run_coro(coro_fn):
        session = MagicMock()
        svc = ActivityService()
        return await svc._query(
            session,
            org_id="acme-org",
            types=None,
            repo_id=None,
            since=None,
            until=None,
            limit=10,
            cursor_at=None,
        )

    with patch.object(ActivityService, "_query", AsyncMock(return_value=fake_events)):
        with patch("src.activity.service.run_db") as mock_run_db:
            mock_run_db.return_value = fake_events
            svc = ActivityService()
            events, cursor = svc.list_recent("acme-org", limit=10)

    assert len(events) == 2
    assert events[0].type == "finding.created"


def test_list_recent_pagination_has_more():
    """When the DB returns limit+1 rows, next_cursor must be set."""
    # Create limit+1 events to simulate there being more pages.
    fake_events = [
        _make_activity_event(f"fe-{i}", "finding.created", i)
        for i in range(6)   # 5 requested + 1 extra
    ]

    with patch.object(ActivityService, "_query", AsyncMock(return_value=fake_events)):
        with patch("src.activity.service.run_db", return_value=fake_events):
            svc = ActivityService()
            events, cursor = svc.list_recent("acme-org", limit=5)

    assert len(events) == 5
    assert cursor is not None


def test_list_recent_no_more_pages():
    """When fewer rows than limit are returned, next_cursor is None."""
    fake_events = [
        _make_activity_event(f"fe-{i}", "finding.created", i)
        for i in range(3)
    ]

    with patch.object(ActivityService, "_query", AsyncMock(return_value=fake_events)):
        with patch("src.activity.service.run_db", return_value=fake_events):
            svc = ActivityService()
            events, cursor = svc.list_recent("acme-org", limit=10)

    assert len(events) == 3
    assert cursor is None


def test_list_recent_type_filter_passed_through():
    """types list must be forwarded to run_db's coro_fn correctly."""
    # We intercept run_db and call the coroutine ourselves to capture kwargs.
    import asyncio
    called_with: dict = {}

    async def _fake_query(session, **kwargs):
        called_with.update(kwargs)
        return []

    # Patch run_db to invoke the lambda with a mock session and capture kwargs.
    def _mock_run_db(coro_fn):
        session = MagicMock()
        # coro_fn is a lambda wrapping ActivityService._query — call it.
        # We override _query to capture kwargs instead.
        return asyncio.get_event_loop().run_until_complete(coro_fn(session))

    with patch.object(ActivityService, "_query", new=lambda self, session, **kw: _fake_query(session, **kw)):
        with patch("src.activity.service.run_db", side_effect=_mock_run_db):
            svc = ActivityService()
            svc.list_recent("acme-org", types=["finding.created", "scan.completed"])

    assert called_with.get("types") == ["finding.created", "scan.completed"]


def test_list_recent_repo_filter_passed_through():
    import asyncio
    called_with: dict = {}

    async def _fake_query(session, **kwargs):
        called_with.update(kwargs)
        return []

    def _mock_run_db(coro_fn):
        session = MagicMock()
        return asyncio.get_event_loop().run_until_complete(coro_fn(session))

    with patch.object(ActivityService, "_query", new=lambda self, session, **kw: _fake_query(session, **kw)):
        with patch("src.activity.service.run_db", side_effect=_mock_run_db):
            svc = ActivityService()
            svc.list_recent("acme-org", repo_id="my-repo")

    assert called_with.get("repo_id") == "my-repo"


def test_supported_types_list():
    assert "finding.created" in SUPPORTED_TYPES
    assert "scan.completed" in SUPPORTED_TYPES
    assert "integration.connected" in SUPPORTED_TYPES
    assert "kev.added" in SUPPORTED_TYPES
    assert "sla.breached" in SUPPORTED_TYPES
