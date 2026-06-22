"""Unit tests for HistoryService.list_recent.

All DB calls are mocked so no real Postgres is required.
Tests cover: empty result, type filter, repo filter, scan/finding
union, pagination (has_more + next_cursor), and cursor decode robustness.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.history.service import (  # noqa: E402
    HistoryService,
    HistoryEvent,
    SUPPORTED_TYPES,
    _encode_cursor,
    _decode_cursor,
    _finding_event_type,
    _scan_summary,
    _wants,
)



def _ts(delta_hours: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=delta_hours)


def _make_history_event(id_: str, evt_type: str, hours_ago: int = 1) -> HistoryEvent:
    return HistoryEvent(
        id=id_,
        type=evt_type,
        occurred_at=_ts(hours_ago),
        actor="system",
        repo_id="acme-org/api",
        summary="test event",
        payload={},
    )



def test_finding_event_type_dismissed():
    assert _finding_event_type(None, "dismissed") == "finding.dismissed"


def test_finding_event_type_fixed():
    assert _finding_event_type("open", "fixed") == "finding.fixed"


def test_finding_event_type_reopened():
    assert _finding_event_type("dismissed", "open") == "finding.reopened"


def test_finding_event_type_created():
    assert _finding_event_type(None, "open") == "finding.created"



def test_scan_summary_completed_with_findings():
    assert "3 new finding" in _scan_summary("dependencies_scanning", "completed", {"new_findings": 3})


def test_scan_summary_completed_no_findings():
    summary = _scan_summary("code_scanning", "completed", {})
    assert "completed" in summary


def test_scan_summary_failed():
    assert "failed" in _scan_summary("secret_scanning", "failed", {})


def test_scan_summary_cancelled():
    assert "cancelled" in _scan_summary("dependencies_scanning", "cancelled", {})



def test_wants_none_types_returns_true():
    assert _wants(None, {"finding.created"}) is True


def test_wants_matching_type():
    assert _wants(["finding.created", "scan.completed"], {"finding.created"}) is True


def test_wants_no_match():
    assert _wants(["scan.completed"], {"finding.created"}) is False



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



def _patch_service_query(events: list[HistoryEvent]):
    """Patch the internal _query coroutine to return the given events."""
    async def _fake_query(session, **kwargs):
        return events

    return patch.object(HistoryService, "_query", new=_fake_query)


def test_list_recent_empty():
    with _patch_service_query([]):
        with patch("src.history.service.run_db", return_value=[]):
            svc = HistoryService()
            events, cursor = svc.list_recent(asset_ids=["a1"])
    assert events == []
    assert cursor is None


def test_list_recent_returns_events():
    fake_events = [
        _make_history_event("fe-1", "finding.created", 1),
        _make_history_event("fe-2", "scan.completed", 2),
    ]

    def fake_run_db(coro_fn):
        import asyncio
        return asyncio.get_event_loop().run_until_complete(_run_coro(coro_fn))

    async def _run_coro(coro_fn):
        session = MagicMock()
        svc = HistoryService()
        return await svc._query(
            session,
            asset_ids=["a1"],
            types=None,
            repo_id=None,
            since=None,
            until=None,
            limit=10,
            cursor_at=None,
        )

    with patch.object(HistoryService, "_query", AsyncMock(return_value=fake_events)):
        with patch("src.history.service.run_db") as mock_run_db:
            mock_run_db.return_value = fake_events
            svc = HistoryService()
            events, cursor = svc.list_recent(asset_ids=["a1"], limit=10)

    assert len(events) == 2
    assert events[0].type == "finding.created"


def test_list_recent_pagination_has_more():
    """When the DB returns limit+1 rows, next_cursor must be set."""
    # Create limit+1 events to simulate there being more pages.
    fake_events = [
        _make_history_event(f"fe-{i}", "finding.created", i)
        for i in range(6)   # 5 requested + 1 extra
    ]

    with patch.object(HistoryService, "_query", AsyncMock(return_value=fake_events)):
        with patch("src.history.service.run_db", return_value=fake_events):
            svc = HistoryService()
            events, cursor = svc.list_recent(asset_ids=["a1"], limit=5)

    assert len(events) == 5
    assert cursor is not None


def test_list_recent_no_more_pages():
    """When fewer rows than limit are returned, next_cursor is None."""
    fake_events = [
        _make_history_event(f"fe-{i}", "finding.created", i)
        for i in range(3)
    ]

    with patch.object(HistoryService, "_query", AsyncMock(return_value=fake_events)):
        with patch("src.history.service.run_db", return_value=fake_events):
            svc = HistoryService()
            events, cursor = svc.list_recent(asset_ids=["a1"], limit=10)

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
        # coro_fn is a lambda wrapping HistoryService._query — call it.
        # We override _query to capture kwargs instead.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro_fn(session))
        finally:
            loop.close()

    with patch.object(HistoryService, "_query", new=lambda self, session, **kw: _fake_query(session, **kw)):
        with patch("src.history.service.run_db", side_effect=_mock_run_db):
            svc = HistoryService()
            svc.list_recent(asset_ids=["a1"], types=["finding.created", "scan.completed"])

    assert called_with.get("types") == ["finding.created", "scan.completed"]


def test_list_recent_repo_filter_passed_through():
    import asyncio
    called_with: dict = {}

    async def _fake_query(session, **kwargs):
        called_with.update(kwargs)
        return []

    def _mock_run_db(coro_fn):
        session = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro_fn(session))
        finally:
            loop.close()

    with patch.object(HistoryService, "_query", new=lambda self, session, **kw: _fake_query(session, **kw)):
        with patch("src.history.service.run_db", side_effect=_mock_run_db):
            svc = HistoryService()
            svc.list_recent(asset_ids=["a1"], repo_id="my-repo")

    assert called_with.get("repo_id") == "my-repo"


def test_supported_types_list():
    assert "finding.created" in SUPPORTED_TYPES
    assert "finding.dismissed" in SUPPORTED_TYPES
    assert "finding.fixed" in SUPPORTED_TYPES
    assert "finding.reopened" in SUPPORTED_TYPES
    assert "scan.completed" in SUPPORTED_TYPES
    assert "scan.failed" in SUPPORTED_TYPES
    assert "scan.cancelled" in SUPPORTED_TYPES


def _fake_scan_session(run):
    """Session stub whose execute().scalars().all() yields the given run(s)."""
    from types import SimpleNamespace

    runs = run if isinstance(run, list) else [run]

    class _Result:
        def scalars(self):
            return SimpleNamespace(all=lambda: runs)

    class _Session:
        async def execute(self, *_a, **_k):
            return _Result()

    return _Session()


def _fake_run(status: str):
    from types import SimpleNamespace

    return SimpleNamespace(
        id="scan-1",
        status=status,
        tool="dependencies_scanning",
        finished_at=_ts(1),
        started_at=_ts(2),
        metadata_json={"repo": "acme-org/api"},
    )


def test_query_scan_runs_maps_cancelled_to_scan_cancelled():
    """A cancelled ScanRun surfaces as a scan.cancelled history event."""
    import asyncio

    async def _run():
        return await HistoryService()._query_scan_runs(
            _fake_scan_session(_fake_run("cancelled")),
            asset_ids=["a1"], types=None, repo_id=None,
            since=None, until=None, cursor_at=None, limit=10,
        )

    events = asyncio.run(_run())
    assert len(events) == 1
    assert events[0].type == "scan.cancelled"
    assert "cancelled" in events[0].summary


def test_query_scan_runs_occurred_at_falls_back_to_started_at():
    """A cancelled run with no finished_at still surfaces, timed at started_at."""
    import asyncio
    from types import SimpleNamespace

    started = _ts(3)
    run = SimpleNamespace(
        id="scan-2", status="cancelled", tool="code_scanning",
        finished_at=None, started_at=started, metadata_json={},
    )

    async def _run():
        return await HistoryService()._query_scan_runs(
            _fake_scan_session(run),
            asset_ids=["a1"], types=None, repo_id=None,
            since=None, until=None, cursor_at=None, limit=10,
        )

    events = asyncio.run(_run())
    assert len(events) == 1
    assert events[0].type == "scan.cancelled"
    assert events[0].occurred_at == started


def test_query_scan_runs_type_filter_excludes_cancelled_when_unrequested():
    """Filtering to scan.completed must drop a cancelled run."""
    import asyncio

    async def _run():
        return await HistoryService()._query_scan_runs(
            _fake_scan_session(_fake_run("cancelled")),
            asset_ids=["a1"], types=["scan.completed"], repo_id=None,
            since=None, until=None, cursor_at=None, limit=10,
        )

    assert asyncio.run(_run()) == []


def test_supported_types_excludes_audit_events():
    """Audit-driven signals surface in /settings/audit, not the activity feed."""
    for forbidden in (
        "integration.connected",
        "integration.disconnected",
        "kev.added",
        "sla.breached",
        "intel.cve.added",
    ):
        assert forbidden not in SUPPORTED_TYPES


def test_list_recent_empty_asset_ids_short_circuits():
    """Empty asset_ids returns ([], None) without touching the DB — fail-closed."""
    with patch("src.history.service.run_db") as mock_run_db:
        svc = HistoryService()
        events, cursor = svc.list_recent(asset_ids=[])
    assert events == []
    assert cursor is None
    assert mock_run_db.call_count == 0
