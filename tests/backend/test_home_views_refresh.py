"""Tests for the event-driven home dashboard MV refresh worker.

Tests 1-3: pure asyncio worker behaviour — no DB required.
Tests 4-7: verify that the 4 lifecycle write paths call
           request_home_views_refresh() after their DB transaction.
           These run against testcontainers Postgres (conftest.py).
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from sqlalchemy import delete as sa_delete

from src.db.helpers import run_db
from src.db.models import Decision, Finding
from src.shared.finding_queries import upsert_decision
from src.shared.lifecycle import (
    LifecycleHooks,
    ScanContext,
    apply_lifecycle,
    bulk_dismiss,
    dismiss_finding,
    reopen_finding,
)


# ---------------------------------------------------------------------------
# Minimal hooks for lifecycle integration tests
# ---------------------------------------------------------------------------

class _MinimalHooks(LifecycleHooks):
    tool = "code_scanning"

    def compute_identity_key(self, raw: dict) -> str:
        return raw.get("key", "")

    def initial_state(self, raw: dict) -> str:
        return "open"

    def extract_repo(self, raw: dict) -> str | None:
        return raw.get("repo", "acme-org/api")

    def extract_severity(self, raw: dict) -> str | None:
        return raw.get("severity", "high")

    def extract_detail(self, raw: dict) -> dict:
        return raw.get("detail", {})

    def canonical_external_ref(self, ctx, raw) -> tuple[str, str] | None:
        # Org-scoped path: findings keep asset_id NULL, so apply_lifecycle
        # resolves them via the unconditional asset_id-IS-NULL prefetch.
        return None


_HOOKS = _MinimalHooks()
_TOOL = "code_scanning"


def _clean(keys: list[str]) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(
                Finding.tool == _TOOL, Finding.identity_key.in_(keys)
            )
        )
        await session.execute(
            sa_delete(Decision).where(
                Decision.tool == _TOOL, Decision.identity_key.in_(keys)
            )
        )
    run_db(_del)


def _seed_open_finding(key: str) -> None:
    async def _q(session):
        f = Finding(
            tool=_TOOL,
            asset_id=None,
            identity_key=key,
            state="open",
            severity="high",
            detail={},
        )
        session.add(f)
    run_db(_q)


def _seed_dismissed_finding(key: str) -> None:
    async def _q(session):
        f = Finding(
            tool=_TOOL,
            asset_id=None,
            identity_key=key,
            state="dismissed",
            severity="high",
            detail={},
        )
        session.add(f)
        await session.flush()
        await upsert_decision(
            session, tool=_TOOL, asset_id=None, identity_key=key,
            status="dismissed", reason="Risk is tolerable", decided_by="tester",
        )
    run_db(_q)


# ---------------------------------------------------------------------------
# Worker behaviour tests (pure asyncio, no DB)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_request_refresh_sets_event_when_loop_running():
    """request_home_views_refresh sets the internal event when a loop is running."""
    import src.shared.home_views_refresher as _mod

    # Reset module-level event so this test is isolated
    _mod._refresh_event = None

    from src.shared.home_views_refresher import request_home_views_refresh, _get_event

    request_home_views_refresh()
    # call_soon_threadsafe schedules the callback; yield to the loop to process it
    await asyncio.sleep(0)

    event = _get_event()
    assert event.is_set()

    # Cleanup
    event.clear()
    _mod._refresh_event = None


@pytest.mark.asyncio
async def test_worker_debounces_rapid_requests():
    """10 rapid requests coalesce into exactly 1 refresh call."""
    import src.shared.home_views_refresher as _mod
    _mod._refresh_event = None

    call_count = 0

    def _fake_refresh():
        nonlocal call_count
        call_count += 1

    with patch("src.shared.home_views_refresher.refresh_all_home_views", _fake_refresh):
        from src.shared.home_views_refresher import (
            home_views_refresh_worker,
            request_home_views_refresh,
        )

        task = asyncio.create_task(home_views_refresh_worker(debounce=0.05))

        # Fire 10 rapid requests within 0.01s
        for _ in range(10):
            request_home_views_refresh()
            await asyncio.sleep(0.001)

        # Wait long enough for one debounced cycle to complete
        await asyncio.sleep(0.2)

        assert call_count == 1

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    _mod._refresh_event = None


@pytest.mark.asyncio
async def test_worker_survives_refresh_failure():
    """Worker logs the error and retries on the next trigger; no crash."""
    import src.shared.home_views_refresher as _mod
    _mod._refresh_event = None

    call_count = 0

    def _flaky_refresh():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("simulated refresh failure")

    with patch("src.shared.home_views_refresher.refresh_all_home_views", _flaky_refresh):
        from src.shared.home_views_refresher import (
            home_views_refresh_worker,
            request_home_views_refresh,
        )

        task = asyncio.create_task(home_views_refresh_worker(debounce=0.02))

        # First request — will fail
        request_home_views_refresh()
        await asyncio.sleep(0.15)
        assert call_count == 1  # ran once, raised

        # Second request — should succeed
        request_home_views_refresh()
        await asyncio.sleep(0.15)
        assert call_count == 2  # ran again, no exception escaped

        # Task is still alive (no crash)
        assert not task.done()

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    _mod._refresh_event = None


# ---------------------------------------------------------------------------
# Lifecycle integration tests — verify refresh is triggered
# ---------------------------------------------------------------------------

def test_apply_lifecycle_triggers_refresh():
    """apply_lifecycle calls request_home_views_refresh after DB work."""
    org = "refresh-apply-lifecycle"
    key = "lifecycle-k1"
    _clean([key])
    # Seed an existing finding so apply_lifecycle takes the update path,
    # avoiding the upsert_finding → compliance auto-mapper code path
    # (which queries compliance_control_mappings, absent in the test schema).
    _seed_open_finding(key)

    with patch(
        "src.shared.lifecycle.request_home_views_refresh"
    ) as mock_refresh:
        ctx = ScanContext(
            tool=_TOOL, org=org, run_id="run-test", source_type="source_connection"
        )
        apply_lifecycle(_HOOKS, ctx, [{"key": key}])

    mock_refresh.assert_called_once()


def test_dismiss_finding_triggers_refresh():
    """dismiss_finding calls request_home_views_refresh after DB work."""
    org = "refresh-dismiss"
    key = "dismiss-key"
    _clean([key])
    _seed_open_finding(key)

    with patch(
        "src.shared.lifecycle.request_home_views_refresh"
    ) as mock_refresh:
        dismiss_finding(
            tool=_TOOL,
            org=org,
            identity_key=key,
            reason="Risk is tolerable",
            user_id="tester",
        )

    mock_refresh.assert_called_once()


def test_reopen_finding_triggers_refresh():
    """reopen_finding calls request_home_views_refresh after DB work."""
    org = "refresh-reopen"
    key = "reopen-key"
    _clean([key])
    _seed_dismissed_finding(key)

    with patch(
        "src.shared.lifecycle.request_home_views_refresh"
    ) as mock_refresh:
        reopen_finding(tool=_TOOL, org=org, identity_key=key, user_id="tester")

    mock_refresh.assert_called_once()


def test_bulk_dismiss_triggers_refresh():
    """bulk_dismiss calls request_home_views_refresh after DB work."""
    org = "refresh-bulk-dismiss"
    keys = ["bulk-k1", "bulk-k2"]
    _clean(keys)
    for k in keys:
        _seed_open_finding(k)

    with patch(
        "src.shared.lifecycle.request_home_views_refresh"
    ) as mock_refresh:
        count = bulk_dismiss(
            tool=_TOOL,
            org=org,
            identity_keys=keys,
            reason="Risk is tolerable",
            user_id="tester",
        )

    assert count == 2
    mock_refresh.assert_called_once()
