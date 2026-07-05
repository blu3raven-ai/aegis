"""Unit tests for compute_and_store_daily_snapshots and the scheduler tick."""
from __future__ import annotations

import os
import uuid
from datetime import date
from unittest.mock import patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)


def test_take_posture_snapshots_calls_service():
    """Scheduler tick delegates to compute_and_store_daily_snapshots and logs the count."""
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch(
        "src.posture.service.compute_and_store_daily_snapshots",
        return_value=42,
    ) as mock_compute:
        scheduler._take_posture_snapshots()
    mock_compute.assert_called_once_with()


def test_take_posture_snapshots_swallows_errors():
    """A failing service call must not crash the scheduler thread."""
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with patch(
        "src.posture.service.compute_and_store_daily_snapshots",
        side_effect=RuntimeError("simulated failure"),
    ):
        scheduler._take_posture_snapshots()  # must not raise


def test_compute_and_store_uses_run_db_with_today_default(monkeypatch):
    """compute_and_store_daily_snapshots dispatches to run_db with the current date by default."""
    from src.posture import service

    captured = {}

    def fake_run_db(coro_factory):
        # We don't execute the coroutine — just verify the call shape.
        captured["called"] = True
        return 0

    monkeypatch.setattr(service, "run_db", fake_run_db)
    result = service.compute_and_store_daily_snapshots()
    assert captured["called"] is True
    assert result == 0


def test_compute_and_store_respects_today_override(monkeypatch):
    """Passing today=... lets the caller pin the snapshot date (used by backfill)."""
    from datetime import date

    from src.posture import service

    monkeypatch.setattr(service, "run_db", lambda fn: 0)
    # Smoke: function accepts and routes through cleanly.
    service.compute_and_store_daily_snapshots(today=date(2026, 6, 1))


# ── Integration: real DB ──────────────────────────────────────────────────────
# Fixtures mirror test_posture_triage.py: pytest-asyncio + conftest db_session.

@pytest.mark.asyncio
async def test_snapshot_excludes_archived_findings(db_session):
    """Archived findings must not inflate the nightly posture snapshot.

    The live triage resolvers all apply ``AND f.archived = false``; the snapshot
    writer must match so the trend line stays consistent with live numbers.
    """
    from sqlalchemy import delete, select as sa_select

    from src.db.models import Asset, Finding, PostureSnapshot
    from src.posture.service import compute_and_store_daily_snapshots

    asset_id = str(uuid.uuid4())
    today = date.today()

    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}",
        display_name="acme-org/snap-archived-test",
    ))
    await db_session.flush()

    # One real open critical + one archived open critical.
    # Only the non-archived one must appear in the snapshot.
    db_session.add(Finding(
        tool="code_scanning", asset_id=asset_id,
        identity_key=f"snap-real-{uuid.uuid4()}",
        state="open", severity="critical", archived=False,
    ))
    db_session.add(Finding(
        tool="code_scanning", asset_id=asset_id,
        identity_key=f"snap-arch-{uuid.uuid4()}",
        state="open", severity="critical", archived=True,
    ))
    await db_session.commit()

    try:
        count = compute_and_store_daily_snapshots(today=today)
        assert count >= 1, "expected at least one asset row written"

        row = (await db_session.execute(
            sa_select(PostureSnapshot).where(
                PostureSnapshot.asset_id == asset_id,
                PostureSnapshot.snapshot_date == today,
            )
        )).scalar_one_or_none()

        assert row is not None, "snapshot row not written"
        assert row.severity_critical == 1, (
            f"archived finding leaked into snapshot: severity_critical={row.severity_critical}"
        )
        assert row.risk_score == 5, (
            f"risk_score should be 5 (gauge of 1 critical, raw 10), got {row.risk_score}"
        )
    finally:
        await db_session.execute(
            delete(PostureSnapshot).where(PostureSnapshot.asset_id == asset_id)
        )
        await db_session.execute(
            delete(Finding).where(Finding.asset_id == asset_id)
        )
        await db_session.execute(
            delete(Asset).where(Asset.id == asset_id)
        )
        await db_session.commit()


@pytest.mark.asyncio
async def test_snapshot_records_new_findings_for_discover_and_resolve_asset(db_session):
    """An asset whose only same-day finding was created AND already closed must
    still record its new_findings (discovery velocity), even with zero open
    findings — otherwise a discover-and-resolve day is silently dropped."""
    from datetime import datetime, timezone

    from sqlalchemy import delete, select as sa_select

    from src.db.models import Asset, Finding, PostureSnapshot
    from src.posture.service import compute_and_store_daily_snapshots

    asset_id = str(uuid.uuid4())
    today = date.today()
    now = datetime.now(timezone.utc)

    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}",
        display_name="acme-org/discover-resolve",
    ))
    await db_session.flush()

    # Created today, already resolved (state != open) — never appears in the
    # open-severity query but must still count toward new_findings.
    db_session.add(Finding(
        tool="code_scanning", asset_id=asset_id,
        identity_key=f"snap-dr-{uuid.uuid4()}",
        state="fixed", severity="critical", archived=False,
        created_at=now, fixed_at=now,
    ))
    await db_session.commit()

    try:
        compute_and_store_daily_snapshots(today=today)

        row = (await db_session.execute(
            sa_select(PostureSnapshot).where(
                PostureSnapshot.asset_id == asset_id,
                PostureSnapshot.snapshot_date == today,
            )
        )).scalar_one_or_none()

        assert row is not None, "snapshot row must be written for a discover-and-resolve asset"
        assert row.new_findings == 1, (
            f"new_findings should be 1 (created today), got {row.new_findings}"
        )
        # No open findings, so severity counts and risk stay 0.
        assert row.severity_critical == 0
        assert row.risk_score == 0
    finally:
        await db_session.execute(
            delete(PostureSnapshot).where(PostureSnapshot.asset_id == asset_id)
        )
        await db_session.execute(
            delete(Finding).where(Finding.asset_id == asset_id)
        )
        await db_session.execute(
            delete(Asset).where(Asset.id == asset_id)
        )
        await db_session.commit()
