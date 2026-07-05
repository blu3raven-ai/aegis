"""Regression: home remediation stats query references the real findings column.

`get_remediation_stats_by_asset_ids` runs raw SQL against the `findings` table.
The fix-timestamp column is `fixed_at` (the `Finding` model has no `resolved_at`
— that column lives on `RuleViolation`). A stale `resolved_at` reference made the
query raise UndefinedColumn, which failed the whole Home dashboard query with
"Some data failed to load". This test exercises the SQL against the real schema
so the column name can't drift again unnoticed.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.db.models import Asset, Finding  # noqa: E402
from src.shared.home_views import get_remediation_stats_by_asset_ids  # noqa: E402


@pytest.mark.asyncio
async def test_remediation_stats_counts_fixed_findings(db_session):
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}",
        display_name="acme-org/widget",
    ))
    created = datetime.now(timezone.utc) - timedelta(days=2)
    db_session.add(Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid.uuid4()}",
        asset_id=asset_id,
        state="fixed",
        severity="high",
        created_at=created,
        fixed_at=created + timedelta(days=2),
    ))
    # An open finding on the same asset must not count toward remediation.
    db_session.add(Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid.uuid4()}",
        asset_id=asset_id,
        state="open",
        severity="low",
        created_at=created,
    ))
    await db_session.commit()

    try:
        stats = get_remediation_stats_by_asset_ids([asset_id])
        assert stats["total_fixed"] == 1
        assert stats["avg_days"] == 2.0
        assert stats["fixed_last_30d"] == 1
    finally:
        from sqlalchemy import delete
        await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_remediation_stats_empty_scope_short_circuits():
    assert get_remediation_stats_by_asset_ids([]) == {
        "total_fixed": 0, "avg_days": None, "median_days": None, "fixed_last_30d": 0,
    }
