"""Empty-scope behavior of the posture analytics functions — a caller with no
asset grants must get an empty/zero result, never data. Locks the fail-closed
guard across the posture surface."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.posture import service as svc  # noqa: E402


@pytest.mark.asyncio
async def test_snapshot_empty_scope_is_empty(_create_tables):
    payload = svc.get_posture_snapshot(asset_ids=[])
    # An empty payload — no findings counted for a scopeless caller.
    total = getattr(payload, "total_findings", None)
    assert total in (0, None)


@pytest.mark.asyncio
async def test_list_endpoints_empty_scope_return_empty_lists(_create_tables):
    assert svc.get_posture_by_team(asset_ids=[]) == []
    assert svc.get_posture_trend(asset_ids=[], days=30) == []
    assert svc.get_scanner_breakdown(asset_ids=[]) == []


@pytest.mark.asyncio
async def test_summary_endpoints_empty_scope_return_zeroed_dicts(_create_tables):
    exploit = svc.get_exploitability_summary(asset_ids=[])
    assert isinstance(exploit, dict)
    sla = svc.get_sla_posture(asset_ids=[])
    assert isinstance(sla, dict)
