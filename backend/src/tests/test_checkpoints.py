"""Contract tests for per-asset scan checkpoints + coverage-gap computation.

write_checkpoint/read_checkpoints_for_tool/compute_coverage_gaps back the
scanner-coverage view: which assets are missing a scanner or went stale. These
run against the real DB (the helpers use run_db); assets are seeded via the test
session, which shares the same Postgres.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Asset, ScanCheckpoint
from src.shared.checkpoints import (
    compute_coverage_gaps,
    read_checkpoints_for_tool,
    write_checkpoint,
)

_TOOL = "dependencies_scanning"


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


@pytest_asyncio.fixture
async def assets(db_session):
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for i, aid in enumerate(ids):
        db_session.add(Asset(
            id=aid, type="repo", source="source_connection",
            external_ref=f"github:acme/repo{i}-{aid[:8]}",
            display_name=f"acme/repo{i}", asset_metadata={},
        ))
    await db_session.commit()
    yield ids
    await db_session.execute(delete(ScanCheckpoint).where(ScanCheckpoint.asset_id.in_(ids)))
    await db_session.execute(delete(Asset).where(Asset.id.in_(ids)))
    await db_session.commit()


@pytest.mark.asyncio
async def test_write_and_read_checkpoint(assets):
    a = assets[0]
    write_checkpoint(_TOOL, a, commit_sha="abc123", scanned_at=_iso(datetime.now(timezone.utc)))
    cps = read_checkpoints_for_tool(_TOOL, [a])
    assert cps[a]["lastCommitSha"] == "abc123"
    assert cps[a]["lastScannedAt"]


@pytest.mark.asyncio
async def test_write_checkpoint_upserts(assets):
    a = assets[0]
    write_checkpoint(_TOOL, a, commit_sha="first")
    write_checkpoint(_TOOL, a, commit_sha="second")
    cps = read_checkpoints_for_tool(_TOOL, [a])
    assert cps[a]["lastCommitSha"] == "second"  # updated in place, not duplicated
    assert list(cps.keys()) == [a]


@pytest.mark.asyncio
async def test_coverage_gaps_missing_stale_and_covered(assets):
    fresh, stale, missing = assets
    now = datetime.now(timezone.utc)
    write_checkpoint(_TOOL, fresh, scanned_at=_iso(now))
    write_checkpoint(_TOOL, stale, scanned_at=_iso(now - timedelta(days=40)))
    # `missing` intentionally has no checkpoint.

    gaps = {g["assetId"]: g for g in compute_coverage_gaps(_TOOL, assets, stale_after_days=30)}

    assert fresh not in gaps  # recently scanned -> covered
    assert gaps[stale]["reason"] == "stale"
    assert gaps[missing]["reason"] == "missing_checkpoint"
    assert gaps[missing]["repository"] == "acme/repo2"  # display name carried through


@pytest.mark.asyncio
async def test_unparseable_date_counts_as_stale(db_session, assets):
    a = assets[0]
    db_session.add(ScanCheckpoint(tool=_TOOL, asset_id=a, last_commit_sha="x", last_commit_date="not-a-date"))
    await db_session.commit()
    gaps = compute_coverage_gaps(_TOOL, [a], stale_after_days=30)
    assert {g["assetId"]: g["reason"] for g in gaps} == {a: "stale"}


@pytest.mark.asyncio
async def test_empty_inputs(assets):
    assert compute_coverage_gaps(_TOOL, []) == []
    assert read_checkpoints_for_tool(_TOOL, []) == {}
