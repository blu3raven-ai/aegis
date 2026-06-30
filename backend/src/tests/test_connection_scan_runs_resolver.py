"""Regression: sources.connectionScanRuns must surface connection-level runs.

A "Scan now" / scheduled sync fans out across every discovered repo in one
runner job, so its ScanRun row is born with ``asset_id`` NULL and is keyed only
by ``org_label`` in metadata. The pre-fix resolver matched on ``asset_id`` alone
(``NULL IN (...)`` is false in SQL), so these runs never appeared in the Scans
tab — it read "No scans yet" even while the source header showed "Scanning…".

These tests lock in the fixed contract against a real DB:
  * an org-level (NULL asset_id) manual run shows up for a caller who has scope
    on the connection,
  * the BOLA gate still holds — a caller with no in-scope asset under the
    connection sees nothing,
  * asset-bound runs (CI / BYO) keep resolving to their repo display name.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.db.models import Asset, ScanRun  # noqa: E402
from src.sources import scan_runs_resolvers  # noqa: E402

_ORG = "acme-org"


def _ctx(asset_ids: list[str]) -> dict:
    # has_permission is consulted inside _require_view_findings; patched per test.
    return {"request": object(), "asset_ids": asset_ids}


async def _seed_asset(session, *, repo: str = "widget", owner: str = _ORG) -> str:
    """Seed a source-connection repo asset tied to the connection by its
    external_ref owner — the linkage the resolver scopes on (source_ref is
    never populated for source-connection assets)."""
    asset_id = str(uuid.uuid4())
    session.add(Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        source_ref=None,
        external_ref=f"github:{owner}/{repo}",
        display_name=f"{owner}/{repo}",
    ))
    await session.flush()
    return asset_id


@pytest.mark.asyncio
async def test_connection_level_run_with_null_asset_id_is_returned(db_session):
    """An org-level manual run (asset_id NULL) appears once the caller has
    scope on the connection — the core regression."""
    connection_id = f"conn-{uuid.uuid4()}"
    asset_id = await _seed_asset(db_session)

    run_id = "manual-1750000000000-dependencies_scanning"
    db_session.add(ScanRun(
        id=run_id,
        tool="dependencies_scanning",
        asset_id=None,
        status="running",
        started_at=datetime.now(timezone.utc),
        metadata_json={"org_label": _ORG, "findingsCount": 7},
    ))
    await db_session.commit()

    try:
        with patch.object(scan_runs_resolvers, "_require_view_findings", return_value=None), \
             patch.object(
                 scan_runs_resolvers.sources_store, "get_connection",
                 return_value={"auth": {"orgOrOwner": _ORG}},
             ):
            runs = await scan_runs_resolvers.connection_scan_runs(
                connection_id=connection_id, limit=50, info_context=_ctx([asset_id]),
            )

        ids = {r.scan_id for r in runs}
        assert run_id in ids, "connection-level NULL-asset run must surface in the Scans tab"
        row = next(r for r in runs if r.scan_id == run_id)
        assert row.status == "running"
        assert row.findings_count == 7
        assert row.asset_name == "All repositories"
    finally:
        await _cleanup(db_session, run_ids=[run_id], asset_ids=[asset_id])


@pytest.mark.asyncio
async def test_no_connection_scope_hides_connection_level_run(db_session):
    """Caller with no in-scope asset under the connection sees nothing — the
    org-level run is not leaked by org_label alone."""
    connection_id = f"conn-{uuid.uuid4()}"
    # Asset exists but the caller's scope (below) does NOT include it.
    asset_id = await _seed_asset(db_session)

    run_id = "manual-1750000000001-secret_scanning"
    db_session.add(ScanRun(
        id=run_id,
        tool="secret_scanning",
        asset_id=None,
        status="running",
        started_at=datetime.now(timezone.utc),
        metadata_json={"org_label": _ORG},
    ))
    await db_session.commit()

    try:
        with patch.object(scan_runs_resolvers, "_require_view_findings", return_value=None), \
             patch.object(
                 scan_runs_resolvers.sources_store, "get_connection",
                 return_value={"auth": {"orgOrOwner": _ORG}},
             ):
            runs = await scan_runs_resolvers.connection_scan_runs(
                connection_id=connection_id, limit=50,
                info_context=_ctx([str(uuid.uuid4())]),  # unrelated asset id
            )
        assert runs == []
    finally:
        await _cleanup(db_session, run_ids=[run_id], asset_ids=[asset_id])


@pytest.mark.asyncio
async def test_asset_bound_run_resolves_to_repo_name(db_session):
    """Asset-bound runs (CI / BYO) keep resolving to the repo display name and
    are still returned alongside connection-level runs."""
    connection_id = f"conn-{uuid.uuid4()}"
    asset_id = await _seed_asset(db_session)

    run_id = f"scan-{uuid.uuid4()}"
    db_session.add(ScanRun(
        id=run_id,
        tool="dependencies_scanning",
        asset_id=asset_id,
        status="completed",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        metadata_json={"findings_count": 2},
    ))
    await db_session.commit()

    try:
        with patch.object(scan_runs_resolvers, "_require_view_findings", return_value=None), \
             patch.object(
                 scan_runs_resolvers.sources_store, "get_connection",
                 return_value={"auth": {"orgOrOwner": _ORG}},
             ):
            runs = await scan_runs_resolvers.connection_scan_runs(
                connection_id=connection_id, limit=50, info_context=_ctx([asset_id]),
            )
        row = next(r for r in runs if r.scan_id == run_id)
        assert row.asset_name == "acme-org/widget"
        assert row.findings_count == 2
    finally:
        await _cleanup(db_session, run_ids=[run_id], asset_ids=[asset_id])


@pytest.mark.asyncio
async def test_asset_in_other_org_does_not_grant_scope(db_session):
    """A granted source-connection asset whose external_ref owner differs from
    the connection's org must NOT establish scope — owner matching, not merely
    'any source_connection asset', is the gate."""
    asset_id = await _seed_asset(db_session, owner="other-org")  # not _ORG

    run_id = "manual-1750000000002-dependencies_scanning"
    db_session.add(ScanRun(
        id=run_id,
        tool="dependencies_scanning",
        asset_id=None,
        status="running",
        started_at=datetime.now(timezone.utc),
        metadata_json={"org_label": _ORG},
    ))
    await db_session.commit()

    try:
        with patch.object(scan_runs_resolvers, "_require_view_findings", return_value=None), \
             patch.object(
                 scan_runs_resolvers.sources_store, "get_connection",
                 return_value={"auth": {"orgOrOwner": _ORG}},
             ):
            runs = await scan_runs_resolvers.connection_scan_runs(
                connection_id=f"conn-{uuid.uuid4()}", limit=50,
                info_context=_ctx([asset_id]),
            )
        assert runs == []
    finally:
        await _cleanup(db_session, run_ids=[run_id], asset_ids=[asset_id])


async def _cleanup(session, *, run_ids: list[str], asset_ids: list[str]) -> None:
    from sqlalchemy import delete
    await session.execute(delete(ScanRun).where(ScanRun.id.in_(run_ids)))
    await session.execute(delete(Asset).where(Asset.id.in_(asset_ids)))
    await session.commit()
