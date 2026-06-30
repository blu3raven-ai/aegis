"""sbom_search overlays open-finding severity counts per component (joined on
asset_id + package_name) and can filter to vulnerable components only."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding, Sbom, SbomComponent  # noqa: E402
from src.sbom.resolvers import sbom_search  # noqa: E402


async def _seed(db_session) -> str:
    """Seed one asset with a vulnerable component (log4j: 1 critical + 1 high
    open, plus 1 fixed that must NOT count) and a clean component (lodash)."""
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.flush()
    db_session.add(Sbom(asset_id=asset_id, run_id=f"auto-{uuid.uuid4().hex}", s3_key=f"k/{uuid.uuid4().hex}"))
    db_session.add(SbomComponent(
        asset_id=asset_id, purl="pkg:maven/org.apache/log4j@2.14.1",
        name="log4j", version="2.14.1", ecosystem="maven", source_tool="syft",
    ))
    db_session.add(SbomComponent(
        asset_id=asset_id, purl="pkg:npm/lodash@4.17.21",
        name="lodash", version="4.17.21", ecosystem="npm", source_tool="syft",
    ))
    await db_session.flush()
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-A"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="high", package_name="log4j", cve_id="CVE-B"),
        # Fixed finding — excluded from the overlay (only open counts).
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="fixed", severity="critical", package_name="log4j", cve_id="CVE-C"),
    ])
    await db_session.commit()
    return asset_id


async def _cleanup(db_session, asset_id: str) -> None:
    await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
    await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == asset_id))
    await db_session.execute(delete(Sbom).where(Sbom.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_overlays_open_finding_counts(db_session):
    asset_id = await _seed(db_session)
    try:
        conn = sbom_search(info_context={"asset_ids": [asset_id]})
        by_name = {c.name: c for c in conn.items}
        assert by_name["log4j"].vulns.critical == 1
        assert by_name["log4j"].vulns.high == 1
        assert by_name["log4j"].vulns.total == 2  # the fixed finding is excluded
        assert by_name["lodash"].vulns.total == 0
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_vulnerable_only_filters_clean_components(db_session):
    asset_id = await _seed(db_session)
    try:
        conn = sbom_search(vulnerable_only=True, info_context={"asset_ids": [asset_id]})
        names = {c.name for c in conn.items}
        assert "log4j" in names
        assert "lodash" not in names
        assert conn.total == 1
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_scope_isolation(db_session):
    # A caller scoped elsewhere sees nothing — counts never leak cross-tenant.
    asset_id = await _seed(db_session)
    try:
        conn = sbom_search(info_context={"asset_ids": [str(uuid.uuid4())]})
        assert conn.items == []
    finally:
        await _cleanup(db_session, asset_id)
