"""sbom_component_vulns returns per-(package, version) open-finding severity
counts for a single repo, scoped to the caller's asset grants. Findings with no
resolved version land in the version=None (name-level) bucket."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding  # noqa: E402
from src.sbom.resolvers import sbom_component_vulns  # noqa: E402


async def _seed(db_session) -> tuple[str, str]:
    """Seed one repo asset whose open findings span two packages, plus noise
    that must be excluded: a fixed finding and a finding with no package_name."""
    asset_id = str(uuid.uuid4())
    display_name = f"acme-org/{uuid.uuid4().hex}"
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=display_name,
    ))
    await db_session.flush()
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-A"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="high", package_name="log4j", cve_id="CVE-B"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="medium", package_name="lodash", cve_id="CVE-D"),
        # Fixed finding — excluded (only open findings count).
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="fixed", severity="critical", package_name="log4j", cve_id="CVE-C"),
        # No package_name (e.g. a code/secret finding) — excluded from the overlay.
        Finding(tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="high", package_name=None, cve_id=None),
    ])
    await db_session.commit()
    return asset_id, display_name


async def _cleanup(db_session, asset_id: str) -> None:
    await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_aggregates_open_findings_per_package(db_session):
    asset_id, display_name = await _seed(db_session)
    try:
        rows = sbom_component_vulns(repo=display_name, info_context={"asset_ids": [asset_id]})
        by_name = {r.package_name: r.vulns for r in rows}
        assert by_name["log4j"].critical == 1
        assert by_name["log4j"].high == 1
        assert by_name["log4j"].total == 2  # fixed finding excluded
        assert by_name["lodash"].medium == 1
        assert by_name["lodash"].total == 1
        # The package_name-less finding produces no entry.
        assert None not in by_name
        assert len(rows) == 2
        # These findings carry no resolved version → the name-level bucket.
        assert all(r.package_version is None for r in rows)
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_splits_counts_per_version(db_session):
    # Two versions of one package + one finding with no resolved version.
    asset_id = str(uuid.uuid4())
    display_name = f"acme-org/{uuid.uuid4().hex}"
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=display_name,
    ))
    await db_session.flush()
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="critical", package_name="vllm", package_version="0.5.0", cve_id="CVE-1"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="high", package_name="vllm", package_version="0.6.0", cve_id="CVE-2"),
        # No resolved version — lands in the version=None (name-level) bucket.
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
                state="open", severity="low", package_name="vllm", package_version=None, cve_id="CVE-3"),
    ])
    await db_session.commit()
    try:
        rows = sbom_component_vulns(repo=display_name, info_context={"asset_ids": [asset_id]})
        by_ver = {r.package_version: r.vulns for r in rows}
        assert set(by_ver) == {"0.5.0", "0.6.0", None}
        assert by_ver["0.5.0"].critical == 1 and by_ver["0.5.0"].total == 1
        assert by_ver["0.6.0"].high == 1 and by_ver["0.6.0"].total == 1
        assert by_ver[None].low == 1 and by_ver[None].total == 1
        assert all(r.package_name == "vllm" for r in rows)
        assert len(rows) == 3
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_out_of_scope_repo_returns_empty(db_session):
    # A caller scoped elsewhere sees nothing — counts never leak cross-tenant.
    asset_id, display_name = await _seed(db_session)
    try:
        rows = sbom_component_vulns(repo=display_name, info_context={"asset_ids": [str(uuid.uuid4())]})
        assert rows == []
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_unknown_repo_returns_empty(db_session):
    asset_id, _ = await _seed(db_session)
    try:
        rows = sbom_component_vulns(repo="acme-org/does-not-exist", info_context={"asset_ids": [asset_id]})
        assert rows == []
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_empty_scope_returns_empty(db_session):
    asset_id, display_name = await _seed(db_session)
    try:
        assert sbom_component_vulns(repo=display_name, info_context={"asset_ids": []}) == []
    finally:
        await _cleanup(db_session, asset_id)
