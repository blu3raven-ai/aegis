"""sbom_package_repos returns the in-scope repositories affected by a package's
open vulnerabilities, with per-repo severity, worst-first."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding  # noqa: E402
from src.sbom.resolvers import sbom_package_repos  # noqa: E402


async def _seed(db_session) -> tuple[str, str, str]:
    """Two repos + one container image with open log4j findings (api: 1 critical
    + 1 high; web: 1 medium; img: 1 critical), plus a fixed finding and a
    different package that must be excluded."""
    a = str(uuid.uuid4())
    b = str(uuid.uuid4())
    c = str(uuid.uuid4())
    db_session.add_all([
        Asset(id=a, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api"),
        Asset(id=b, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/web"),
        Asset(id=c, type="image", source="source_connection",
              external_ref=f"ghcr:acme-org/{uuid.uuid4().hex}:latest", display_name="acme-org/img"),
    ])
    await db_session.flush()
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-A"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="high", package_name="log4j", cve_id="CVE-B"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="medium", package_name="log4j", cve_id="CVE-C"),
        Finding(tool="container_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=c,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-IMG"),
        # Excluded: fixed finding + a different package.
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="fixed", severity="critical", package_name="log4j", cve_id="CVE-D"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="low", package_name="lodash", cve_id="CVE-E"),
    ])
    await db_session.commit()
    return a, b, c


async def _cleanup(db_session, *asset_ids: str) -> None:
    for aid in asset_ids:
        await db_session.execute(delete(Finding).where(Finding.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_returns_affected_repos_worst_first(db_session):
    a, b, c = await _seed(db_session)
    try:
        rows = sbom_package_repos(package_name="log4j", info_context={"asset_ids": [a, b, c]})
        # Worst-first: api (2 incl. a high) > img (1 critical) > web (1 medium).
        assert [r.repo for r in rows] == ["acme-org/api", "acme-org/img", "acme-org/web"]
        by = {r.repo: r for r in rows}
        assert by["acme-org/api"].vulns.critical == 1
        assert by["acme-org/api"].vulns.high == 1
        assert by["acme-org/api"].vulns.total == 2  # fixed finding excluded
        assert by["acme-org/api"].is_container is False
        assert by["acme-org/web"].vulns.medium == 1
        # The container image is included and flagged so the UI won't link it
        # to the repo-only detail route.
        assert by["acme-org/img"].is_container is True
    finally:
        await _cleanup(db_session, a, b, c)


@pytest.mark.asyncio
async def test_scope_isolation(db_session):
    a, b, c = await _seed(db_session)
    try:
        assert sbom_package_repos(
            package_name="log4j", info_context={"asset_ids": [str(uuid.uuid4())]}
        ) == []
        assert sbom_package_repos(package_name="log4j", info_context={"asset_ids": []}) == []
    finally:
        await _cleanup(db_session, a, b, c)


@pytest.mark.asyncio
async def test_unknown_package_returns_empty(db_session):
    a, b, c = await _seed(db_session)
    try:
        assert sbom_package_repos(
            package_name="does-not-exist", info_context={"asset_ids": [a, b, c]}
        ) == []
    finally:
        await _cleanup(db_session, a, b, c)
