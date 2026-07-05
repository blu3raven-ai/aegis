"""Tests for SBOM per-ecosystem analytics resolver."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding, SbomComponent  # noqa: E402
from src.sbom.resolvers import sbom_ecosystem_analytics  # noqa: E402


async def _seed(db_session) -> tuple[str, str]:
    """Two repos with packages across different ecosystems."""
    a = str(uuid.uuid4())
    b = str(uuid.uuid4())
    db_session.add_all([
        Asset(id=a, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api"),
        Asset(id=b, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/web"),
    ])
    await db_session.flush()
    db_session.add_all([
        # Maven packages
        SbomComponent(asset_id=a, purl="pkg:maven/org.apache/log4j@2.14.1",
                      name="log4j", version="2.14.1", ecosystem="maven", source_tool="syft"),
        SbomComponent(asset_id=b, purl="pkg:maven/spring-core@5.3.21",
                      name="spring-core", version="5.3.21", ecosystem="maven", source_tool="syft"),
        # NPM packages
        SbomComponent(asset_id=a, purl="pkg:npm/lodash@4.17.21",
                      name="lodash", version="4.17.21", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=b, purl="pkg:npm/express@4.18.2",
                      name="express", version="4.18.2", ecosystem="npm", source_tool="syft"),
        # PyPI packages
        SbomComponent(asset_id=a, purl="pkg:pypi/django@4.1.0",
                      name="django", version="4.1.0", ecosystem="pypi", source_tool="syft"),
    ])
    await db_session.flush()
    db_session.add_all([
        # Maven findings
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-LOG4J"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="high", package_name="log4j", cve_id="CVE-LOG4J-2"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="medium", package_name="spring-core", cve_id="CVE-SPRING"),
        # NPM findings
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="high", package_name="lodash", cve_id="CVE-LODASH"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="critical", package_name="express", cve_id="CVE-EXPRESS"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="high", package_name="express", cve_id="CVE-EXPRESS-2"),
        # PyPI findings
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="low", package_name="django", cve_id="CVE-DJANGO"),
        # Finding without component (unknown ecosystem)
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="critical", package_name="ghost-pkg", cve_id="CVE-GHOST"),
    ])
    await db_session.commit()
    return a, b


async def _cleanup(db_session, *asset_ids: str) -> None:
    for aid in asset_ids:
        await db_session.execute(delete(Finding).where(Finding.asset_id == aid))
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_ecosystem_analytics_aggregates_correctly(db_session):
    """Test that ecosystem analytics aggregates findings and components correctly."""
    a, b = await _seed(db_session)
    try:
        analytics = sbom_ecosystem_analytics(info_context={"asset_ids": [a, b]})
        ecosystems = {e.ecosystem: e for e in analytics}

        # Verify all ecosystems present
        assert set(ecosystems.keys()) == {"maven", "npm", "pypi", ""}

        # Maven: log4j (crit+high on a) + spring-core (medium on b)
        maven = ecosystems["maven"]
        assert maven.critical == 1
        assert maven.high == 1
        assert maven.medium == 1
        assert maven.low == 0
        assert maven.total_findings == 3
        assert maven.total_components == 2
        assert maven.assets_with_components == 2
        assert maven.assets_with_findings == 2
        assert maven.coverage_percentage == 100.0  # 2 assets with components / 2 total assets

        # NPM: lodash (high on a) + express (crit+high on b)
        npm = ecosystems["npm"]
        assert npm.critical == 1
        assert npm.high == 2
        assert npm.medium == 0
        assert npm.low == 0
        assert npm.total_findings == 3
        assert npm.total_components == 2
        assert npm.assets_with_components == 2
        assert npm.assets_with_findings == 2
        assert npm.coverage_percentage == 100.0

        # PyPI: django (low on a only)
        pypi = ecosystems["pypi"]
        assert pypi.critical == 0
        assert pypi.high == 0
        assert pypi.medium == 0
        assert pypi.low == 1
        assert pypi.total_findings == 1
        assert pypi.total_components == 1
        assert pypi.assets_with_components == 1
        assert pypi.assets_with_findings == 1
        assert pypi.coverage_percentage == 50.0  # 1 asset with components / 2 total assets

        # Unknown: ghost-pkg (critical on b, no component)
        unknown = ecosystems[""]
        assert unknown.critical == 1
        assert unknown.high == 0
        assert unknown.medium == 0
        assert unknown.low == 0
        assert unknown.total_findings == 1
        assert unknown.total_components == 0
        assert unknown.assets_with_components == 0
        assert unknown.assets_with_findings == 1
        assert unknown.coverage_percentage == 0.0

    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_ecosystem_analytics_with_scope(db_session):
    """Test that ecosystem analytics respects asset scope."""
    a, b = await _seed(db_session)
    try:
        # Scope to only asset a
        analytics = sbom_ecosystem_analytics(info_context={"asset_ids": [a]})
        ecosystems = {e.ecosystem: e for e in analytics}

        # Maven: only log4j's findings on asset a (1 critical, 1 high)
        maven = ecosystems["maven"]
        assert maven.critical == 1
        assert maven.high == 1
        assert maven.medium == 0
        assert maven.total_findings == 2
        assert maven.total_components == 1
        assert maven.assets_with_components == 1
        assert maven.assets_with_findings == 1
        assert maven.coverage_percentage == 100.0  # 1/1 assets

        # PyPI: only asset a has Django
        pypi = ecosystems["pypi"]
        assert pypi.total_components == 1
        assert pypi.assets_with_components == 1
        assert pypi.coverage_percentage == 100.0  # 1/1 assets

        # NPM: only lodash on asset a
        npm = ecosystems["npm"]
        assert npm.total_components == 1
        assert npm.critical == 0
        assert npm.high == 1
        assert npm.total_findings == 1

    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_ecosystem_analytics_empty_scope(db_session):
    """Test that ecosystem analytics returns empty for empty scope."""
    analytics = sbom_ecosystem_analytics(info_context={"asset_ids": []})
    assert list(analytics) == []


@pytest.mark.asyncio
async def test_ecosystem_with_components_but_no_findings(db_session):
    """A healthy ecosystem (components, zero open findings) must still appear —
    dropping it would make a coverage view read as 'no coverage'."""
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/clean",
    ))
    await db_session.flush()
    db_session.add(SbomComponent(
        asset_id=aid, purl="pkg:gem/rails@7.0.4", name="rails",
        version="7.0.4", ecosystem="gem", source_tool="syft",
    ))
    await db_session.commit()
    try:
        analytics = sbom_ecosystem_analytics(info_context={"asset_ids": [aid]})
        ecosystems = {e.ecosystem: e for e in analytics}

        assert "gem" in ecosystems
        gem = ecosystems["gem"]
        assert gem.total_components == 1
        assert gem.total_findings == 0
        assert gem.critical == 0
        assert gem.high == 0
        assert gem.medium == 0
        assert gem.low == 0
        assert gem.risk_score == 0
        assert gem.assets_with_components == 1
        assert gem.assets_with_findings == 0
        assert gem.coverage_percentage == 100.0  # 1/1 assets
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_finding_not_double_counted_across_ecosystems(db_session):
    """A package name present in two ecosystems on the same asset must not make
    one finding count once per ecosystem — that would inflate total_findings,
    the severity tallies, and the risk score."""
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/dual",
    ))
    await db_session.flush()
    # Same package name "foo" in two ecosystems on the same asset.
    db_session.add_all([
        SbomComponent(asset_id=aid, purl="pkg:npm/foo@1.0.0", name="foo",
                      version="1.0.0", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=aid, purl="pkg:pypi/foo@2.0.0", name="foo",
                      version="2.0.0", ecosystem="pypi", source_tool="syft"),
    ])
    await db_session.flush()
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=aid,
        state="open", severity="critical", package_name="foo", cve_id="CVE-FOO",
    ))
    await db_session.commit()
    try:
        analytics = sbom_ecosystem_analytics(info_context={"asset_ids": [aid]})
        ecosystems = {e.ecosystem: e for e in analytics}

        # Both ecosystems still surface their own component…
        assert ecosystems["npm"].total_components == 1
        assert ecosystems["pypi"].total_components == 1

        # …but the single finding is attributed to exactly one ecosystem, never
        # both. Assert on the aggregate so the test doesn't over-couple to the
        # tie-break; the finding lands in "npm" (min of {npm, pypi}).
        assert sum(e.total_findings for e in analytics) == 1
        assert sum(e.critical for e in analytics) == 1
        assert ecosystems["npm"].total_findings == 1
        assert ecosystems["npm"].critical == 1
        assert ecosystems["pypi"].total_findings == 0
    finally:
        await _cleanup(db_session, aid)