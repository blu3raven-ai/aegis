"""sbom_risky_components aggregates open findings into estate-wide risky packages
ranked by severity weight + blast radius (distinct assets affected)."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding, SbomComponent  # noqa: E402
from src.sbom.resolvers import sbom_risky_components  # noqa: E402


async def _seed(db_session) -> tuple[str, str]:
    """Two repos. log4j is vulnerable in BOTH (blast radius 2: 2 critical + 1
    high); lodash is vulnerable in one (1 medium). Plus a fixed finding and a
    package-less finding that must be excluded."""
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
        # log4j is GPL (copyleft) in repo a but MIT (permissive) in repo b — the
        # risk view must surface the worst case (copyleft). lodash is permissive.
        SbomComponent(asset_id=a, purl="pkg:maven/org.apache/log4j@2.14.1",
                      name="log4j", version="2.14.1", ecosystem="maven", source_tool="syft",
                      license_expression="GPL-3.0-only", license_category="copyleft"),
        SbomComponent(asset_id=a, purl="pkg:npm/lodash@4.17.21",
                      name="lodash", version="4.17.21", ecosystem="npm", source_tool="syft",
                      license_expression="MIT", license_category="permissive"),
        SbomComponent(asset_id=b, purl="pkg:maven/org.apache/log4j@2.14.1",
                      name="log4j", version="2.14.1", ecosystem="maven", source_tool="syft",
                      license_expression="MIT", license_category="permissive"),
    ])
    await db_session.flush()
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-A"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="HIGH", package_name="log4j", cve_id="CVE-B"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="critical", package_name="log4j", cve_id="CVE-C"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="medium", package_name="lodash", cve_id="CVE-D"),
        # Excluded: fixed, and a finding with no package_name.
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="fixed", severity="critical", package_name="log4j", cve_id="CVE-E"),
        Finding(tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="high", package_name=None, cve_id=None),
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
async def test_aggregates_and_ranks_by_risk(db_session):
    a, b = await _seed(db_session)
    try:
        conn = sbom_risky_components(info_context={"asset_ids": [a, b]})
        names = [c.package_name for c in conn.items]
        assert conn.total == 2
        # log4j outranks lodash (critical weight ≫ medium) — comes first.
        assert names == ["log4j", "lodash"]
        by = {c.package_name: c for c in conn.items}
        assert by["log4j"].vulns.critical == 2      # one per repo
        assert by["log4j"].vulns.high == 1          # case-insensitive ("HIGH")
        assert by["log4j"].vulns.total == 3         # fixed finding excluded
        assert by["log4j"].repo_count == 2          # blast radius across both repos
        assert by["log4j"].ecosystem == "maven"
        # Worst-case licence across the estate: copyleft (repo a) beats the
        # permissive copy in repo b.
        assert by["log4j"].license_category == "copyleft"
        assert by["log4j"].license == "GPL-3.0-only"
        assert by["lodash"].vulns.medium == 1
        assert by["lodash"].repo_count == 1
        assert by["lodash"].ecosystem == "npm"
        assert by["lodash"].license_category == "permissive"
        assert by["lodash"].license == "MIT"
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_license_absent_yields_null(db_session):
    # A risky package whose components carry no classified licence reports null,
    # not an empty-string or a guessed category.
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/nolic",
    ))
    await db_session.flush()
    db_session.add(SbomComponent(
        asset_id=aid, purl="pkg:npm/leftpad@1.0.0", name="leftpad",
        version="1.0.0", ecosystem="npm", source_tool="syft",
    ))
    await db_session.flush()
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=aid,
        state="open", severity="high", package_name="leftpad", cve_id="CVE-NL",
    ))
    await db_session.commit()
    try:
        conn = sbom_risky_components(info_context={"asset_ids": [aid]})
        by = {c.package_name: c for c in conn.items}
        assert by["leftpad"].license is None
        assert by["leftpad"].license_category is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_multi_ecosystem_name_splits_into_per_ecosystem_rows(db_session):
    # A name present in two ecosystems in scope splits into one row per
    # ecosystem, each with its own accurate counts (not one merged row).
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/mixed",
    ))
    await db_session.flush()
    db_session.add_all([
        SbomComponent(asset_id=aid, purl="pkg:npm/shared@1.0.0", name="shared",
                      version="1.0.0", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=aid, purl="pkg:pypi/shared@2.0.0", name="shared",
                      version="2.0.0", ecosystem="pypi", source_tool="syft"),
    ])
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=aid,
        state="open", severity="high", package_name="shared",
    ))
    await db_session.commit()
    try:
        conn = sbom_risky_components(info_context={"asset_ids": [aid]})
        by_eco = {c.ecosystem: c for c in conn.items if c.package_name == "shared"}
        assert set(by_eco) == {"npm", "pypi"}
        assert by_eco["npm"].vulns.high == 1
        assert by_eco["pypi"].vulns.high == 1
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ecosystem_filter_excludes_same_name_other_ecosystem(db_session):
    # B5: filtering to npm must not pull in a same-named pypi package's findings
    # (the old name-membership filter over-counted cross-ecosystem collisions).
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    for aid, display in [(a, "acme-org/npm-repo"), (b, "acme-org/pypi-repo")]:
        db_session.add(Asset(
            id=aid, type="repo", source="source_connection",
            external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=display,
        ))
    await db_session.flush()
    db_session.add_all([
        SbomComponent(asset_id=a, purl="pkg:npm/dup@1.0.0", name="dup",
                      version="1.0.0", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=b, purl="pkg:pypi/dup@2.0.0", name="dup",
                      version="2.0.0", ecosystem="pypi", source_tool="syft"),
    ])
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="high", package_name="dup"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="critical", package_name="dup"),
    ])
    await db_session.commit()
    try:
        conn = sbom_risky_components(ecosystems=["npm"], info_context={"asset_ids": [a, b]})
        rows = [c for c in conn.items if c.package_name == "dup"]
        assert len(rows) == 1
        assert rows[0].ecosystem == "npm"
        assert rows[0].vulns.high == 1
        assert rows[0].vulns.critical == 0  # the pypi critical is excluded
        assert rows[0].repo_count == 1
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_single_ecosystem_finding_without_component_does_not_fragment(db_session):
    # A single-ecosystem package with a finding on an asset that has NO component
    # for it must stay ONE row (resolved to its sole ecosystem via the fallback),
    # not fragment into a real-ecosystem row + a blank "unknown" row.
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    for aid, d in [(a, "acme-org/has-comp"), (b, "acme-org/no-comp")]:
        db_session.add(Asset(
            id=aid, type="repo", source="source_connection",
            external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=d,
        ))
    await db_session.flush()
    # Only asset a carries the SBOM component for 'lib' (npm); asset b does not.
    db_session.add(SbomComponent(asset_id=a, purl="pkg:npm/lib@1.0.0", name="lib",
                                 version="1.0.0", ecosystem="npm", source_tool="syft"))
    db_session.add_all([
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a,
                state="open", severity="high", package_name="lib"),
        Finding(tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=b,
                state="open", severity="critical", package_name="lib"),
    ])
    await db_session.commit()
    try:
        conn = sbom_risky_components(info_context={"asset_ids": [a, b]})
        rows = [c for c in conn.items if c.package_name == "lib"]
        assert len(rows) == 1  # not fragmented
        assert rows[0].ecosystem == "npm"  # resolved to the sole ecosystem
        assert rows[0].repo_count == 2  # both assets counted
        assert rows[0].vulns.high == 1 and rows[0].vulns.critical == 1
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_finding_without_sbom_component_gets_blank_ecosystem(db_session):
    # A finding whose package is in no current SBOM (unknown ecosystem) is not
    # dropped — it lands in a blank-ecosystem row.
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/orphan",
    ))
    await db_session.flush()
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=aid,
        state="open", severity="critical", package_name="ghost-pkg",
    ))
    await db_session.commit()
    try:
        conn = sbom_risky_components(info_context={"asset_ids": [aid]})
        by = {c.package_name: c for c in conn.items}
        assert by["ghost-pkg"].ecosystem == ""
        assert by["ghost-pkg"].vulns.critical == 1
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_scope_limits_blast_radius(db_session):
    # Scoped to one asset: log4j's blast radius drops to 1, lodash unaffected.
    a, b = await _seed(db_session)
    try:
        conn = sbom_risky_components(info_context={"asset_ids": [a]})
        by = {c.package_name: c for c in conn.items}
        assert by["log4j"].repo_count == 1
        assert by["log4j"].vulns.total == 2
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_search_and_ecosystem_filters(db_session):
    a, b = await _seed(db_session)
    try:
        only_log = sbom_risky_components(search="log", info_context={"asset_ids": [a, b]})
        assert [c.package_name for c in only_log.items] == ["log4j"]

        only_npm = sbom_risky_components(ecosystems=["npm"], info_context={"asset_ids": [a, b]})
        assert [c.package_name for c in only_npm.items] == ["lodash"]
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_empty_scope_returns_empty(db_session):
    a, b = await _seed(db_session)
    try:
        assert sbom_risky_components(info_context={"asset_ids": []}).items == []
        # Out-of-scope caller sees nothing.
        conn = sbom_risky_components(info_context={"asset_ids": [str(uuid.uuid4())]})
        assert conn.items == [] and conn.total == 0
    finally:
        await _cleanup(db_session, a, b)
