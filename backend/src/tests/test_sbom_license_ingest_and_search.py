"""populate_components persists the license expression + risk category, and
sbom_search filters by license category at the SQL layer within scope."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from sqlalchemy import delete, select  # noqa: E402

from src.db.models import Asset, Sbom, SbomComponent  # noqa: E402
from src.sbom.resolvers import sbom_filter_options, sbom_search  # noqa: E402
from src.sbom.storage import populate_components  # noqa: E402


async def _mk_asset(db_session, display_name="acme-org/api") -> str:
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=display_name,
    ))
    await db_session.commit()
    return aid


async def _cleanup(db_session, *aids: str) -> None:
    for aid in aids:
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
        await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_dedup_keeps_the_declared_and_most_restrictive_license(db_session):
    # Same purl listed twice. The dedup must not drop a declared license the
    # first occurrence lacked, and among declared licenses the most restrictive
    # wins (mirrors the classifier's AND-stacking).
    aid = await _mk_asset(db_session)
    sbom = {"components": [
        # first occurrence: no license; second declares MIT -> MIT must survive.
        {"name": "a", "version": "1", "purl": "pkg:npm/a@1"},
        {"name": "a", "version": "1", "purl": "pkg:npm/a@1",
         "licenses": [{"license": {"id": "MIT"}}]},
        # first MIT, second GPL -> the more restrictive GPL wins.
        {"name": "b", "version": "1", "purl": "pkg:npm/b@1",
         "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "b", "version": "1", "purl": "pkg:npm/b@1",
         "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
    ]}
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        by = {n: (e, c) for n, e, c in (await db_session.execute(
            select(SbomComponent.name, SbomComponent.license_expression, SbomComponent.license_category)
            .where(SbomComponent.asset_id == aid)
        )).all()}
        assert by["a"] == ("MIT", "permissive")          # declared beats none
        assert by["b"][1] == "copyleft"                  # most restrictive wins
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_persists_and_self_backfills_license(db_session):
    aid = await _mk_asset(db_session)
    sbom = {"components": [
        {"name": "lodash", "version": "4.0.0", "purl": "pkg:npm/lodash@4.0.0",
         "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "gpl-lib", "version": "1.0", "purl": "pkg:npm/gpl-lib@1.0",
         "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
        {"name": "nolic", "version": "1.0", "purl": "pkg:npm/nolic@1.0"},
    ]}
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        rows = (await db_session.execute(
            select(SbomComponent.name, SbomComponent.license_expression, SbomComponent.license_category)
            .where(SbomComponent.asset_id == aid)
        )).all()
        by = {n: (e, c) for n, e, c in rows}
        assert by["lodash"] == ("MIT", "permissive")
        assert by["gpl-lib"][1] == "copyleft"
        assert by["nolic"] == (None, "none")  # no license declared

        # Re-ingest with a changed license: delete+insert replaces both columns.
        sbom["components"][0]["licenses"] = [{"license": {"id": "GPL-3.0-only"}}]
        populate_components("acme-org", "api", sbom, asset_id=aid)
        cat = (await db_session.execute(
            select(SbomComponent.license_category)
            .where(SbomComponent.asset_id == aid, SbomComponent.name == "lodash")
        )).scalar_one()
        assert cat == "copyleft"
    finally:
        await _cleanup(db_session, aid)


async def _seed_for_search(db_session, aid: str) -> None:
    db_session.add(Sbom(asset_id=aid, commit_sha="HEAD", s3_key=f"{aid}/s.json", run_id="r1"))
    db_session.add_all([
        SbomComponent(asset_id=aid, purl="pkg:npm/mit@1", name="mit-lib", version="1",
                      ecosystem="npm", license_expression="MIT", license_category="permissive"),
        SbomComponent(asset_id=aid, purl="pkg:npm/gpl@1", name="gpl-lib", version="1",
                      ecosystem="npm", license_expression="GPL-3.0-only", license_category="copyleft"),
        SbomComponent(asset_id=aid, purl="pkg:npm/agpl@1", name="agpl-lib", version="1",
                      ecosystem="npm", license_expression="AGPL-3.0-only", license_category="network-copyleft"),
    ])
    await db_session.commit()


@pytest.mark.asyncio
async def test_search_filters_by_license_category_scoped(db_session):
    aid = await _mk_asset(db_session)
    await _seed_for_search(db_session, aid)
    try:
        # Filter to copyleft → only the GPL component, with license fields populated.
        res = sbom_search(license_categories=["copyleft"], info_context={"asset_ids": [aid]})
        assert [i.name for i in res.items] == ["gpl-lib"]
        assert res.items[0].license == "GPL-3.0-only"
        assert res.items[0].license_category == "copyleft"

        # Multiple categories compose.
        res2 = sbom_search(license_categories=["copyleft", "network-copyleft"],
                           info_context={"asset_ids": [aid]})
        assert sorted(i.name for i in res2.items) == ["agpl-lib", "gpl-lib"]

        # Out-of-scope / empty scope returns nothing — filter never leaks.
        assert sbom_search(license_categories=["copyleft"],
                           info_context={"asset_ids": [str(uuid.uuid4())]}).items == []
        assert sbom_search(license_categories=["copyleft"], info_context={"asset_ids": []}).items == []
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_filter_options_categories_worst_first(db_session):
    aid = await _mk_asset(db_session)
    await _seed_for_search(db_session, aid)
    try:
        opts = sbom_filter_options(info_context={"asset_ids": [aid]})
        # network-copyleft (7) > copyleft (6) > permissive (1).
        assert opts.license_categories == ["network-copyleft", "copyleft", "permissive"]
        assert sbom_filter_options(info_context={"asset_ids": []}).license_categories == []
    finally:
        await _cleanup(db_session, aid)
