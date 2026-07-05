"""populate_components classifies each component direct/transitive/unknown from
the CycloneDX dependency graph, and sbom_search filters by that origin."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete, select  # noqa: E402

from src.db.models import Asset, Sbom, SbomComponent  # noqa: E402
from src.sbom.resolvers import sbom_filter_options, sbom_search  # noqa: E402
from src.sbom.storage import populate_components  # noqa: E402


async def _mk_asset(db_session) -> str:
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.commit()
    return aid


async def _cleanup(db_session, *aids: str) -> None:
    for aid in aids:
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
        await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


async def _origins(db_session, aid: str) -> dict[str, bool | None]:
    rows = (await db_session.execute(
        select(SbomComponent.name, SbomComponent.is_direct).where(SbomComponent.asset_id == aid)
    )).all()
    return {n: d for n, d in rows}


def _c(name, ref):
    return {"name": name, "version": "1.0", "purl": f"pkg:npm/{name}@1.0", "bom-ref": ref}


@pytest.mark.asyncio
async def test_ingest_rich_graph(db_session):
    aid = await _mk_asset(db_session)
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [_c("express", "r-exp"), _c("lodash", "r-lod"), _c("ms", "r-ms")],
        "dependencies": [
            {"ref": "root", "dependsOn": ["r-exp", "r-lod"]},  # direct
            {"ref": "r-exp", "dependsOn": ["r-ms"]},            # ms is transitive
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        o = await _origins(db_session, aid)
        assert o["express"] is True and o["lodash"] is True
        assert o["ms"] is False
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_flat_list_is_unknown(db_session):
    aid = await _mk_asset(db_session)
    sbom = {"components": [_c("express", "r-exp"), _c("lodash", "r-lod")]}  # no graph, no root
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        o = await _origins(db_session, aid)
        assert o["express"] is None and o["lodash"] is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_container_suppressed(db_session):
    aid = await _mk_asset(db_session)
    # Even with a graph, a container/OS root means "direct" is meaningless.
    sbom = {
        "metadata": {"component": {"bom-ref": "img", "type": "container"}},
        "components": [_c("openssl", "r-ssl")],
        "dependencies": [{"ref": "img", "dependsOn": ["r-ssl"]}],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _origins(db_session, aid))["openssl"] is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_keys_on_bomref_not_purl(db_session):
    aid = await _mk_asset(db_session)
    # Synthetic bom-refs that are NOT purls; a component with no bom-ref while a
    # graph exists must be unknown, not guessed transitive.
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [
            {"name": "a", "version": "1", "purl": "pkg:npm/a@1", "bom-ref": "syft-aaa"},
            {"name": "b", "version": "1", "purl": "pkg:npm/b@1"},  # no bom-ref
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["syft-aaa"]}],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        o = await _origins(db_session, aid)
        assert o["a"] is True
        assert o["b"] is None  # graph present but no bom-ref -> unknown, not transitive
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_dedup_direct_wins(db_session):
    aid = await _mk_asset(db_session)
    # Same purl appears as a direct root child AND a transitive child elsewhere.
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [
            {"name": "x", "version": "1", "purl": "pkg:npm/x@1", "bom-ref": "x-direct"},
            {"name": "x", "version": "1", "purl": "pkg:npm/x@1", "bom-ref": "x-trans"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["x-direct"]},
            {"ref": "other", "dependsOn": ["x-trans"]},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _origins(db_session, aid))["x"] is True  # direct wins
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_orphan_is_unknown_not_transitive(db_session):
    aid = await _mk_asset(db_session)
    # "orphan" is in components[] but referenced nowhere in the graph -> unknown,
    # NOT transitive (the graph never connects it).
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [_c("express", "r-exp"), _c("orphan", "r-orphan")],
        "dependencies": [
            {"ref": "root", "dependsOn": ["r-exp"]},
            {"ref": "r-exp", "dependsOn": []},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        o = await _origins(db_session, aid)
        assert o["express"] is True
        assert o["orphan"] is None  # mentioned nowhere -> unknown
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_empty_root_depends_on_is_all_unknown(db_session):
    aid = await _mk_asset(db_session)
    # Root declares zero direct deps -> no direct-ness signal at all -> unknown.
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [_c("a", "r-a")],
        "dependencies": [{"ref": "root", "dependsOn": []}],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _origins(db_session, aid))["a"] is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_malformed_metadata_no_crash(db_session):
    aid = await _mk_asset(db_session)
    sbom = {"metadata": None, "components": [_c("a", "r-a")], "dependencies": None}
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _origins(db_session, aid))["a"] is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_non_dict_metadata_no_crash(db_session):
    aid = await _mk_asset(db_session)
    # Malformed-but-truthy shapes must degrade to unknown, never raise mid-ingest.
    sbom = {"metadata": "garbage", "components": [_c("a", "r-a")], "dependencies": "nope"}
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _origins(db_session, aid))["a"] is None
    finally:
        await _cleanup(db_session, aid)


async def _declared_ranges(db_session, aid: str) -> dict[str, str | None]:
    rows = (await db_session.execute(
        select(SbomComponent.name, SbomComponent.declared_range).where(SbomComponent.asset_id == aid)
    )).all()
    return {n: r for n, r in rows}


@pytest.mark.asyncio
async def test_ingest_captures_declared_range(db_session):
    aid = await _mk_asset(db_session)
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "bom-ref": "r-lodash",
             "properties": [{"name": "aegis:declared_range", "value": "^4.17.0"}]},
            {"name": "ms", "version": "2.1.3", "purl": "pkg:npm/ms@2.1.3", "bom-ref": "r-ms"},
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["r-lodash"]}, {"ref": "r-lodash", "dependsOn": ["r-ms"]}],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        ranges = await _declared_ranges(db_session, aid)
        assert ranges["lodash"] == "^4.17.0"  # property captured
        assert ranges["ms"] is None  # no property -> null
    finally:
        await _cleanup(db_session, aid)


async def _manifest_cols(db_session, aid: str, name: str):
    return (await db_session.execute(
        select(
            SbomComponent.manifest_path,
            SbomComponent.manifest_line,
            SbomComponent.manifest_snippet,
            SbomComponent.manifest_snippet_start,
        ).where(SbomComponent.asset_id == aid, SbomComponent.name == name)
    )).first()


@pytest.mark.asyncio
async def test_ingest_captures_manifest_location(db_session):
    aid = await _mk_asset(db_session)
    sbom = {
        "components": [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "bom-ref": "r-lodash",
             "properties": [
                 {"name": "aegis:declared_range", "value": "^4.17.0"},
                 {"name": "aegis:declared_path", "value": "package.json"},
                 {"name": "aegis:declared_line", "value": "12"},
                 {"name": "aegis:declared_snippet", "value": '  "lodash": "^4.17.0"'},
                 {"name": "aegis:declared_snippet_start", "value": "8"},
             ]},
            {"name": "ms", "version": "2.1.3", "purl": "pkg:npm/ms@2.1.3", "bom-ref": "r-ms"},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        path, line, snippet, start = await _manifest_cols(db_session, aid, "lodash")
        assert path == "package.json"
        assert line == 12
        assert '"lodash": "^4.17.0"' in snippet
        assert start == 8
        # No manifest properties -> all null.
        assert await _manifest_cols(db_session, aid, "ms") == (None, None, None, None)
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_manifest_line_non_numeric_is_null(db_session):
    aid = await _mk_asset(db_session)
    sbom = {
        "components": [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "properties": [
                 {"name": "aegis:declared_path", "value": "package.json"},
                 {"name": "aegis:declared_line", "value": "not-a-number"},
             ]},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        path, line, _, _ = await _manifest_cols(db_session, aid, "lodash")
        assert path == "package.json"
        assert line is None  # non-numeric parsed to null, no crash
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_declared_range_absent_is_null(db_session):
    aid = await _mk_asset(db_session)
    sbom = {"components": [_c("lodash", "r-lodash")]}  # no properties key at all
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _declared_ranges(db_session, aid))["lodash"] is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_declared_range_malformed_no_crash(db_session):
    aid = await _mk_asset(db_session)
    # properties not a list; entries not dicts; value not a string -> all None.
    sbom = {
        "components": [
            {"name": "a", "version": "1", "purl": "pkg:npm/a@1", "properties": "garbage"},
            {"name": "b", "version": "1", "purl": "pkg:npm/b@1", "properties": ["nope", 7]},
            {"name": "c", "version": "1", "purl": "pkg:npm/c@1",
             "properties": [{"name": "aegis:declared_range", "value": {"not": "a string"}}]},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        ranges = await _declared_ranges(db_session, aid)
        assert ranges == {"a": None, "b": None, "c": None}
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_declared_range_dedup_keeps_non_null(db_session):
    aid = await _mk_asset(db_session)
    # Same purl twice: one row carries the property, one doesn't. The non-null
    # value must survive dedup regardless of which row is seen first.
    sbom = {
        "components": [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "bom-ref": "r-lodash-a"},
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "bom-ref": "r-lodash-b",
             "properties": [{"name": "aegis:declared_range", "value": "^4.17.0"}]},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        assert (await _declared_ranges(db_session, aid))["lodash"] == "^4.17.0"
    finally:
        await _cleanup(db_session, aid)


async def _seed_search(db_session, aid: str) -> None:
    db_session.add(Sbom(asset_id=aid, commit_sha="HEAD", s3_key=f"{aid}/s.json", run_id="r1"))
    db_session.add_all([
        SbomComponent(asset_id=aid, purl="pkg:npm/d@1", name="direct-lib", version="1",
                      ecosystem="npm", is_direct=True),
        SbomComponent(asset_id=aid, purl="pkg:npm/t@1", name="trans-lib", version="1",
                      ecosystem="npm", is_direct=False),
        SbomComponent(asset_id=aid, purl="pkg:npm/u@1", name="unknown-lib", version="1",
                      ecosystem="npm", is_direct=None),
    ])
    await db_session.commit()


@pytest.mark.asyncio
async def test_search_filter_by_dependency_scoped(db_session):
    aid = await _mk_asset(db_session)
    await _seed_search(db_session, aid)
    try:
        direct = sbom_search(dependency="direct", info_context={"asset_ids": [aid]})
        assert [i.name for i in direct.items] == ["direct-lib"]
        assert direct.items[0].is_direct is True

        assert [i.name for i in sbom_search(dependency="transitive", info_context={"asset_ids": [aid]}).items] == ["trans-lib"]
        assert [i.name for i in sbom_search(dependency="unknown", info_context={"asset_ids": [aid]}).items] == ["unknown-lib"]

        # Out-of-scope / empty scope never leak.
        assert sbom_search(dependency="direct", info_context={"asset_ids": [str(uuid.uuid4())]}).items == []
        assert sbom_search(dependency="direct", info_context={"asset_ids": []}).items == []
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_filter_options_dependency_scopes(db_session):
    aid = await _mk_asset(db_session)
    await _seed_search(db_session, aid)
    try:
        opts = sbom_filter_options(info_context={"asset_ids": [aid]})
        assert opts.dependency_scopes == ["direct", "transitive", "unknown"]
        assert sbom_filter_options(info_context={"asset_ids": []}).dependency_scopes == []
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_captures_declared_scope(db_session):
    """The runner's aegis:declared_scope property lands on SbomComponent.scope."""
    aid = await _mk_asset(db_session)
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "application"}},
        "components": [
            {
                "name": "jest", "version": "29.0.0", "purl": "pkg:npm/jest@29.0.0",
                "bom-ref": "r-jest",
                "properties": [{"name": "aegis:declared_scope", "value": "dev"}],
            },
            {
                "name": "express", "version": "4.0.0", "purl": "pkg:npm/express@4.0.0",
                "bom-ref": "r-exp",
                "properties": [{"name": "aegis:declared_scope", "value": "prod"}],
            },
            # transitive dep — no declared scope stamped
            {"name": "ms", "version": "2.0", "purl": "pkg:npm/ms@2.0", "bom-ref": "r-ms"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["r-jest", "r-exp"]},
            {"ref": "r-exp", "dependsOn": ["r-ms"]},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        rows = (await db_session.execute(
            select(SbomComponent.name, SbomComponent.scope).where(SbomComponent.asset_id == aid)
        )).all()
        scope = {n: s for n, s in rows}
        assert scope["jest"] == "dev"
        assert scope["express"] == "prod"
        assert scope["ms"] is None
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_ingest_captures_layer_attribution(db_session):
    """The runner's aegis:layer_digest/index properties land on SbomComponent."""
    aid = await _mk_asset(db_session)
    sbom = {
        "metadata": {"component": {"bom-ref": "root", "type": "container"}},
        "components": [
            {
                "name": "openssl", "version": "1.1.1", "purl": "pkg:deb/debian/openssl@1.1.1",
                "bom-ref": "r-ssl",
                "properties": [
                    {"name": "aegis:layer_digest", "value": "sha256:base"},
                    {"name": "aegis:layer_index", "value": "0"},
                ],
            },
            {"name": "app", "version": "2.0", "purl": "pkg:npm/app@2.0", "bom-ref": "r-app"},
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["r-ssl", "r-app"]}],
    }
    try:
        populate_components("acme-org", "img", sbom, asset_id=aid)
        rows = (await db_session.execute(
            select(SbomComponent.name, SbomComponent.layer_digest, SbomComponent.layer_index)
            .where(SbomComponent.asset_id == aid)
        )).all()
        by_name = {n: (d, i) for n, d, i in rows}
        assert by_name["openssl"] == ("sha256:base", 0)
        assert by_name["app"] == (None, None)  # unattributed component
    finally:
        await _cleanup(db_session, aid)
