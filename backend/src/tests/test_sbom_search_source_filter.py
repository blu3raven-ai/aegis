"""sbom_search discriminates repo vs container components by Asset.type, not by
source_tool (container scans also stamp source_tool="syft"), and exposes the
discriminator as is_container."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Sbom, SbomComponent  # noqa: E402
import src.sbom.resolvers as resolvers_mod  # noqa: E402
from src.sbom.resolvers import sbom_search  # noqa: E402


async def _seed(db_session) -> tuple[str, str]:
    """One repo asset and one image asset, seeded with the real write pattern:
    the repo dependency has source_tool=None (no scanner:source property) while
    the container component has source_tool="syft" — the exact case the old
    source_tool-based filter inverted."""
    repo_id = str(uuid.uuid4())
    image_id = str(uuid.uuid4())
    db_session.add_all([
        Asset(id=repo_id, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api"),
        Asset(id=image_id, type="image", source="source_connection",
              external_ref=f"ghcr:acme-org/{uuid.uuid4().hex}:latest", display_name="acme-org/api-image"),
    ])
    await db_session.flush()
    db_session.add_all([
        Sbom(asset_id=repo_id, run_id=f"auto-{uuid.uuid4().hex}", s3_key=f"k/{uuid.uuid4().hex}"),
        Sbom(asset_id=image_id, run_id=f"auto-{uuid.uuid4().hex}", s3_key=f"k/{uuid.uuid4().hex}"),
        SbomComponent(asset_id=repo_id, purl="pkg:npm/lodash@4.17.21",
                      name="lodash", version="4.17.21", ecosystem="npm", source_tool=None),
        SbomComponent(asset_id=image_id, purl="pkg:apk/openssl@3.0.0",
                      name="openssl", version="3.0.0", ecosystem="apk", source_tool="syft"),
    ])
    await db_session.commit()
    return repo_id, image_id


async def _cleanup(db_session, *asset_ids: str) -> None:
    for aid in asset_ids:
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
        await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_dependencies_filter_returns_only_repo_components(db_session):
    repo_id, image_id = await _seed(db_session)
    try:
        conn = sbom_search(source="dependencies", info_context={"asset_ids": [repo_id, image_id]})
        assert {c.name for c in conn.items} == {"lodash"}  # null-source repo dep included
        assert conn.items[0].is_container is False
    finally:
        await _cleanup(db_session, repo_id, image_id)


@pytest.mark.asyncio
async def test_containers_filter_returns_only_image_components(db_session):
    repo_id, image_id = await _seed(db_session)
    try:
        conn = sbom_search(source="containers", info_context={"asset_ids": [repo_id, image_id]})
        assert {c.name for c in conn.items} == {"openssl"}  # syft-stamped container included
        assert conn.items[0].is_container is True
    finally:
        await _cleanup(db_session, repo_id, image_id)


@pytest.mark.asyncio
async def test_no_source_filter_returns_both_with_correct_flag(db_session):
    repo_id, image_id = await _seed(db_session)
    try:
        conn = sbom_search(info_context={"asset_ids": [repo_id, image_id]})
        by = {c.name: c for c in conn.items}
        assert set(by) == {"lodash", "openssl"}
        assert by["lodash"].is_container is False
        assert by["openssl"].is_container is True
    finally:
        await _cleanup(db_session, repo_id, image_id)


@pytest.mark.asyncio
async def test_version_filter_flags_truncation_when_scan_cap_hit(db_session, monkeypatch):
    # The version filter scans a bounded candidate set; when more rows match the
    # SQL prefilter than the cap, results are partial and must be flagged so the
    # count isn't read as authoritative.
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/big",
    ))
    await db_session.flush()
    db_session.add(Sbom(asset_id=aid, run_id=f"auto-{uuid.uuid4().hex}", s3_key=f"k/{uuid.uuid4().hex}"))
    db_session.add_all([
        SbomComponent(asset_id=aid, purl=f"pkg:npm/p{i}@2.0.0",
                      name=f"p{i}", version="2.0.0", ecosystem="npm", source_tool=None)
        for i in range(5)
    ])
    await db_session.commit()
    try:
        # Cap below the match count → truncated, and total reflects only the cap.
        monkeypatch.setattr(resolvers_mod, "_MAX_VERSION_SCAN", 3)
        capped = sbom_search(
            version_op="gte", version_value="1.0.0", per_page=50,
            info_context={"asset_ids": [aid]},
        )
        assert capped.truncated is True
        assert capped.total == 3  # only the first 3 scanned rows were filtered

        # Cap above the match count → not truncated, full count.
        monkeypatch.setattr(resolvers_mod, "_MAX_VERSION_SCAN", 10)
        full = sbom_search(
            version_op="gte", version_value="1.0.0", per_page=50,
            info_context={"asset_ids": [aid]},
        )
        assert full.truncated is False
        assert full.total == 5

        # A non-version search never sets the flag (it doesn't scan-cap).
        plain = sbom_search(info_context={"asset_ids": [aid]})
        assert plain.truncated is False
    finally:
        await _cleanup(db_session, aid)


def test_parse_version_tuple_handles_v_prefix_and_unparseable():
    parse = resolvers_mod._parse_version_tuple
    # Last element is a release indicator: 1 = full release, 0 = pre-release.
    assert parse("1.2.3") == (1, 2, 3, 1)
    assert parse("v1.5.0") == (1, 5, 0, 1)  # Go module style
    assert parse("V2.0") == (2, 0, 1)
    assert parse("1.0.0-beta") == (1, 0, 0, 0)   # pre-release < full release
    assert parse("2.0.0-rc1") == (2, 0, 0, 0)
    assert parse("latest") is None  # no numeric part → excluded, not (0,)
    assert parse("") is None


@pytest.mark.asyncio
async def test_version_filter_parses_go_prefix_and_excludes_unparseable(db_session):
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/gv",
    ))
    await db_session.flush()
    db_session.add(Sbom(asset_id=aid, run_id=f"auto-{uuid.uuid4().hex}", s3_key=f"k/{uuid.uuid4().hex}"))
    db_session.add_all([
        SbomComponent(asset_id=aid, purl="pkg:golang/example.com/mod@v1.5.0",
                      name="mod", version="v1.5.0", ecosystem="golang", source_tool=None),
        SbomComponent(asset_id=aid, purl="pkg:npm/rolling@latest",
                      name="rolling", version="latest", ecosystem="npm", source_tool=None),
    ])
    await db_session.commit()
    try:
        # >=1.0.0 INCLUDES the Go v1.5.0 (v-strip) and EXCLUDES 'latest' (no
        # numeric part) rather than treating it as version 0.
        conn = sbom_search(version_op="gte", version_value="1.0.0", per_page=50,
                           info_context={"asset_ids": [aid]})
        assert {c.name for c in conn.items} == {"mod"}
        # Strict gt excludes an exactly-equal version.
        conn_gt = sbom_search(version_op="gt", version_value="1.5.0", per_page=50,
                             info_context={"asset_ids": [aid]})
        assert {c.name for c in conn_gt.items} == set()
    finally:
        await _cleanup(db_session, aid)


# ── Boolean search grammar (parser + compiler) integration ───────────────────


from graphql import GraphQLError  # noqa: E402


async def _seed_grammar(db_session) -> str:
    """One repo asset carrying lodash + axios (npm) and flask (pypi)."""
    repo_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=repo_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/web",
    ))
    await db_session.flush()
    db_session.add(Sbom(asset_id=repo_id, run_id=f"auto-{uuid.uuid4().hex}", s3_key=f"k/{uuid.uuid4().hex}"))
    db_session.add_all([
        SbomComponent(asset_id=repo_id, purl="pkg:npm/lodash@4.17.21",
                      name="lodash", version="4.17.21", ecosystem="npm", source_tool=None),
        SbomComponent(asset_id=repo_id, purl="pkg:npm/axios@1.6.0",
                      name="axios", version="1.6.0", ecosystem="npm", source_tool=None),
        SbomComponent(asset_id=repo_id, purl="pkg:pypi/flask@3.0.0",
                      name="flask", version="3.0.0", ecosystem="pypi", source_tool=None),
    ])
    await db_session.commit()
    return repo_id


@pytest.mark.asyncio
async def test_grammar_or_returns_rows_for_both_terms(db_session):
    repo_id = await _seed_grammar(db_session)
    try:
        conn = sbom_search(search="lodash OR axios", info_context={"asset_ids": [repo_id]})
        assert {c.name for c in conn.items} == {"lodash", "axios"}
    finally:
        await _cleanup(db_session, repo_id)


@pytest.mark.asyncio
async def test_grammar_field_and_ecosystem(db_session):
    repo_id = await _seed_grammar(db_session)
    try:
        conn = sbom_search(search="name:lodash AND ecosystem:npm", info_context={"asset_ids": [repo_id]})
        assert {c.name for c in conn.items} == {"lodash"}
        # ecosystem is an exact match, so a pypi component is excluded even when
        # the name would otherwise match.
        empty = sbom_search(search="name:lodash AND ecosystem:pypi", info_context={"asset_ids": [repo_id]})
        assert empty.items == []
    finally:
        await _cleanup(db_session, repo_id)


@pytest.mark.asyncio
async def test_grammar_not_excludes_ecosystem(db_session):
    repo_id = await _seed_grammar(db_session)
    try:
        conn = sbom_search(search="NOT ecosystem:pypi", info_context={"asset_ids": [repo_id]})
        assert {c.name for c in conn.items} == {"lodash", "axios"}  # flask (pypi) excluded
    finally:
        await _cleanup(db_session, repo_id)


@pytest.mark.asyncio
async def test_grammar_malformed_query_raises_bad_input(db_session):
    repo_id = await _seed_grammar(db_session)
    try:
        with pytest.raises(GraphQLError) as exc:
            sbom_search(search="name:", info_context={"asset_ids": [repo_id]})
        assert exc.value.extensions.get("code") == "BAD_USER_INPUT"
    finally:
        await _cleanup(db_session, repo_id)
