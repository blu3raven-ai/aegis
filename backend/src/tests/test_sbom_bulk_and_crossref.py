"""sbom_bulk_lookup batches the whole query list into one scoped statement and
attributes matches by purl / case-insensitive name / scoped-name suffix;
sbom_cross_references is scope-bounded and capped."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete  # noqa: E402

import src.sbom.resolvers as resolvers_mod  # noqa: E402
from src.db.models import Asset, Sbom, SbomComponent  # noqa: E402
from src.sbom.range_match import declared_range_admits  # noqa: E402
from src.sbom.resolvers import (  # noqa: E402
    _parse_bulk_query,
    sbom_bulk_lookup,
    sbom_cross_references,
)


@pytest.mark.parametrize("ecosystem,declared_range,version,expected", [
    ("npm", "^1.7.7", "1.9.0", True),       # caret admits same-major higher
    ("npm", "^1.7.7", "2.0.0", False),      # caret denies next-major
    ("npm", "~1.7.0", "1.9.0", False),      # tilde pins minor
    ("pypi", ">=2.0,<3.0", "2.5.1", True),
    ("pypi", ">=2.0,<3.0", "3.1.0", False),
    ("gem", "~> 1.0", "1.4.0", True),
    ("cargo", "^1.0", "1.5.0", False),      # univers cannot parse cargo natively
    ("golang", ">=1.0.0", "1.5.0", False),  # univers cannot parse golang natively
    ("npm", None, "1.9.0", False),          # missing range
    (None, "^1.7.7", "1.9.0", False),       # missing ecosystem
    ("npm", "^1.7.7", None, False),         # missing version
    ("npm", "not-a-range", "1.9.0", False), # garbage range -> fail-closed
    ("made-up-eco", "^1.0", "1.5.0", False),  # unknown scheme
])
def test_declared_range_admits(ecosystem, declared_range, version, expected):
    assert declared_range_admits(ecosystem, declared_range, version) is expected


@pytest.mark.parametrize("raw,expected", [
    # (match_query, ecosystem, flagged_version)
    ("lodash", ("lodash", None, None)),
    ("lodash@4.17.21", ("lodash", None, "4.17.21")),
    ("@angular/core", ("@angular/core", None, None)),
    ("@angular/core@13.0.0", ("@angular/core", None, "13.0.0")),
    ("pkg:npm/lodash", ("pkg:npm/lodash", "npm", None)),
    ("pkg:npm/lodash@4.17.21", ("pkg:npm/lodash", "npm", "4.17.21")),
    ("pkg:pypi/requests@2.31.0?arch=src#sub/path",
     ("pkg:pypi/requests", "pypi", "2.31.0")),
])
def test_parse_bulk_query(raw, expected):
    assert _parse_bulk_query(raw) == expected


async def _add_asset(db_session, display_name: str, components: list[dict]) -> str:
    """Create one repo asset with a Sbom row and the given components."""
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=display_name,
    ))
    await db_session.flush()
    db_session.add(Sbom(asset_id=aid, commit_sha="HEAD", s3_key=f"{aid}/sbom.cdx.json", run_id="r1"))
    db_session.add_all([
        SbomComponent(
            asset_id=aid, purl=c["purl"], name=c["name"],
            version=c.get("version", "1.0.0"), ecosystem=c.get("ecosystem", "npm"),
            declared_range=c.get("declared_range"),
        )
        for c in components
    ])
    await db_session.commit()
    return aid


async def _cleanup(db_session, *asset_ids: str) -> None:
    for aid in asset_ids:
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
        await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_bulk_lookup_matches_purl_name_and_suffix(db_session):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/lodash@4.0.0", "name": "lodash", "version": "4.0.0"},
        {"purl": "pkg:npm/%40angular/core@17.0.0", "name": "@angular/core", "version": "17.0.0"},
        {"purl": "pkg:npm/Log4j@2.0.0", "name": "Log4j", "version": "2.0.0"},
    ])
    b = await _add_asset(db_session, "acme-org/web", [
        {"purl": "pkg:npm/lodash@4.0.0", "name": "lodash", "version": "4.0.0"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=[
                "pkg:npm/lodash@4.0.0",  # pinned purl, in two repos at the pinned version
                "core",                   # bare-name suffix match of @angular/core
                "LOG4J",                  # case-insensitive name match
                "does-not-exist",         # not found
            ],
            info_context={"asset_ids": [a, b]},
        )
        assert res.truncated is False
        by = {r.query: r for r in res.matches}
        # One result per query, preserving input order.
        assert [r.query for r in res.matches] == [
            "pkg:npm/lodash@4.0.0", "core", "LOG4J", "does-not-exist",
        ]
        lodash = by["pkg:npm/lodash@4.0.0"]
        assert lodash.found is True
        assert lodash.queried_version == "4.0.0"
        assert lodash.exposure == "flagged_in_use"
        assert [(o.repo, o.version, o.flagged) for o in lodash.occurrences] == [
            ("acme-org/api", "4.0.0", True), ("acme-org/web", "4.0.0", True),
        ]
        assert by["core"].found is True
        assert by["core"].name == "@angular/core"
        assert by["core"].exposure == "present"
        assert by["LOG4J"].found is True
        assert by["LOG4J"].name == "Log4j"
        assert by["does-not-exist"].found is False
        assert by["does-not-exist"].exposure == "not_found"
        assert by["does-not-exist"].occurrences == []
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_bulk_lookup_multi_segment_suffix(db_session):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:golang/github.com/sirupsen/logrus@1.9.0",
         "name": "github.com/sirupsen/logrus"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=["sirupsen/logrus", "logrus"], info_context={"asset_ids": [a]}
        )
        by = {r.query: r for r in res.matches}
        # Multi-segment partial query matches the "/<q>" suffix...
        assert by["sirupsen/logrus"].found is True
        # ...and the bare last segment still matches too.
        assert by["logrus"].found is True
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_scope_isolation(db_session):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/lodash@4.0.0", "name": "lodash"},
    ])
    try:
        # Caller scoped elsewhere (or unscoped) never sees the component.
        assert sbom_bulk_lookup(
            queries=["lodash"], info_context={"asset_ids": [str(uuid.uuid4())]}
        ).matches[0].found is False
        empty = sbom_bulk_lookup(queries=["lodash"], info_context={"asset_ids": []})
        assert empty.matches == []
        assert empty.truncated is False
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_escapes_like_metacharacters(db_session):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/real@1.0.0", "name": "real"},
    ])
    try:
        # "%" must be literal, not a wildcard that matches "real".
        assert sbom_bulk_lookup(
            queries=["%"], info_context={"asset_ids": [a]}
        ).matches[0].found is False
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_cross_references_scope_and_cap(db_session, monkeypatch):
    purl = "pkg:npm/openssl@3.0.0"
    a = await _add_asset(db_session, "acme-org/api", [{"purl": purl, "name": "openssl"}])
    b = await _add_asset(db_session, "acme-org/web", [{"purl": purl, "name": "openssl"}])
    c = await _add_asset(db_session, "acme-org/cli", [{"purl": purl, "name": "openssl"}])
    try:
        # All three in-scope assets are returned, untruncated.
        full = sbom_cross_references(purl=purl, info_context={"asset_ids": [a, b, c]})
        assert sorted(x.repo for x in full.items) == ["acme-org/api", "acme-org/cli", "acme-org/web"]
        assert full.truncated is False

        # Out-of-scope assets are excluded.
        scoped = sbom_cross_references(purl=purl, info_context={"asset_ids": [a]})
        assert [x.repo for x in scoped.items] == ["acme-org/api"]
        empty = sbom_cross_references(purl=purl, info_context={"asset_ids": []})
        assert empty.items == []
        assert empty.truncated is False

        # The fan-out cap bounds the result set and flags truncation honestly.
        monkeypatch.setattr(resolvers_mod, "_MAX_CROSS_REFS", 2)
        capped = sbom_cross_references(purl=purl, info_context={"asset_ids": [a, b, c]})
        assert len(capped.items) == 2
        assert capped.truncated is True
        assert capped.cap == 2

        # Exactly-at-cap must NOT report truncation (3 rows, cap 3).
        monkeypatch.setattr(resolvers_mod, "_MAX_CROSS_REFS", 3)
        exact = sbom_cross_references(purl=purl, info_context={"asset_ids": [a, b, c]})
        assert len(exact.items) == 3
        assert exact.truncated is False
    finally:
        await _cleanup(db_session, a, b, c)


@pytest.mark.asyncio
async def test_bulk_lookup_exposure_buckets(db_session):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/lodash@4.17.21", "name": "lodash", "version": "4.17.21"},
        {"purl": "pkg:npm/axios@1.6.0", "name": "axios", "version": "1.6.0"},
    ])
    b = await _add_asset(db_session, "acme-org/web", [
        {"purl": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=[
                "lodash@4.17.21",   # present at that version in api -> flagged_in_use
                "axios@9.9.9",      # present, but never at 9.9.9 -> other_versions
                "lodash",           # no version pinned -> present
                "ghost-pkg",        # absent -> not_found
            ],
            info_context={"asset_ids": [a, b]},
        )
        by = {r.query: r for r in res.matches}

        flagged = by["lodash@4.17.21"]
        assert flagged.exposure == "flagged_in_use"
        assert flagged.queried_version == "4.17.21"
        flagged_occ = [o for o in flagged.occurrences if o.flagged]
        assert [(o.repo, o.version) for o in flagged_occ] == [("acme-org/api", "4.17.21")]

        other = by["axios@9.9.9"]
        assert other.exposure == "other_versions"
        assert all(not o.flagged for o in other.occurrences)
        assert {o.version for o in other.occurrences} == {"1.6.0"}

        present = by["lodash"]
        assert present.exposure == "present"
        assert present.queried_version is None
        assert {o.repo for o in present.occurrences} == {"acme-org/api", "acme-org/web"}

        assert by["ghost-pkg"].exposure == "not_found"
        assert by["ghost-pkg"].found is False
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_bulk_lookup_flags_row_cap_truncation(db_session, monkeypatch):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/lodash@4.0.0", "name": "lodash"},
        {"purl": "pkg:npm/axios@1.0.0", "name": "axios"},
        {"purl": "pkg:npm/zod@3.0.0", "name": "zod"},
    ])
    try:
        # Cap below the match count: the row fan-out is truncated and flagged,
        # so the UI can warn that some queries' data may be incomplete.
        monkeypatch.setattr(resolvers_mod, "_MAX_BULK_ROWS", 2)
        res = sbom_bulk_lookup(
            queries=["lodash", "axios", "zod"], info_context={"asset_ids": [a]}
        )
        assert res.truncated is True
        # Still one result row per input query regardless of the row cap.
        assert len(res.matches) == 3

        # Exactly-at-cap must not over-report truncation.
        monkeypatch.setattr(resolvers_mod, "_MAX_BULK_ROWS", 3)
        exact = sbom_bulk_lookup(
            queries=["lodash", "axios", "zod"], info_context={"asset_ids": [a]}
        )
        assert exact.truncated is False
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_reports_true_occurrence_total(db_session, monkeypatch):
    # lodash present in 3 repos; cap the per-query occurrence LIST at 2. The
    # occurrence_total must still report the true blast radius (3), not the cap.
    ids = []
    for i in range(3):
        ids.append(await _add_asset(db_session, f"acme-org/r{i}", [
            {"purl": "pkg:npm/lodash@4.0.0", "name": "lodash"},
        ]))
    try:
        monkeypatch.setattr(resolvers_mod, "_MAX_BULK_OCCURRENCES", 2)
        res = sbom_bulk_lookup(queries=["lodash"], info_context={"asset_ids": ids})
        m = res.matches[0]
        assert m.occurrence_total == 3
        assert m.occurrences_truncated is True
        assert len(m.occurrences) == 2
    finally:
        for a in ids:
            await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_flags_input_truncation(db_session, monkeypatch):
    # More pasted packages than the input cap: only the first N are checked and
    # the overflow must be flagged (it appears in no bucket).
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/lodash@4.0.0", "name": "lodash"},
    ])
    try:
        monkeypatch.setattr(resolvers_mod, "MAX_BULK_ITEMS", 2)
        res = sbom_bulk_lookup(
            queries=["lodash", "axios", "zod"], info_context={"asset_ids": [a]}
        )
        assert res.input_truncated is True
        assert res.accepted_count == 2
        assert len(res.matches) == 2  # only the first two were checked

        monkeypatch.setattr(resolvers_mod, "MAX_BULK_ITEMS", 3)
        exact = sbom_bulk_lookup(
            queries=["lodash", "axios", "zod"], info_context={"asset_ids": [a]}
        )
        assert exact.input_truncated is False
        assert exact.accepted_count == 3
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_latent_exposure(db_session):
    # Present at a benign version, but the declared range admits the flagged
    # one: a clean reinstall could pull it in -> latent.
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/widget@1.9.0", "name": "widget", "version": "1.9.0",
         "declared_range": "^1.7.7"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=["widget@1.8.0"],   # never installed at 1.8.0, but ^1.7.7 admits it
            info_context={"asset_ids": [a]},
        )
        match = res.matches[0]
        assert match.exposure == "latent"
        assert [o.latent for o in match.occurrences] == [True]
        assert all(not o.flagged for o in match.occurrences)
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_range_excludes_flagged_is_other_versions(db_session):
    # Declared range does NOT admit the flagged version -> plain other_versions.
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/widget@1.9.0", "name": "widget", "version": "1.9.0",
         "declared_range": "~1.7.0"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=["widget@1.9.5"],   # ~1.7.0 does not admit 1.9.5
            info_context={"asset_ids": [a]},
        )
        match = res.matches[0]
        assert match.exposure == "other_versions"
        assert all(not o.latent for o in match.occurrences)
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_flagged_in_use_beats_latent(db_session):
    # One repo actually on the flagged version, another merely latent:
    # flagged_in_use wins the precedence.
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/widget@1.8.0", "name": "widget", "version": "1.8.0"},
    ])
    b = await _add_asset(db_session, "acme-org/web", [
        {"purl": "pkg:npm/widget@1.9.0", "name": "widget", "version": "1.9.0",
         "declared_range": "^1.7.7"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=["widget@1.8.0"],
            info_context={"asset_ids": [a, b]},
        )
        match = res.matches[0]
        assert match.exposure == "flagged_in_use"
        # Both signals are still attributed at the occurrence level.
        flagged = [o for o in match.occurrences if o.flagged]
        latent = [o for o in match.occurrences if o.latent]
        assert [(o.repo, o.version) for o in flagged] == [("acme-org/api", "1.8.0")]
        assert [(o.repo, o.version) for o in latent] == [("acme-org/web", "1.9.0")]
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_bulk_lookup_no_declared_range_never_latent(db_session):
    a = await _add_asset(db_session, "acme-org/api", [
        {"purl": "pkg:npm/widget@1.9.0", "name": "widget", "version": "1.9.0"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=["widget@1.8.0"],
            info_context={"asset_ids": [a]},
        )
        match = res.matches[0]
        assert match.exposure == "other_versions"
        assert all(not o.latent for o in match.occurrences)
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_bulk_lookup_cargo_golang_fail_closed(db_session):
    # univers cannot parse cargo/golang native ranges; must read as not-latent
    # rather than raising.
    a = await _add_asset(db_session, "acme-org/svc", [
        {"purl": "pkg:cargo/widget@1.9.0", "name": "widget", "version": "1.9.0",
         "ecosystem": "cargo", "declared_range": "^1.7.7"},
    ])
    b = await _add_asset(db_session, "acme-org/svc2", [
        {"purl": "pkg:golang/widget@1.9.0", "name": "gadget", "version": "1.9.0",
         "ecosystem": "golang", "declared_range": ">=1.0.0"},
    ])
    try:
        res = sbom_bulk_lookup(
            queries=["widget@1.8.0", "gadget@1.8.0"],
            info_context={"asset_ids": [a, b]},
        )
        by = {r.query: r for r in res.matches}
        assert by["widget@1.8.0"].exposure == "other_versions"
        assert by["gadget@1.8.0"].exposure == "other_versions"
        assert all(
            not o.latent
            for r in res.matches for o in r.occurrences
        )
    finally:
        await _cleanup(db_session, a, b)
