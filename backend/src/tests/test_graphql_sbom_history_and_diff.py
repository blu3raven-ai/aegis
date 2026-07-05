"""Unit tests for the sbom_history and sbom_diff GraphQL resolvers."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import delete

import src.sbom.resolvers as resolvers_mod
from src.db.models import Asset, SbomRun
from src.graphql.schema import SbomQuery
from src.sbom.diff_overlay import DiffOverlay
from src.sbom.resolvers import (
    SbomDiffError,
    SbomDiffResult,
    SbomHistoryEntry,
    sbom_history,
)


def _empty_overlay() -> DiffOverlay:
    """An overlay with the OSV delta unavailable and no findings — lets the
    mocked diff tests exercise classification without a DB."""
    return DiffOverlay(available=False, current_findings={}, _ids_by_ref={}, _sev_by_id={})


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace()})


@pytest.fixture
def empty_scope_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": [],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.fixture
def scoped_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": ["asset-1"],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


# ── sbom_history ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sbom_history_empty_scope_returns_empty(empty_scope_ctx):
    result = await SbomQuery().history(_info(), repo="acme/api", limit=10)
    assert result == []


@pytest.mark.asyncio
async def test_sbom_history_rejects_malformed_repo(scoped_ctx):
    # Path traversal attempt — extra slash, '..' must not flow into MinIO prefix.
    for bad in ["acme/api/extra", "../etc/passwd", "acme", "/abs/path", "acme/.."]:
        result = await SbomQuery().history(_info(), repo=bad, limit=10)
        assert result == [], f"expected empty for malformed repo {bad!r}"


async def _seed_runs(db_session, asset_id: str, runs: list[tuple[str, datetime]]) -> None:
    """Seed one repo asset (display_name acme/api) with the given run history."""
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme/{uuid.uuid4().hex}", display_name="acme/api",
    ))
    await db_session.flush()
    db_session.add_all([
        SbomRun(asset_id=asset_id, run_id=rid, commit_sha="HEAD", scanned_at=ts)
        for rid, ts in runs
    ])
    await db_session.commit()


async def _cleanup(db_session, asset_id: str) -> None:
    await db_session.execute(delete(SbomRun).where(SbomRun.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_sbom_history_returns_newest_first(db_session):
    aid = str(uuid.uuid4())
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    await _seed_runs(db_session, aid, [
        ("auto-1700000000000", base),
        ("auto-1700000100000", base + timedelta(hours=1)),
        ("auto-1700000200000", base + timedelta(hours=2)),
    ])
    try:
        result = sbom_history(repo="acme/api", limit=10, info_context={"asset_ids": [aid]})
        assert [e.run_id for e in result] == [
            "auto-1700000200000",
            "auto-1700000100000",
            "auto-1700000000000",
        ]
        assert all(isinstance(e, SbomHistoryEntry) for e in result)
        # created_at is the real scanned_at; key reconstructs the per-run blob path.
        assert result[0].created_at == (base + timedelta(hours=2)).isoformat()
        assert result[0].key == "dependencies_scanning/acme/auto-1700000200000/api/sbom.cdx.json"
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_sbom_history_scope_isolation(db_session):
    aid = str(uuid.uuid4())
    await _seed_runs(db_session, aid, [("auto-1", datetime(2026, 1, 1, tzinfo=timezone.utc))])
    try:
        # A caller scoped to a different asset (or no scope) sees nothing.
        assert sbom_history(
            repo="acme/api", limit=10, info_context={"asset_ids": [str(uuid.uuid4())]}
        ) == []
        assert sbom_history(repo="acme/api", limit=10, info_context={"asset_ids": []}) == []
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_sbom_history_limit_clamped(db_session):
    aid = str(uuid.uuid4())
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    await _seed_runs(db_session, aid, [
        (f"auto-{i}", base + timedelta(seconds=i)) for i in range(150)
    ])
    try:
        big = sbom_history(repo="acme/api", limit=999, info_context={"asset_ids": [aid]})
        small = sbom_history(repo="acme/api", limit=-5, info_context={"asset_ids": [aid]})
        assert len(big) == 100, "limit clamps to MAX of 100"
        assert len(small) == 1, "limit floor is 1"
    finally:
        await _cleanup(db_session, aid)


# ── sbom_diff ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sbom_diff_bad_request_when_no_args(scoped_ctx):
    result = await SbomQuery().diff(_info())
    assert isinstance(result, SbomDiffError)
    assert result.code == "BAD_REQUEST"


@pytest.mark.asyncio
async def test_sbom_diff_repo_requires_both_run_ids(scoped_ctx):
    result = await SbomQuery().diff(_info(), repo_id="acme/api", from_run_id="auto-1")
    assert isinstance(result, SbomDiffError)
    assert result.code == "BAD_REQUEST"


@pytest.mark.asyncio
async def test_sbom_diff_uniform_not_found_for_out_of_scope_repo(scoped_ctx):
    # _resolve_repo_asset_id returns None — caller cannot distinguish
    # "out of scope" from "doesn't exist". Both return NOT_FOUND.
    with patch("src.sbom.resolvers.run_db", return_value=None):
        result = await SbomQuery().diff(
            _info(),
            repo_id="acme/api",
            from_run_id="auto-1700000000000",
            to_run_id="auto-1700000100000",
        )
    assert isinstance(result, SbomDiffError)
    assert result.code == "NOT_FOUND"


@pytest.mark.asyncio
async def test_sbom_diff_rejects_malformed_repo(scoped_ctx):
    result = await SbomQuery().diff(
        _info(),
        repo_id="../etc/passwd",
        from_run_id="auto-1",
        to_run_id="auto-2",
    )
    assert isinstance(result, SbomDiffError)
    assert result.code == "NOT_FOUND"  # uniform — never leak existence


@pytest.mark.asyncio
async def test_sbom_diff_rejects_malformed_run_id(scoped_ctx):
    # Slash in run_id would let a caller traverse into another asset's prefix.
    result = await SbomQuery().diff(
        _info(),
        repo_id="acme/api",
        from_run_id="auto-1/../other",
        to_run_id="auto-2",
    )
    assert isinstance(result, SbomDiffError)
    assert result.code == "NOT_FOUND"


@pytest.mark.asyncio
async def test_sbom_diff_repo_happy_path(scoped_ctx):
    # diff_sboms keys on (name, purl). To classify a row as version_changed
    # the purl must match across the two sides — same package, version diff.
    from_sbom = {"components": [
        {"name": "left", "version": "1.0", "purl": "pkg:npm/left",
         "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "stable", "version": "9.9", "purl": "pkg:npm/stable"},
    ]}
    to_sbom = {"components": [
        {"name": "left", "version": "2.0", "purl": "pkg:npm/left",
         "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
        {"name": "stable", "version": "9.9", "purl": "pkg:npm/stable"},
        {"name": "newcomer", "version": "0.1", "purl": "pkg:npm/newcomer"},
    ]}

    # run_db is called three times: resolve the repo asset id, confirm both run
    # ids belong to that asset (_asset_owns_runs → True), then the vuln overlay.
    with patch("src.sbom.resolvers.run_db", side_effect=["asset-1", True, _empty_overlay()]), \
         patch("src.sbom.resolvers.download_json", side_effect=[from_sbom, to_sbom]):
        result = await SbomQuery().diff(
            _info(),
            repo_id="acme/api",
            from_run_id="auto-1700000000000",
            to_run_id="auto-1700000100000",
        )

    assert isinstance(result, SbomDiffResult)
    assert result.unchanged_count == 1
    assert [c.name for c in result.added] == ["newcomer"]
    assert result.removed == []
    assert len(result.version_changed) == 1
    assert result.version_changed[0].name == "left"
    assert result.version_changed[0].from_version == "1.0"
    assert result.version_changed[0].to_version == "2.0"
    # The bump changed the license — classified through the resolver seam.
    assert result.version_changed[0].from_license_category == "permissive"
    assert result.version_changed[0].to_license_category == "copyleft"
    assert result.version_changed[0].to_license == "GPL-3.0-only"
    # Overlay unavailable here → deltas default to zero, flag is False.
    assert result.remediation_signal_available is False
    assert result.added[0].known_vulns.total == 0
    assert result.version_changed[0].resolved.total == 0
    # Small diff → not truncated; counts mirror the (full) lists.
    assert result.truncated is False
    assert result.added_count == 1 and result.removed_count == 0
    assert result.version_changed_count == 1


@pytest.mark.asyncio
async def test_sbom_diff_caps_node_lists_and_reports_true_totals(scoped_ctx, monkeypatch):
    # A pathological container diff: more added nodes than the cap. The lists are
    # clipped but the counts report the true totals and `truncated` is set.
    monkeypatch.setattr(resolvers_mod, "_MAX_DIFF_NODES", 1)
    from_sbom = {"components": []}
    to_sbom = {"components": [
        {"name": "a", "version": "1.0", "purl": "pkg:npm/a"},
        {"name": "b", "version": "1.0", "purl": "pkg:npm/b"},
        {"name": "c", "version": "1.0", "purl": "pkg:npm/c"},
    ]}
    with patch("src.sbom.resolvers.run_db", side_effect=["asset-1", True, _empty_overlay()]), \
         patch("src.sbom.resolvers.download_json", side_effect=[from_sbom, to_sbom]):
        result = await SbomQuery().diff(
            _info(),
            repo_id="acme/api",
            from_run_id="auto-1700000000000",
            to_run_id="auto-1700000100000",
        )

    assert isinstance(result, SbomDiffResult)
    assert result.added_count == 3       # true total
    assert len(result.added) == 1        # clipped to the cap
    assert result.truncated is True


@pytest.mark.asyncio
async def test_sbom_diff_run_not_owned_by_asset_returns_not_found(scoped_ctx):
    # BOLA regression: the repo resolves in scope (asset-1), but a supplied run
    # id is NOT one of that asset's runs — e.g. a display_name-colliding
    # sibling's snapshot. _asset_owns_runs returns False → uniform NOT_FOUND,
    # and no blob is ever fetched.
    fetched = {"v": False}

    def fake_download(_key):
        fetched["v"] = True
        return {"components": []}

    with patch("src.sbom.resolvers.run_db", side_effect=["asset-1", False]), \
         patch("src.sbom.resolvers.download_json", side_effect=fake_download):
        result = await SbomQuery().diff(
            _info(),
            repo_id="acme/api",
            from_run_id="auto-1700000000000",
            to_run_id="auto-9999999999999",
        )

    assert isinstance(result, SbomDiffError)
    assert result.code == "NOT_FOUND"
    assert fetched["v"] is False


@pytest.mark.asyncio
async def test_sbom_diff_rejects_malformed_image_digest(scoped_ctx):
    # Anything but "sha256:<64-hex>" returns NOT_FOUND. Important because
    # this string flows into a DB lookup; a relaxed parser would let callers
    # probe arbitrary strings against the Sbom table.
    result = await SbomQuery().diff(
        _info(),
        image_digest_from="not-a-digest",
        image_digest_to="sha256:" + "a" * 64,
    )
    assert isinstance(result, SbomDiffError)
    assert result.code == "NOT_FOUND"
