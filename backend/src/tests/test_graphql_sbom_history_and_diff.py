"""Unit tests for the sbom_history and sbom_diff GraphQL resolvers."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import SbomQuery
from src.sbom.resolvers import (
    SbomDiffError,
    SbomDiffResult,
    SbomHistoryEntry,
)


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


@pytest.mark.asyncio
async def test_sbom_history_out_of_scope_returns_empty(scoped_ctx):
    # Repo is well-formed but the caller has no scope on it.
    with patch("src.sbom.resolvers.run_db", return_value=None):
        result = await SbomQuery().history(_info(), repo="acme/api", limit=10)
    assert result == []


@pytest.mark.asyncio
async def test_sbom_history_returns_newest_first(scoped_ctx):
    # In-scope (run_db returns a truthy asset id) and the object store lists keys.
    keys = [
        "dependencies_scanning/acme/auto-1700000000000/api/sbom.cdx.json",
        "dependencies_scanning/acme/auto-1700000100000/api/sbom.cdx.json",
        "dependencies_scanning/acme/auto-1700000200000/api/sbom.cdx.json",
    ]
    with patch("src.sbom.resolvers.run_db", return_value="asset-1"), \
         patch("src.sbom.resolvers.list_objects", return_value=keys):
        result = await SbomQuery().history(_info(), repo="acme/api", limit=10)

    assert [e.run_id for e in result] == [
        "auto-1700000200000",
        "auto-1700000100000",
        "auto-1700000000000",
    ]
    assert all(isinstance(e, SbomHistoryEntry) for e in result)
    assert all(e.created_at is not None for e in result)


@pytest.mark.asyncio
async def test_sbom_history_limit_clamped(scoped_ctx):
    keys = [
        f"dependencies_scanning/acme/auto-{1700000000000 + i}/api/sbom.cdx.json"
        for i in range(150)
    ]
    with patch("src.sbom.resolvers.run_db", return_value="asset-1"), \
         patch("src.sbom.resolvers.list_objects", return_value=keys):
        big = await SbomQuery().history(_info(), repo="acme/api", limit=999)
        small = await SbomQuery().history(_info(), repo="acme/api", limit=-5)

    assert len(big) == 100, "limit clamps to MAX of 100"
    assert len(small) == 1, "limit floor is 1"


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
    # _repo_in_scope_async returns False — caller cannot distinguish
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
        {"name": "left", "version": "1.0", "purl": "pkg:npm/left"},
        {"name": "stable", "version": "9.9", "purl": "pkg:npm/stable"},
    ]}
    to_sbom = {"components": [
        {"name": "left", "version": "2.0", "purl": "pkg:npm/left"},
        {"name": "stable", "version": "9.9", "purl": "pkg:npm/stable"},
        {"name": "newcomer", "version": "0.1", "purl": "pkg:npm/newcomer"},
    ]}

    with patch("src.sbom.resolvers.run_db", return_value="asset-1"), \
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
