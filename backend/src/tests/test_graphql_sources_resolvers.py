"""Unit tests for the sources GraphQL resolvers.

Covers the GQL-only resolvers: repoSources, imageSources, source (polymorphic
detail). The source-connections catalog reads (connections, internal-orgs) live
on REST and are tested in test_source_connections_catalog_router.py.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from graphql import GraphQLError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.sources import resolvers as sources_resolvers  # noqa: E402
from src.sources.service import (  # noqa: E402
    ImageDetailView,
    ImageListResult,
    ImageView,
    RepoDetailView,
    RepoListResult,
    RepoView,
)



_FAKE_REPO_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_FAKE_IMAGE_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


def _ctx_allow() -> dict:
    """Context whose backing request always passes permission checks."""
    return {"request": SimpleNamespace(_allow=True)}


def _ctx_deny() -> dict:
    return {"request": SimpleNamespace(_allow=False)}


def _has_permission(request, _perm) -> bool:
    return getattr(request, "_allow", False)


def _make_repo_view() -> RepoView:
    return RepoView(
        asset_id=_FAKE_REPO_ID,
        display_name="acme-org/api",
        last_scanned_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        finding_counts={"critical": 1, "high": 2, "medium": 0, "low": 3},
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1234",
        scanners_with_coverage=["dependencies_scanning", "secret_scanning"],
        coverage_status="fresh",
    )


def _make_image_view() -> ImageView:
    return ImageView(
        asset_id=_FAKE_IMAGE_ID,
        display_name="acme-org/web:latest",
        last_scanned_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
        finding_counts={"critical": 0, "high": 4, "medium": 1, "low": 0},
        image_digest="sha256:deadbeef" + "0" * 56,
        image_name="acme-org/web",
        image_tag="latest",
        layer_count=7,
        size_bytes=12345678,
        base_os="alpine:3.18",
        repos=["acme-org/web-app"],
    )


# ── repo_sources ────────────────────────────────────────────────────────────


def test_repo_sources_returns_summaries(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    monkeypatch.setattr(
        sources_resolvers,
        "_list_repo_sources",
        lambda **_: RepoListResult(sources=[_make_repo_view()], next_cursor=None, total_count=None),
    )

    result = sources_resolvers.repo_sources(
        asset_ids=[_FAKE_REPO_ID], info_context=_ctx_allow(), limit=50,
    )

    assert len(result.sources) == 1
    s = result.sources[0]
    assert s.type == "repo"
    assert s.asset_id == _FAKE_REPO_ID
    assert s.finding_counts.critical == 1
    assert s.repo.coverage_status == "fresh"
    assert "dependencies_scanning" in s.repo.scanners_with_coverage


def test_repo_sources_denies_without_view_findings(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)

    with pytest.raises(GraphQLError) as excinfo:
        sources_resolvers.repo_sources(
            asset_ids=[_FAKE_REPO_ID], info_context=_ctx_deny(),
        )
    assert excinfo.value.extensions.get("code") == "PERMISSION_DENIED"


# ── image_sources ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_image_sources_returns_summaries(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    monkeypatch.setattr(
        sources_resolvers,
        "_list_image_sources",
        AsyncMock(return_value=ImageListResult(
            sources=[_make_image_view()], next_cursor=None, total_count=1,
        )),
    )

    result = await sources_resolvers.image_sources(
        asset_ids=[_FAKE_IMAGE_ID], info_context=_ctx_allow(), limit=50,
    )

    assert len(result.sources) == 1
    s = result.sources[0]
    assert s.type == "image"
    assert s.image.image_digest.startswith("sha256:")
    assert s.image.base_os == "alpine:3.18"
    assert s.finding_counts.high == 4
    assert result.total_count == 1


@pytest.mark.asyncio
async def test_image_sources_rejects_bad_limit(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)

    with pytest.raises(GraphQLError) as excinfo:
        await sources_resolvers.image_sources(
            asset_ids=[_FAKE_IMAGE_ID], info_context=_ctx_allow(), limit=1000,
        )
    assert excinfo.value.extensions.get("code") == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_image_sources_wraps_value_error_as_validation(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    monkeypatch.setattr(
        sources_resolvers,
        "_list_image_sources",
        AsyncMock(side_effect=ValueError("Invalid cursor")),
    )

    with pytest.raises(GraphQLError) as excinfo:
        await sources_resolvers.image_sources(
            asset_ids=[_FAKE_IMAGE_ID], info_context=_ctx_allow(), cursor="garbage",
        )
    assert excinfo.value.extensions.get("code") == "VALIDATION_ERROR"


# ── source (polymorphic detail) ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_source_returns_repo_detail(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    detail = RepoDetailView(
        asset_id=_FAKE_REPO_ID,
        display_name="acme-org/api",
        last_scanned_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        finding_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1234",
        scanners_with_coverage=["dependencies_scanning"],
        coverage_status="fresh",
        scan_history=[],
        active_findings=[],
    )
    monkeypatch.setattr(sources_resolvers, "_get_source", AsyncMock(return_value=detail))

    result = await sources_resolvers.source(
        asset_id=_FAKE_REPO_ID, asset_ids=[_FAKE_REPO_ID], info_context=_ctx_allow(),
    )
    assert result is not None
    assert result.type == "repo"
    assert result.repo.last_scanned_sha == "abc1234"


@pytest.mark.asyncio
async def test_source_returns_image_detail(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    detail = ImageDetailView(
        asset_id=_FAKE_IMAGE_ID,
        display_name="acme-org/web:latest",
        last_scanned_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
        finding_counts={"critical": 0, "high": 1, "medium": 0, "low": 0},
        scan_history=[],
        active_findings=[],
        image_digest="sha256:abc",
        image_name="acme-org/web",
        image_tag="latest",
    )
    monkeypatch.setattr(sources_resolvers, "_get_source", AsyncMock(return_value=detail))

    result = await sources_resolvers.source(
        asset_id=_FAKE_IMAGE_ID, asset_ids=[_FAKE_IMAGE_ID], info_context=_ctx_allow(),
    )
    assert result is not None
    assert result.type == "image"
    assert result.image.image_digest == "sha256:abc"


@pytest.mark.asyncio
async def test_source_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    monkeypatch.setattr(sources_resolvers, "_get_source", AsyncMock(return_value=None))

    result = await sources_resolvers.source(
        asset_id=_FAKE_REPO_ID, asset_ids=[_FAKE_REPO_ID], info_context=_ctx_allow(),
    )
    assert result is None


# ── connection_scan_runs ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connection_scan_runs_denies_without_view_findings(monkeypatch):
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    from src.sources import scan_runs_resolvers as srr

    with pytest.raises(GraphQLError) as excinfo:
        await srr.connection_scan_runs(
            connection_id="conn-1", limit=50, info_context=_ctx_deny(),
        )
    assert excinfo.value.extensions.get("code") == "PERMISSION_DENIED"


@pytest.mark.asyncio
async def test_connection_scan_runs_empty_scope_returns_empty(monkeypatch):
    """A caller with view_findings but no asset scope gets an empty list, not a DB hit."""
    monkeypatch.setattr(sources_resolvers, "has_permission", _has_permission)
    from src.sources import scan_runs_resolvers as srr

    # _ctx_allow() carries no asset_ids → fail-closed empty result.
    out = await srr.connection_scan_runs(
        connection_id="conn-1", limit=50, info_context=_ctx_allow(),
    )
    assert out == []


def test_list_connection_runs_maps_and_scopes(monkeypatch):
    """Runs are joined to their asset name + scanner and mapped to the GQL row."""
    import asyncio
    from src.sources import scan_runs_resolvers as srr

    started = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 6, 1, 12, 5, tzinfo=timezone.utc)

    class _AssetsResult:
        def all(self):
            # (id, display_name, external_ref) — owner segment ties the asset to
            # the connection's org (source_ref is never populated).
            return [(_FAKE_REPO_ID, "acme-org/api", "github:acme-org/api")]

    class _RunsScalars:
        def all(self):
            return [SimpleNamespace(
                id="scan-1", asset_id=_FAKE_REPO_ID, tool="dependencies_scanning",
                status="completed", started_at=started, finished_at=finished,
                metadata_json={"findings_count": 4}, error=None,
            )]

    class _RunsResult:
        def scalars(self):
            return _RunsScalars()

    class _Session:
        def __init__(self):
            self._n = 0

        async def execute(self, *_a, **_k):
            self._n += 1
            return _AssetsResult() if self._n == 1 else _RunsResult()

    def _fake_run_db(coro_fn):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro_fn(_Session()))
        finally:
            loop.close()

    monkeypatch.setattr(srr, "run_db", _fake_run_db)
    monkeypatch.setattr(
        srr.sources_store, "get_connection",
        lambda _cid: {"auth": {"orgOrOwner": "acme-org"}},
    )

    out = srr._list_connection_runs("conn-1", [_FAKE_REPO_ID], limit=50)
    assert len(out) == 1
    r = out[0]
    assert r.scan_id == "scan-1"
    assert r.asset_name == "acme-org/api"
    assert r.scanner_type == "dependencies_scanning"
    assert r.status == "completed"
    assert r.duration_ms == 5 * 60 * 1000
    assert r.findings_count == 4


def test_list_connection_runs_empty_when_no_assets_in_scope(monkeypatch):
    """No connection assets fall in the caller's scope → no run query, empty list."""
    import asyncio
    from src.sources import scan_runs_resolvers as srr

    class _EmptyAssets:
        def all(self):
            return []

    class _Session:
        async def execute(self, *_a, **_k):
            return _EmptyAssets()

    def _fake_run_db(coro_fn):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro_fn(_Session()))
        finally:
            loop.close()

    monkeypatch.setattr(srr, "run_db", _fake_run_db)
    monkeypatch.setattr(
        srr.sources_store, "get_connection",
        lambda _cid: {"auth": {"orgOrOwner": "acme-org"}},
    )
    assert srr._list_connection_runs("conn-1", [_FAKE_REPO_ID], limit=50) == []


