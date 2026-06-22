"""Unit tests for the saved_views GraphQL resolver.

Covers unauthenticated callers, per-user user_id propagation, surface
filter pass-through, shape correctness, and the unknown-surface validation
error path. Service is patched at the resolver-module level so these tests
stay DB-free.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from graphql import GraphQLError

from src.graphql.schema import SettingsQuery


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace()})


def _run_db_inline(coro_fn):
    """Inline stand-in for run_db that executes the resolver's async closure
    against a MagicMock session inside a worker thread, so the resolver's
    sync wrapper can call asyncio.run without colliding with the test loop."""
    import concurrent.futures

    def _runner():
        return asyncio.run(coro_fn(MagicMock()))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_runner).result()


@pytest.fixture
def user_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "user-1",
            "role": "viewer",
            "asset_ids": [],
            "tier": "enterprise",
            "request": SimpleNamespace(state=SimpleNamespace(user_sub="user-1")),
            "_cache": {},
        }),
    ):
        yield


@pytest.fixture
def no_request_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u",
            "role": "viewer",
            "asset_ids": [],
            "tier": "enterprise",
            "_cache": {},
        }),
    ):
        yield


@pytest.fixture
def anon_ctx():
    """Authenticated session present, but user_sub on request.state is empty.
    This is the "request reached the resolver without a user identity" path."""
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "",
            "role": "viewer",
            "asset_ids": [],
            "tier": "enterprise",
            "request": SimpleNamespace(state=SimpleNamespace(user_sub="")),
            "_cache": {},
        }),
    ):
        yield


def _row(
    *,
    id_: str = "view-1",
    surface: str = "findings",
    name: str = "KEV-only",
    url_state: dict | None = None,
    is_default: bool = False,
    created_at: datetime | None = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    updated_at: datetime | None = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
):
    row = MagicMock()
    row.id = id_
    row.surface = surface
    row.name = name
    row.url_state = url_state if url_state is not None else {"kev": "true"}
    row.is_default = is_default
    row.created_at = created_at
    row.updated_at = updated_at
    return row


@pytest.mark.asyncio
async def test_saved_views_no_request_raises_unauthenticated(no_request_ctx):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().saved_views(_info(), surface="findings")
    assert excinfo.value.extensions == {"code": "UNAUTHENTICATED"}


@pytest.mark.asyncio
async def test_saved_views_empty_user_raises_unauthenticated(anon_ctx):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().saved_views(_info(), surface="findings")
    assert excinfo.value.extensions == {"code": "UNAUTHENTICATED"}


@pytest.mark.asyncio
async def test_saved_views_propagates_user_id_and_surface(user_ctx):
    captured: dict = {}

    async def _capture(**kwargs):
        captured.update(kwargs)
        return []

    with patch(
        "src.settings.saved_views.resolvers.list_views",
        new=AsyncMock(side_effect=_capture),
    ), patch("src.settings.saved_views.resolvers.run_db", side_effect=_run_db_inline):
        result = await SettingsQuery().saved_views(_info(), surface="findings")

    assert result == []
    assert captured["user_id"] == "user-1"
    assert captured["surface"] == "findings"


@pytest.mark.asyncio
async def test_saved_views_returns_shape(user_ctx):
    row = _row(id_="view-1", name="KEV-only", url_state={"kev": "true"}, is_default=True)
    with patch(
        "src.settings.saved_views.resolvers.list_views",
        new=AsyncMock(return_value=[row]),
    ), patch("src.settings.saved_views.resolvers.run_db", side_effect=_run_db_inline):
        result = await SettingsQuery().saved_views(_info(), surface="findings")

    assert len(result) == 1
    v = result[0]
    assert v.id == "view-1"
    assert v.surface == "findings"
    assert v.name == "KEV-only"
    assert v.url_state == {"kev": "true"}
    assert v.is_default is True
    assert v.created_at == "2026-06-01T12:00:00+00:00"
    assert v.updated_at == "2026-06-01T12:00:00+00:00"


@pytest.mark.asyncio
async def test_saved_views_null_timestamps_pass_through(user_ctx):
    row = _row(created_at=None, updated_at=None)
    with patch(
        "src.settings.saved_views.resolvers.list_views",
        new=AsyncMock(return_value=[row]),
    ), patch("src.settings.saved_views.resolvers.run_db", side_effect=_run_db_inline):
        result = await SettingsQuery().saved_views(_info(), surface="findings")

    assert result[0].created_at is None
    assert result[0].updated_at is None


@pytest.mark.asyncio
async def test_saved_views_unknown_surface_raises_validation_error(user_ctx):
    async def _raise(**_kwargs):
        raise ValueError("unknown surface: other")

    with patch(
        "src.settings.saved_views.resolvers.list_views",
        side_effect=_raise,
    ), patch("src.settings.saved_views.resolvers.run_db", side_effect=_run_db_inline):
        with pytest.raises(GraphQLError) as excinfo:
            await SettingsQuery().saved_views(_info(), surface="other")

    assert excinfo.value.extensions == {"code": "VALIDATION_ERROR"}
    assert "unknown surface" in str(excinfo.value)
