"""Unit tests for resolver_utils.unpack_ctx.

The helper consolidates the two-line boilerplate that lived in every
schema.py resolver:

    ctx = await get_graphql_context(info.context["request"])
    asset_ids = ctx.get("asset_ids") or []

It's exercised transitively by every GraphQL test, but a direct test
locks in the (ctx, asset_ids) tuple contract and the empty-asset_ids
fallback behaviour.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.resolver_utils import unpack_ctx


def _info(request_obj):
    return SimpleNamespace(context={"request": request_obj})


@pytest.mark.asyncio
async def test_unpack_ctx_returns_ctx_and_scoped_asset_ids():
    fake_request = object()
    fake_ctx = {"user_id": "u1", "asset_ids": ["a1", "a2"]}
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value=fake_ctx),
    ) as mocked:
        ctx, asset_ids = await unpack_ctx(_info(fake_request))

    mocked.assert_awaited_once_with(fake_request)
    assert ctx is fake_ctx
    assert asset_ids == ["a1", "a2"]


@pytest.mark.asyncio
async def test_unpack_ctx_returns_empty_list_when_no_asset_ids():
    fake_ctx = {"user_id": "u1"}  # no "asset_ids" key
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value=fake_ctx),
    ):
        ctx, asset_ids = await unpack_ctx(_info(object()))

    assert ctx is fake_ctx
    assert asset_ids == []


@pytest.mark.asyncio
async def test_unpack_ctx_coerces_none_to_empty_list():
    """Some upstreams put asset_ids=None into ctx — must still return [], not None."""
    fake_ctx = {"asset_ids": None}
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value=fake_ctx),
    ):
        ctx, asset_ids = await unpack_ctx(_info(object()))

    assert asset_ids == []
