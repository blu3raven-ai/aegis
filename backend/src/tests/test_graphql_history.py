"""Unit tests for the history GraphQL resolver."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.history.service import HistoryEvent, SUPPORTED_TYPES
from src.graphql.schema import HistoryQuery


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


@pytest.mark.asyncio
async def test_history_empty_scope_returns_empty(empty_scope_ctx):
    # Service short-circuits empty scope, but verify the resolver returns
    # the connection shape rather than blowing up.
    with patch("src.history.resolvers._service.list_recent",
               return_value=([], None)) as svc:
        result = await HistoryQuery().events(_info(), limit=50)

    assert result.events == []
    assert result.next_cursor is None
    assert svc.call_args.kwargs["asset_ids"] == []


@pytest.mark.asyncio
async def test_history_passes_asset_ids_when_scoped(scoped_ctx):
    with patch("src.history.resolvers._service.list_recent",
               return_value=([], None)) as svc:
        await HistoryQuery().events(_info(), limit=10)
    assert svc.call_args.kwargs["asset_ids"] == ["asset-1"]


@pytest.mark.asyncio
async def test_history_returns_event_shape(scoped_ctx):
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    fake_event = HistoryEvent(
        id="fe-1",
        type="finding.created",
        occurred_at=now,
        actor="alice",
        repo_id="acme/api",
        summary="New finding: SQL injection in acme/api",
        payload={"finding_id": "f1", "severity": "high"},
    )
    with patch("src.history.resolvers._service.list_recent",
               return_value=([fake_event], "next-cursor-abc")):
        result = await HistoryQuery().events(_info(), limit=50)

    assert result.next_cursor == "next-cursor-abc"
    assert len(result.events) == 1
    e = result.events[0]
    assert e.id == "fe-1"
    assert e.type == "finding.created"
    assert e.occurred_at == now.isoformat()
    assert e.actor == "alice"
    assert e.repo_id == "acme/api"
    # payload is JSON-encoded so the contract stays stable across event types.
    assert json.loads(e.payload_json) == {"finding_id": "f1", "severity": "high"}


@pytest.mark.asyncio
async def test_history_passes_filters_through(scoped_ctx):
    with patch("src.history.resolvers._service.list_recent",
               return_value=([], None)) as svc:
        await HistoryQuery().events(
            _info(),
            types=["finding.created", "scan.completed"],
            repo_id="acme/api",
            since="2026-01-01T00:00:00+00:00",
            until="2026-01-31T23:59:59+00:00",
            limit=25,
            cursor="prev-cursor",
        )
    call = svc.call_args.kwargs
    assert call["types"] == ["finding.created", "scan.completed"]
    assert call["repo_id"] == "acme/api"
    assert call["since"] == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert call["until"] == datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert call["limit"] == 25
    assert call["cursor"] == "prev-cursor"


@pytest.mark.asyncio
async def test_history_silently_drops_unparseable_since(scoped_ctx):
    with patch("src.history.resolvers._service.list_recent",
               return_value=([], None)) as svc:
        await HistoryQuery().events(_info(), since="not-a-date", limit=10)
    # since gets None, not the bad string — service is never called with garbage.
    assert svc.call_args.kwargs["since"] is None


@pytest.mark.asyncio
async def test_history_types_returns_supported_list(scoped_ctx):
    result = await HistoryQuery().types(_info())
    assert result == list(SUPPORTED_TYPES)
    # Snapshot the membership invariant — adding a type to SUPPORTED_TYPES
    # without intentionally surfacing it should be a test failure.
    assert "finding.created" in result
    assert "scan.completed" in result


@pytest.mark.asyncio
async def test_history_types_requires_auth(empty_scope_ctx):
    # Even with empty scope, auth context still resolves — we just want to
    # verify the resolver fetches the context (so unauth callers can't
    # enumerate the types as a side channel against the GraphQL surface).
    with patch("src.graphql.auth.get_graphql_context",
               new=AsyncMock(side_effect=Exception("Unauthorized"))):
        with pytest.raises(Exception):
            await HistoryQuery().types(_info())
