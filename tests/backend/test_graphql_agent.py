"""Unit tests for the agent-scanning GraphQL resolver.

The surface is just `agentScanning.counts`. Covers empty scope (fail-closed) and
scope propagation to the underlying count helper with the correct tool tag.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import AgentScanningQuery


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
            "user_id": "u", "role": "viewer", "asset_ids": ["a1", "a2"],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.mark.asyncio
async def test_agent_counts_empty_scope_returns_zeros(empty_scope_ctx):
    """Empty asset_ids must propagate as empty and return zero counts."""
    fake_counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    with patch(
        "src.scans.resolvers.get_severity_counts_by_asset_ids",
        return_value=fake_counts,
    ) as helper:
        result = await AgentScanningQuery().counts(_info())

    helper.assert_called_once_with([], tool="agent_scanning", state="open")
    assert result.total == 0
    assert result.critical == 0


@pytest.mark.asyncio
async def test_agent_counts_returns_helper_counts(scoped_ctx):
    fake_counts = {"total": 7, "critical": 1, "high": 2, "medium": 3, "low": 1}
    with patch(
        "src.scans.resolvers.get_severity_counts_by_asset_ids",
        return_value=fake_counts,
    ) as helper:
        result = await AgentScanningQuery().counts(_info())

    helper.assert_called_once_with(["a1", "a2"], tool="agent_scanning", state="open")
    assert result.total == 7
    assert result.critical == 1
    assert result.high == 2
    assert result.medium == 3
    assert result.low == 1


@pytest.mark.asyncio
async def test_agent_counts_only_counts_agent_scanning_tool(scoped_ctx):
    """Defends the tool filter — must NOT roll up other scanner tools."""
    called_with: dict = {}

    def _spy(asset_ids, *, tool, state):
        called_with["tool"] = tool
        called_with["state"] = state
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    with patch(
        "src.scans.resolvers.get_severity_counts_by_asset_ids",
        side_effect=_spy,
    ):
        await AgentScanningQuery().counts(_info())

    assert called_with["tool"] == "agent_scanning"
    assert called_with["state"] == "open"
