"""Unit tests for sources.scanRuns — permission gate + asset-scope filter.

The pre-fix resolver had no permission check and returned every run for
every asset under any org the caller had a grant in, leaking activity
across asset boundaries within an org. These tests lock in the fixed
contract: VIEW_FINDINGS required, results scoped to asset_ids, no
cross-asset fan-out.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from graphql import GraphQLError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.sources import scan_runs_resolvers  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_OTHER_ASSET_ID = "ffffffff-1111-2222-3333-444444444444"


def _ctx(asset_ids: list[str]) -> dict:
    return {
        "request": SimpleNamespace(),
        "asset_ids": asset_ids,
    }


@pytest.mark.asyncio
async def test_scan_runs_requires_view_findings():
    """Caller without view_findings is rejected before any storage hit."""
    called = {"runs": False}

    def fake_list(*args, **kwargs):
        called["runs"] = True
        return []

    with patch("src.sources.scan_runs_resolvers._require_view_findings",
               side_effect=GraphQLError(
                   "Permission denied: view_findings",
                   extensions={"code": "PERMISSION_DENIED"},
               )), \
         patch("src.sources.scan_runs_resolvers._list_runs_for_assets", side_effect=fake_list):
        with pytest.raises(GraphQLError) as exc_info:
            await scan_runs_resolvers.scan_runs(
                tool="dependencies_scanning", limit=10,
                info_context=_ctx([_FAKE_ASSET_ID]),
            )
    assert exc_info.value.extensions.get("code") == "PERMISSION_DENIED"
    assert called["runs"] is False


@pytest.mark.asyncio
async def test_scan_runs_returns_empty_for_unknown_tool():
    """Unknown tool short-circuits to [] without touching storage."""
    called = {"runs": False}

    def fake_list(*args, **kwargs):
        called["runs"] = True
        return []

    with patch("src.sources.scan_runs_resolvers._require_view_findings", return_value=None), \
         patch("src.sources.scan_runs_resolvers._list_runs_for_assets", side_effect=fake_list):
        result = await scan_runs_resolvers.scan_runs(
            tool="garbage", limit=10, info_context=_ctx([_FAKE_ASSET_ID]),
        )
    assert result == []
    assert called["runs"] is False


@pytest.mark.asyncio
async def test_scan_runs_empty_scope_returns_empty():
    """asset_ids=[] short-circuits before storage — fail-closed BOLA gate."""
    called = {"runs": False}

    def fake_list(*args, **kwargs):
        called["runs"] = True
        return []

    with patch("src.sources.scan_runs_resolvers._require_view_findings", return_value=None), \
         patch("src.sources.scan_runs_resolvers._list_runs_for_assets", side_effect=fake_list):
        result = await scan_runs_resolvers.scan_runs(
            tool="dependencies_scanning", limit=10, info_context=_ctx([]),
        )
    assert result == []
    assert called["runs"] is False


@pytest.mark.asyncio
async def test_scan_runs_passes_only_callers_asset_ids_to_storage():
    """The storage helper receives EXACTLY the caller's scoped asset_ids,
    not a broader set derived from org membership. This is the BOLA fix
    locked in — the pre-fix code expanded asset_ids → org_keys and fetched
    every run in those orgs."""
    captured: dict = {}

    def fake_list(tool, asset_ids, *, limit):
        captured["tool"] = tool
        captured["asset_ids"] = asset_ids
        captured["limit"] = limit
        return [
            {
                "id": "run-1", "org": "acme", "status": "completed",
                "createdAt": "2026-06-01T00:00:00Z",
                "startedAt": "2026-06-01T00:00:00Z",
                "finishedAt": "2026-06-01T00:01:00Z",
                "durationSeconds": 60, "findingsCount": 3, "error": None,
            },
        ]

    with patch("src.sources.scan_runs_resolvers._require_view_findings", return_value=None), \
         patch("src.sources.scan_runs_resolvers._list_runs_for_assets", side_effect=fake_list):
        result = await scan_runs_resolvers.scan_runs(
            tool="dependencies_scanning", limit=10,
            info_context=_ctx([_FAKE_ASSET_ID, _OTHER_ASSET_ID]),
        )

    assert captured["tool"] == "dependencies_scanning"
    assert captured["asset_ids"] == [_FAKE_ASSET_ID, _OTHER_ASSET_ID]
    assert captured["limit"] == 10
    assert len(result) == 1
    assert result[0].id == "run-1"
    assert result[0].findings_count == 3


@pytest.mark.asyncio
async def test_scan_runs_accepts_all_four_supported_tools():
    """All four scanner tools are valid and reach storage with the same
    contract — guards against a future regression that hard-codes one tool."""
    captured_tools: list[str] = []

    def fake_list(tool, asset_ids, *, limit):
        captured_tools.append(tool)
        return []

    with patch("src.sources.scan_runs_resolvers._require_view_findings", return_value=None), \
         patch("src.sources.scan_runs_resolvers._list_runs_for_assets", side_effect=fake_list):
        for tool in ("code_scanning", "container_scanning", "dependencies_scanning", "secret_scanning"):
            await scan_runs_resolvers.scan_runs(
                tool=tool, limit=10, info_context=_ctx([_FAKE_ASSET_ID]),
            )

    assert captured_tools == [
        "code_scanning", "container_scanning", "dependencies_scanning", "secret_scanning",
    ]
