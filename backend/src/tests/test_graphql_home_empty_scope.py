"""Regression: home dashboard renders for a user with no team grants."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import Query
from src.graphql.types import BreachSummary, EpssTopResponse, SeverityBreachStat


def _info() -> SimpleNamespace:
    return SimpleNamespace(context={"request": SimpleNamespace()})


@pytest.fixture
def empty_scope_ctx():
    with patch(
        "src.graphql.schema.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": [],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.fixture
def one_asset_scope_ctx():
    with patch(
        "src.graphql.schema.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": ["a-1"],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.mark.asyncio
async def test_epss_top_empty_for_empty_scope(empty_scope_ctx):
    result = await Query().epss_top(_info(), org=None, limit=5)
    assert isinstance(result, EpssTopResponse)
    assert result.findings == []
    assert result.count == 0


@pytest.mark.asyncio
async def test_sla_breach_summary_zeroed_for_empty_scope(empty_scope_ctx):
    result = await Query().sla_breach_summary(_info(), org=None)
    assert isinstance(result, BreachSummary)
    for sev in (result.critical, result.high, result.medium, result.low):
        assert isinstance(sev, SeverityBreachStat)
        assert sev.open == 0 and sev.breached == 0 and sev.breached_pct == 0.0


@pytest.mark.asyncio
async def test_epss_top_passes_asset_ids_when_scoped(one_asset_scope_ctx):
    with patch("src.graphql.schema.epss_top") as resolver:
        resolver.return_value = EpssTopResponse(findings=[], count=0)
        await Query().epss_top(_info(), org=None, limit=5)
    resolver.assert_called_once()
    assert resolver.call_args.kwargs["asset_ids"] == ["a-1"]


@pytest.mark.asyncio
async def test_top_repositories_dict_shape_matches_graphql_type(db_session):
    """Regression: get_top_repositories_by_asset_ids dict keys must match
    HomeRepoSummary fields so HomeRepoSummary(**row) in home_analytics succeeds.

    The cutover landed an extra `asset_id` key in this dict and tipped the
    home dashboard into the 'Some data failed to load' error banner because
    HomeRepoSummary(**r) raised TypeError on the unexpected kwarg.
    """
    from uuid import uuid4

    from sqlalchemy import delete

    from src.assets.service import upsert_asset
    from src.db.models import Asset, Finding
    from src.graphql.types import HomeRepoSummary
    from src.shared.home_views import get_top_repositories_by_asset_ids

    # Unique external_ref + identity_key so the test is isolated from any
    # other test that seeds assets in the shared DB.
    suffix = uuid4().hex[:8]
    external_ref = f"github:acme/foo-{suffix}"
    display_name = f"acme/foo-{suffix}"
    identity_key = f"CVE-X-{suffix}"

    asset_id = await upsert_asset(
        db_session, type="repo", source="source_connection",
        external_ref=external_ref, display_name=display_name,
    )
    db_session.add(Finding(
        tool="dependencies", asset_id=asset_id, identity_key=identity_key,
        state="open", severity="critical",
    ))
    await db_session.commit()

    try:
        rows = get_top_repositories_by_asset_ids([asset_id], limit=5)
        assert rows, "expected at least one top repository"
        # Real failure mode: any extra/missing key here breaks the GraphQL
        # response. Constructing the type exercises the same code path
        # home_analytics uses.
        for r in rows:
            HomeRepoSummary(**r)
    finally:
        await db_session.execute(delete(Finding).where(Finding.identity_key == identity_key))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()
