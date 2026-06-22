"""Unit tests for the integrations catalog GraphQL resolver.

Covers shape correctness against the static CATALOG and auth enforcement.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.connectors.wizards.catalog import CATALOG
from src.graphql.schema import SettingsQuery


def _info(req=None):
    return SimpleNamespace(context={"request": req or SimpleNamespace()})


@pytest.fixture
def viewer_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": [],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.mark.asyncio
async def test_integrations_catalog_returns_all_connectors(viewer_ctx):
    with patch(
        "src.graphql.schema.has_permission",
        return_value=True,
        create=True,
    ):
        # has_permission is imported inside the resolver; patch via authz module
        pass

    with patch("src.authz.enforcement.has_permission", return_value=True):
        result = await SettingsQuery().integrations_catalog(_info())

    assert result.total == len(CATALOG)
    assert len(result.connectors) == len(CATALOG)
    # First entry's id should match the catalog source order
    assert result.connectors[0].id == CATALOG[0].id


@pytest.mark.asyncio
async def test_integrations_catalog_returns_full_connector_shape(viewer_ctx):
    with patch("src.authz.enforcement.has_permission", return_value=True):
        result = await SettingsQuery().integrations_catalog(_info())

    sample = result.connectors[0]
    src = CATALOG[0]
    assert sample.id == src.id
    assert sample.name == src.name
    assert sample.description == src.description
    assert sample.category == src.category
    assert sample.icon_slug == src.icon_slug
    assert sample.version == src.version
    assert sample.status == src.status
    assert sample.enterprise_only == src.enterprise_only
    assert sample.docs_url == src.docs_url
    assert sample.href == src.href
    # config_fields propagates with the same length as source
    assert len(sample.config_fields) == len(src.config_fields)


@pytest.mark.asyncio
async def test_integrations_catalog_requires_view_settings(viewer_ctx):
    """No view_settings permission → GraphQL error, no leak of catalog data."""
    with patch("src.authz.enforcement.has_permission", return_value=False):
        with pytest.raises(Exception):
            await SettingsQuery().integrations_catalog(_info())
