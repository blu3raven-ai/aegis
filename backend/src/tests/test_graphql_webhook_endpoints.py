"""Unit tests for the webhook_endpoints GraphQL resolver.

Mirrors the REST endpoint at GET /api/v1/settings/webhooks. Returns the
same {endpoints, providers} shape so the frontend client transformation
stays trivial. Permission gated on MANAGE_SETTINGS.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import SettingsQuery


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace()})


@pytest.fixture
def admin_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "admin", "asset_ids": [],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.mark.asyncio
async def test_webhook_endpoints_requires_manage_settings(admin_ctx):
    with patch("src.authz.enforcement.has_permission", return_value=False):
        with pytest.raises(Exception):
            await SettingsQuery().webhook_endpoints(_info())


@pytest.mark.asyncio
async def test_webhook_endpoints_returns_list_with_providers(admin_ctx):
    fake_endpoints = [
        {"id": "we-1", "provider": "github", "last4": "***abc",
         "createdAt": "2026-01-01T00:00:00+00:00",
         "updatedAt": "2026-01-01T00:00:00+00:00",
         "rotatedAt": None},
        {"id": "we-2", "provider": "gitlab", "last4": "***def",
         "createdAt": "2026-01-02T00:00:00+00:00",
         "updatedAt": "2026-01-02T00:00:00+00:00",
         "rotatedAt": "2026-01-15T00:00:00+00:00"},
    ]
    fake_providers = ["github", "gitlab", "bitbucket"]

    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.settings.webhooks.resolvers.run_db",
              return_value={"endpoints": fake_endpoints, "providers": fake_providers}),
    ):
        result = await SettingsQuery().webhook_endpoints(_info())

    assert len(result.endpoints) == 2
    assert result.endpoints[0].id == "we-1"
    assert result.endpoints[0].provider == "github"
    assert result.endpoints[0].masked_secret == "***abc"
    assert result.endpoints[0].updated_at == "2026-01-01T00:00:00+00:00"
    assert result.endpoints[0].rotated_at is None
    assert result.endpoints[1].rotated_at == "2026-01-15T00:00:00+00:00"
    assert result.providers == fake_providers


@pytest.mark.asyncio
async def test_webhook_endpoints_returns_empty_when_none(admin_ctx):
    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.settings.webhooks.resolvers.run_db",
              return_value={"endpoints": [], "providers": ["github"]}),
    ):
        result = await SettingsQuery().webhook_endpoints(_info())

    assert result.endpoints == []
    assert result.providers == ["github"]
