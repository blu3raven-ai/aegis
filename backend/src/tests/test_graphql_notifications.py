"""Unit tests for notification GraphQL resolvers.

Covers notification_destinations (Task 2). Tasks 3-5 append more tests here
for deliveries, rules, inbox, unread_count.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import NotificationsQuery


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace(user_sub="u1")})


@pytest.fixture
def admin_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u1", "role": "admin", "asset_ids": [],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.mark.asyncio
async def test_notification_destinations_requires_manage_settings(admin_ctx):
    with patch("src.authz.enforcement.has_permission", return_value=False):
        with pytest.raises(Exception):
            await NotificationsQuery().destinations(_info())


@pytest.mark.asyncio
async def test_notification_destinations_returns_typed_list(admin_ctx):
    fake = [
        {"id": 1, "destination_type": "slack", "name": "ops-channel",
         "config": {"webhook_url": "https://hooks.slack.com/xxx"},
         "enabled": True, "event_filter": {"severity": ["high", "critical"]},
         "created_at": "2026-01-01T00:00:00+00:00",
         "updated_at": "2026-01-01T00:00:00+00:00"},
    ]
    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.notifications.resolvers.list_destinations",
              return_value=fake),
    ):
        result = await NotificationsQuery().destinations(_info())

    assert len(result) == 1
    assert result[0].id == 1
    assert result[0].destination_type == "slack"
    assert result[0].name == "ops-channel"
    assert result[0].enabled is True


@pytest.mark.asyncio
async def test_notification_deliveries_requires_manage_settings(admin_ctx):
    with patch("src.authz.enforcement.has_permission", return_value=False):
        with pytest.raises(Exception):
            await NotificationsQuery().deliveries(_info(), destination_id=1)


@pytest.mark.asyncio
async def test_notification_deliveries_404_when_destination_missing(admin_ctx):
    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.notifications.resolvers.get_destination",
              return_value=None),
    ):
        with pytest.raises(Exception):
            await NotificationsQuery().deliveries(_info(), destination_id=999)


@pytest.mark.asyncio
async def test_notification_deliveries_returns_typed_list(admin_ctx):
    fake_deliveries = [
        {"id": "d-1", "destination_id": 1, "event_id": "e-1",
         "event_type": "finding.created", "status": "delivered",
         "payload_summary": "high-severity CVE in acme/api",
         "response_code": 200, "error": None,
         "attempted_at": "2026-01-01T00:00:00+00:00"},
    ]
    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.notifications.resolvers.get_destination",
              return_value={"id": 1}),
        patch("src.notifications.resolvers.list_deliveries_for_destination",
              return_value=fake_deliveries),
    ):
        result = await NotificationsQuery().deliveries(_info(), destination_id=1)

    assert len(result) == 1
    assert result[0].id == "d-1"
    assert result[0].status == "delivered"
    assert result[0].response_code == 200


@pytest.mark.asyncio
async def test_notification_deliveries_clamps_limit(admin_ctx):
    """REST clamped at min(limit, 200). Mirror that behaviour."""
    captured: dict = {}

    def _fake_list(dest_id, *, limit):
        captured["limit"] = limit
        return []

    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.notifications.resolvers.get_destination",
              return_value={"id": 1}),
        patch("src.notifications.resolvers.list_deliveries_for_destination",
              side_effect=_fake_list),
    ):
        await NotificationsQuery().deliveries(_info(), destination_id=1, limit=500)

    assert captured["limit"] == 200


@pytest.mark.asyncio
async def test_notification_rules_requires_manage_settings(admin_ctx):
    with patch("src.authz.enforcement.has_permission", return_value=False):
        with pytest.raises(Exception):
            await NotificationsQuery().rules(_info())


@pytest.mark.asyncio
async def test_notification_rules_returns_typed_list(admin_ctx):
    fake_rules = [
        {"id": "r-1", "name": "high sev to ops",
         "channel_id": 1, "conditions": {"severity": ["high", "critical"]},
         "priority": 10, "enabled": True,
         "created_at": "2026-01-01T00:00:00+00:00",
         "updated_at": "2026-01-01T00:00:00+00:00"},
    ]
    with (
        patch("src.authz.enforcement.has_permission", return_value=True),
        patch("src.notifications.resolvers.list_rules",
              return_value=fake_rules),
    ):
        result = await NotificationsQuery().rules(_info())

    assert len(result) == 1
    assert result[0].id == "r-1"
    assert result[0].channel_id == 1
    assert result[0].enabled is True
    assert result[0].priority == 10


def _info_with_state(user_sub: str = "u1"):
    """Info object with request.state.user_sub — for per-user resolver tests."""
    state = SimpleNamespace(user_sub=user_sub)
    request = SimpleNamespace(state=state)
    return SimpleNamespace(context={"request": request})


@pytest.mark.asyncio
async def test_notifications_inbox_returns_user_scoped_list(admin_ctx):
    fake = [
        {"id": "n-1", "type": "finding.assigned",
         "category": "finding", "severity": "high",
         "title": "You were assigned a finding", "message": "CVE-2026-1234",
         "context": {}, "link": "/findings/42",
         "createdAt": "2026-01-01T00:00:00+00:00", "read": False},
    ]
    with patch(
        "src.notifications.resolvers.get_notifications",
        return_value=(fake, 1),
    ):
        result = await NotificationsQuery().inbox(_info_with_state())

    assert result.total == 1
    assert len(result.notifications) == 1
    assert result.notifications[0].id == "n-1"
    assert result.notifications[0].severity == "high"


@pytest.mark.asyncio
async def test_notifications_inbox_filters_and_paginates(admin_ctx):
    captured: dict = {}

    def _fake(user_id, *, unread_only, limit, offset):
        captured["user_id"] = user_id
        captured["unread_only"] = unread_only
        captured["limit"] = limit
        captured["offset"] = offset
        return ([], 0)

    with patch(
        "src.notifications.resolvers.get_notifications",
        side_effect=_fake,
    ):
        await NotificationsQuery().inbox(
            _info_with_state(), unread_only=True, limit=25, offset=50,
        )

    assert captured["user_id"] == "u1"
    assert captured["unread_only"] is True
    assert captured["limit"] == 25
    assert captured["offset"] == 50


@pytest.mark.asyncio
async def test_notifications_unread_count_returns_int(admin_ctx):
    with patch(
        "src.notifications.resolvers.get_unread_count",
        return_value=7,
    ):
        result = await NotificationsQuery().unread_count(_info_with_state())

    assert result == 7


@pytest.mark.asyncio
async def test_notifications_unread_count_zero_when_none(admin_ctx):
    with patch(
        "src.notifications.resolvers.get_unread_count",
        return_value=0,
    ):
        result = await NotificationsQuery().unread_count(_info_with_state())

    assert result == 0
