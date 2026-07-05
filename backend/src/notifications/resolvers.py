"""GraphQL resolvers for the notifications surface.

Reads (destinations, deliveries, rules, inbox, unread count) live on GraphQL so
the frontend can compose them into dashboard views with a single round-trip.
Writes stay on REST so HTTP-level audit / CSRF / rate-limit hooks apply
uniformly. Admin reads gate on MANAGE_SETTINGS; per-user inbox queries scope on
request.state.user_sub.
"""
from __future__ import annotations

from typing import Optional

import strawberry

from src.notifications.destination import (
    get_destination,
    list_deliveries_for_destination,
    list_destinations,
    redact_config,
)
from src.notifications.rules_model import list_rules
from src.notifications.store import get_notifications, get_unread_count
from src.graphql.resolver_utils import raise_bad_input


@strawberry.type
class NotificationDestination:
    id: int
    destination_type: str
    name: str
    config: strawberry.scalars.JSON
    enabled: bool
    event_filter: strawberry.scalars.JSON
    created_at: Optional[str]
    updated_at: Optional[str]


def _dest_to_gql(d: dict) -> NotificationDestination:
    return NotificationDestination(
        id=int(d.get("id", 0)),
        destination_type=str(d.get("destination_type", "")),
        name=str(d.get("name", "")),
        # Defence-in-depth: _dest_to_dict already redacts, but re-apply so a
        # dict reaching this serializer by another path can't leak secrets.
        config=redact_config(d.get("config") or {}),
        enabled=bool(d.get("enabled", False)),
        event_filter=d.get("event_filter") or {},
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
    )


def notification_destinations() -> list[NotificationDestination]:
    return [_dest_to_gql(d) for d in list_destinations()]


@strawberry.type
class NotificationDelivery:
    id: str
    destination_id: int
    event_id: str
    event_type: str
    status: str
    payload_summary: Optional[str]
    response_code: Optional[int]
    error: Optional[str]
    attempted_at: Optional[str]


def _delivery_to_gql(d: dict) -> NotificationDelivery:
    return NotificationDelivery(
        id=str(d.get("id", "")),
        destination_id=int(d.get("destination_id", 0)),
        event_id=str(d.get("event_id", "")),
        event_type=str(d.get("event_type", "")),
        status=str(d.get("status", "")),
        payload_summary=d.get("payload_summary"),
        response_code=d.get("response_code"),
        error=d.get("error"),
        attempted_at=d.get("attempted_at"),
    )


def notification_deliveries(*, destination_id: int, limit: int = 50) -> list[NotificationDelivery]:
    if get_destination(destination_id) is None:
        raise_bad_input(f"destination {destination_id} not found")
    clamped = min(max(1, int(limit)), 200)
    return [_delivery_to_gql(d) for d in list_deliveries_for_destination(destination_id, limit=clamped)]


@strawberry.type
class NotificationRule:
    id: str
    name: str
    channel_id: int
    conditions: strawberry.scalars.JSON
    priority: int
    enabled: bool
    created_at: Optional[str]
    updated_at: Optional[str]


def _rule_to_gql(r: dict) -> NotificationRule:
    return NotificationRule(
        id=str(r.get("id", "")),
        name=str(r.get("name", "")),
        channel_id=int(r.get("channel_id", 0)),
        conditions=r.get("conditions") or {},
        priority=int(r.get("priority", 0)),
        enabled=bool(r.get("enabled", False)),
        created_at=r.get("created_at"),
        updated_at=r.get("updated_at"),
    )


def notification_rules() -> list[NotificationRule]:
    return [_rule_to_gql(r) for r in list_rules()]


@strawberry.type
class InboxNotification:
    id: str
    type: str
    category: str
    severity: str
    title: str
    message: str
    context: strawberry.scalars.JSON
    link: Optional[str]
    created_at: str
    read: bool


@strawberry.type
class NotificationsInbox:
    notifications: list[InboxNotification]
    total: int


def _inbox_to_gql(n: dict) -> InboxNotification:
    return InboxNotification(
        id=str(n.get("id", "")),
        type=str(n.get("type", "")),
        category=str(n.get("category", "")),
        severity=str(n.get("severity", "info")),
        title=str(n.get("title", "")),
        message=str(n.get("message", "")),
        context=n.get("context") or {},
        link=n.get("link"),
        created_at=str(n.get("createdAt", "")),
        read=bool(n.get("read", False)),
    )


def notifications_inbox(
    *,
    user_id: str,
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> NotificationsInbox:
    clamped_limit = min(max(1, int(limit)), 200)
    clamped_offset = max(0, int(offset))
    rows, total = get_notifications(
        user_id, unread_only=unread_only, limit=clamped_limit, offset=clamped_offset,
    )
    return NotificationsInbox(
        notifications=[_inbox_to_gql(n) for n in rows],
        total=int(total),
    )


def notifications_unread_count(*, user_id: str) -> int:
    return int(get_unread_count(user_id))
