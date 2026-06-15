"""CRUD helpers for notification_rules table.

Returns plain dicts so the router layer has no coupling to SQLAlchemy internals.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import NotificationRule
from src.notifications.routing import Rule


def _rule_to_dict(rule: NotificationRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "enabled": rule.enabled,
        "priority": rule.priority,
        "channel_id": rule.channel_id,
        "conditions": rule.conditions,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def _rule_to_domain(rule: NotificationRule) -> Rule:
    return Rule(
        id=rule.id,
        name=rule.name,
        enabled=rule.enabled,
        priority=rule.priority,
        channel_id=rule.channel_id,
        conditions=rule.conditions or {},
    )


# ── CRUD ──────────────────────────────────────────────────────────────────────


def list_rules() -> list[dict[str, Any]]:
    async def _q(session):
        result = await session.execute(
            select(NotificationRule)
            .order_by(NotificationRule.priority.asc(), NotificationRule.created_at.asc())
        )
        return [_rule_to_dict(r) for r in result.scalars().all()]

    return run_db(_q)


def get_rule(rule_id: str) -> dict[str, Any] | None:
    async def _q(session):
        result = await session.execute(
            select(NotificationRule).where(NotificationRule.id == rule_id)
        )
        rule = result.scalars().first()
        return _rule_to_dict(rule) if rule else None

    return run_db(_q)


def create_rule(
    name: str,
    channel_id: int,
    conditions: dict[str, Any],
    priority: int = 100,
    enabled: bool = True,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    rule_id = f"nr_{uuid.uuid4().hex[:16]}"

    async def _q(session):
        rule = NotificationRule(
            id=rule_id,
            name=name,
            enabled=enabled,
            priority=priority,
            channel_id=channel_id,
            conditions=conditions,
            created_at=now,
            updated_at=now,
        )
        session.add(rule)
        await session.flush()
        return _rule_to_dict(rule)

    return run_db(_q)


def update_rule(
    rule_id: str,
    *,
    name: str | None = None,
    enabled: bool | None = None,
    priority: int | None = None,
    channel_id: int | None = None,
    conditions: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)

    async def _q(session):
        result = await session.execute(
            select(NotificationRule).where(NotificationRule.id == rule_id)
        )
        rule = result.scalars().first()
        if rule is None:
            return None
        if name is not None:
            rule.name = name
        if enabled is not None:
            rule.enabled = enabled
        if priority is not None:
            rule.priority = priority
        if channel_id is not None:
            rule.channel_id = channel_id
        if conditions is not None:
            rule.conditions = conditions
        rule.updated_at = now
        await session.flush()
        return _rule_to_dict(rule)

    return run_db(_q)


def delete_rule(rule_id: str) -> bool:
    async def _q(session):
        result = await session.execute(
            select(NotificationRule).where(NotificationRule.id == rule_id)
        )
        rule = result.scalars().first()
        if rule is None:
            return False
        await session.delete(rule)
        return True

    return run_db(_q)


def get_active_rules() -> list[Rule]:
    """Return enabled rules as domain objects, sorted by priority ascending."""
    async def _q(session):
        result = await session.execute(
            select(NotificationRule)
            .where(NotificationRule.enabled == True)  # noqa: E712
            .order_by(NotificationRule.priority.asc(), NotificationRule.created_at.asc())
        )
        return [_rule_to_domain(r) for r in result.scalars().all()]

    return run_db(_q)
