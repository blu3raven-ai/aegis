"""CRUD lifecycle coverage for rules/store.py — the rule engine that controls
finding suppression, so its create/read/update/toggle/delete must behave."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.rules import store  # noqa: E402


def _create(**over):
    args = dict(
        category="auto_dismiss", name=f"rule-{uuid.uuid4().hex[:8]}",
        description="test rule", enabled=True, priority=10,
        conditions={"severity": ["low"]}, action={"type": "dismiss"},
        created_by="tester",
    )
    args.update(over)
    return store.create_rule(**args)


@pytest.mark.asyncio
async def test_rule_crud_lifecycle(_create_tables):
    created = _create(name="lifecycle-rule")
    rid = created["id"]
    assert created["name"] == "lifecycle-rule" and created["enabled"] is True

    # read
    got = store.get_rule_by_id(rid)
    assert got is not None and got["id"] == rid

    # update
    updated = store.update_rule(rid, priority=99, description="changed")
    assert updated["priority"] == 99 and updated["description"] == "changed"

    # toggle disables it
    toggled = store.toggle_rule(rid)
    assert toggled["enabled"] is False

    # delete
    assert store.delete_rule(rid) is True
    assert store.get_rule_by_id(rid) is None


@pytest.mark.asyncio
async def test_get_update_delete_missing_rule(_create_tables):
    missing = f"rule_{uuid.uuid4().hex}"
    assert store.get_rule_by_id(missing) is None
    assert store.update_rule(missing, priority=1) is None
    assert store.delete_rule(missing) is False
    assert store.toggle_rule(missing) is None


@pytest.mark.asyncio
async def test_list_rules_filters_by_category_and_enabled(_create_tables):
    tag = uuid.uuid4().hex[:6]
    _create(name=f"a-{tag}", category="auto_dismiss", enabled=True)
    _create(name=f"b-{tag}", category="auto_dismiss", enabled=False)

    all_auto = store.list_rules(category="auto_dismiss")
    names = {r["name"] for r in all_auto}
    assert f"a-{tag}" in names and f"b-{tag}" in names

    enabled_only = store.list_rules(category="auto_dismiss", enabled=True)
    enabled_names = {r["name"] for r in enabled_only}
    assert f"a-{tag}" in enabled_names and f"b-{tag}" not in enabled_names
