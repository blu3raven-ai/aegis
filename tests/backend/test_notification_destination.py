"""Tests for notification destination CRUD helpers.

Uses the testcontainers Postgres fixture from conftest.py (runs Alembic
migrations before the session starts via the engine initialisation).
"""
from __future__ import annotations

import pytest
from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import NotificationDelivery, NotificationDestination
from src.notifications.destination import (
    create_destination,
    delete_destination,
    get_destination,
    get_enabled_destinations_for_org,
    list_deliveries_for_destination,
    list_destinations,
    record_delivery,
    update_destination,
)

ORG = "acme-org"


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(NotificationDelivery))
        await session.execute(delete(NotificationDestination))

    run_db(_del)
    yield


# ── create ────────────────────────────────────────────────────────────────────


def test_create_destination_returns_dict():
    dest = create_destination(
        org_id=ORG,
        destination_type="slack",
        name="sec-alerts",
        config={"webhook_url": "https://hooks.example.org/abc"},
    )
    assert dest["id"] is not None
    assert dest["org_id"] == ORG
    assert dest["destination_type"] == "slack"
    assert dest["name"] == "sec-alerts"
    assert dest["enabled"] is True
    assert dest["event_filter"] is None


def test_create_destination_with_event_filter():
    dest = create_destination(
        org_id=ORG,
        destination_type="webhook",
        name="critical-only",
        config={"url": "https://hooks.example.org/wh", "secret": "s3cr3t"},
        event_filter={"event_types": ["chain.created"], "min_severity": "high"},
    )
    assert dest["event_filter"]["min_severity"] == "high"


def test_create_destination_invalid_type():
    with pytest.raises(ValueError, match="destination_type"):
        create_destination(
            org_id=ORG,
            destination_type="fax",
            name="bad",
            config={},
        )


def test_create_destination_email():
    dest = create_destination(
        org_id=ORG,
        destination_type="email",
        name="email-dest",
        config={"to_addresses": ["security@example.com"]},
    )
    assert dest["destination_type"] == "email"


# ── list ──────────────────────────────────────────────────────────────────────


def test_list_destinations_empty():
    assert list_destinations(ORG) == []


def test_list_destinations_multiple():
    create_destination(ORG, "slack", "dest-a", {"webhook_url": "https://hooks.example.org/a"})
    create_destination(ORG, "email", "dest-b", {"to_addresses": ["a@example.com"]})
    dests = list_destinations(ORG)
    assert len(dests) == 2
    names = {d["name"] for d in dests}
    assert names == {"dest-a", "dest-b"}


def test_list_destinations_org_isolation():
    create_destination(ORG, "slack", "dest-x", {"webhook_url": "https://hooks.example.org/x"})
    # Different org should return nothing
    assert list_destinations("other-org") == []


# ── get ───────────────────────────────────────────────────────────────────────


def test_get_destination_returns_none_for_missing():
    assert get_destination(99999, ORG) is None


def test_get_destination_returns_existing():
    dest = create_destination(ORG, "slack", "test-dest", {"webhook_url": "https://hooks.example.org/t"})
    fetched = get_destination(dest["id"], ORG)
    assert fetched is not None
    assert fetched["id"] == dest["id"]


def test_get_destination_wrong_org_returns_none():
    dest = create_destination(ORG, "slack", "test-dest", {"webhook_url": "https://hooks.example.org/t"})
    assert get_destination(dest["id"], "other-org") is None


# ── update ────────────────────────────────────────────────────────────────────


def test_update_destination_name():
    dest = create_destination(ORG, "slack", "old-name", {"webhook_url": "https://hooks.example.org/u"})
    updated = update_destination(dest["id"], ORG, name="new-name")
    assert updated["name"] == "new-name"


def test_update_destination_enabled():
    dest = create_destination(ORG, "slack", "toggle-dest", {"webhook_url": "https://hooks.example.org/tog"})
    updated = update_destination(dest["id"], ORG, enabled=False)
    assert updated["enabled"] is False


def test_update_destination_not_found_returns_none():
    result = update_destination(99999, ORG, name="x")
    assert result is None


# ── delete ────────────────────────────────────────────────────────────────────


def test_delete_destination_returns_true():
    dest = create_destination(ORG, "slack", "to-delete", {"webhook_url": "https://hooks.example.org/d"})
    assert delete_destination(dest["id"], ORG) is True
    assert get_destination(dest["id"], ORG) is None


def test_delete_destination_not_found_returns_false():
    assert delete_destination(99999, ORG) is False


# ── enabled destinations ──────────────────────────────────────────────────────


def test_get_enabled_destinations_skips_disabled():
    create_destination(ORG, "slack", "enabled-dest", {"webhook_url": "https://hooks.example.org/en"}, enabled=True)
    dest2 = create_destination(ORG, "slack", "disabled-dest", {"webhook_url": "https://hooks.example.org/dis"}, enabled=False)
    update_destination(dest2["id"], ORG, enabled=False)
    enabled = get_enabled_destinations_for_org(ORG)
    names = {d["name"] for d in enabled}
    assert "enabled-dest" in names
    assert "disabled-dest" not in names


# ── delivery records ──────────────────────────────────────────────────────────


def test_record_delivery_creates_row():
    dest = create_destination(ORG, "slack", "delivery-dest", {"webhook_url": "https://hooks.example.org/dl"})
    rec = record_delivery(dest["id"], "evt123", "chain.created", "delivered")
    assert rec["status"] == "delivered"
    assert rec["event_id"] == "evt123"


def test_record_delivery_upsert_updates_status():
    dest = create_destination(ORG, "slack", "upsert-dest", {"webhook_url": "https://hooks.example.org/up"})
    record_delivery(dest["id"], "evt456", "chain.created", "failed", error="timeout")
    updated = record_delivery(dest["id"], "evt456", "chain.created", "delivered")
    assert updated["status"] == "delivered"


def test_list_deliveries_for_destination():
    dest = create_destination(ORG, "slack", "list-del-dest", {"webhook_url": "https://hooks.example.org/ld"})
    record_delivery(dest["id"], "ev1", "chain.created", "delivered")
    record_delivery(dest["id"], "ev2", "finding.created", "failed")
    deliveries = list_deliveries_for_destination(dest["id"])
    assert len(deliveries) == 2
