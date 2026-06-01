"""Tests for the /api/v1/notifications/* REST endpoints.

Uses a minimal FastAPI app (no lifespan, no JWT) so tests run without a
live Postgres or Redis setup — the real DB fixtures from conftest.py
back the CRUD calls.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import NotificationDelivery, NotificationDestination
from src.notifications.admin_router import router as notifications_admin_router

ORG = "acme-org"


def _require_permission_noop(request: Request, permission: str) -> None:
    """Skip RBAC in tests — unit tests cover the permission gate separately."""
    pass


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(NotificationDelivery))
        await session.execute(delete(NotificationDestination))
    run_db(_del)
    yield


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        "src.notifications.admin_router.require_permission",
        _require_permission_noop,
    )
    mini = FastAPI()
    mini.include_router(notifications_admin_router)
    return TestClient(mini, raise_server_exceptions=True)


# ── GET /destinations ─────────────────────────────────────────────────────────


def test_list_destinations_empty(client):
    resp = client.get(f"/api/v1/notifications/destinations?org_id={ORG}")
    assert resp.status_code == 200
    assert resp.json() == {"destinations": []}


def test_list_destinations_populated(client):
    client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "slack",
            "name": "test-slack",
            "config": {"webhook_url": "https://hooks.example.org/test"},
        },
    )
    resp = client.get(f"/api/v1/notifications/destinations?org_id={ORG}")
    assert resp.status_code == 200
    dests = resp.json()["destinations"]
    assert len(dests) == 1
    assert dests[0]["name"] == "test-slack"


# ── POST /destinations ────────────────────────────────────────────────────────


def test_create_destination_returns_201(client):
    resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "webhook",
            "name": "my-webhook",
            "config": {"url": "https://hooks.example.org/wh", "secret": "abc"},
            "event_filter": {"min_severity": "high"},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "my-webhook"
    assert data["event_filter"]["min_severity"] == "high"


def test_create_destination_invalid_type_returns_422(client):
    resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "fax",
            "name": "bad",
            "config": {},
        },
    )
    assert resp.status_code == 422


def test_create_destination_duplicate_name_returns_409(client):
    body = {
        "org_id": ORG,
        "destination_type": "email",
        "name": "dup-dest",
        "config": {"to_addresses": ["a@example.com"]},
    }
    client.post("/api/v1/notifications/destinations", json=body)
    resp = client.post("/api/v1/notifications/destinations", json=body)
    assert resp.status_code == 409


# ── GET /destinations/{id} ────────────────────────────────────────────────────


def test_get_destination_by_id(client):
    create_resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "slack",
            "name": "single-dest",
            "config": {"webhook_url": "https://hooks.example.org/s"},
        },
    )
    dest_id = create_resp.json()["id"]
    resp = client.get(f"/api/v1/notifications/destinations/{dest_id}?org_id={ORG}")
    assert resp.status_code == 200
    assert resp.json()["id"] == dest_id


def test_get_destination_not_found(client):
    resp = client.get(f"/api/v1/notifications/destinations/99999?org_id={ORG}")
    assert resp.status_code == 404


# ── PUT /destinations/{id} ────────────────────────────────────────────────────


def test_update_destination(client):
    create_resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "slack",
            "name": "upd-dest",
            "config": {"webhook_url": "https://hooks.example.org/u"},
        },
    )
    dest_id = create_resp.json()["id"]
    resp = client.put(
        f"/api/v1/notifications/destinations/{dest_id}?org_id={ORG}",
        json={"enabled": False},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_update_destination_not_found(client):
    resp = client.put(
        f"/api/v1/notifications/destinations/99999?org_id={ORG}",
        json={"enabled": False},
    )
    assert resp.status_code == 404


# ── DELETE /destinations/{id} ─────────────────────────────────────────────────


def test_delete_destination_returns_204(client):
    create_resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "slack",
            "name": "del-dest",
            "config": {"webhook_url": "https://hooks.example.org/del"},
        },
    )
    dest_id = create_resp.json()["id"]
    resp = client.delete(f"/api/v1/notifications/destinations/{dest_id}?org_id={ORG}")
    assert resp.status_code == 204
    # Confirm gone
    assert client.get(f"/api/v1/notifications/destinations/{dest_id}?org_id={ORG}").status_code == 404


def test_delete_destination_not_found(client):
    resp = client.delete(f"/api/v1/notifications/destinations/99999?org_id={ORG}")
    assert resp.status_code == 404


# ── GET /destinations/{id}/deliveries ────────────────────────────────────────


def test_list_deliveries_empty(client):
    create_resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": ORG,
            "destination_type": "slack",
            "name": "deliv-dest",
            "config": {"webhook_url": "https://hooks.example.org/deliv"},
        },
    )
    dest_id = create_resp.json()["id"]
    resp = client.get(f"/api/v1/notifications/destinations/{dest_id}/deliveries?org_id={ORG}")
    assert resp.status_code == 200
    assert resp.json()["deliveries"] == []
