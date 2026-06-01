"""Endpoint shape tests for GET /api/v1/fleet/runners."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.fleet.router import router as fleet_router
from src.fleet.service import RunnerStatus


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(fleet_router)
    return app


@pytest.fixture
def client():
    return TestClient(_make_app(), raise_server_exceptions=True)


def _runner(
    agent_id: str = "runner-abc",
    status: str = "healthy",
    seconds_since: int = 10,
) -> RunnerStatus:
    last_hb = (datetime.now(timezone.utc) - timedelta(seconds=seconds_since)).isoformat()
    return RunnerStatus(
        agent_id=agent_id,
        hostname="node-01",
        scanner_types=["dependencies", "sast"],
        in_flight_jobs=2,
        processed_total=1450,
        last_heartbeat_at=last_hb,
        seconds_since_heartbeat=seconds_since,
        status=status,
    )


# ── Endpoint shape ────────────────────────────────────────────────────────────


def test_list_runners_empty(client: TestClient):
    with patch("src.fleet.router.FleetService") as MockSvc:
        MockSvc.return_value.list_runners.return_value = []
        resp = client.get("/api/v1/fleet/runners")
    assert resp.status_code == 200
    assert resp.json() == {"runners": []}


def test_list_runners_returns_list(client: TestClient):
    runners = [_runner("runner-abc", "healthy"), _runner("runner-xyz", "degraded", 80)]
    with patch("src.fleet.router.FleetService") as MockSvc:
        MockSvc.return_value.list_runners.return_value = runners
        resp = client.get("/api/v1/fleet/runners")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["runners"]) == 2
    assert data["runners"][0]["agent_id"] == "runner-abc"
    assert data["runners"][0]["status"] == "healthy"
    assert data["runners"][1]["status"] == "degraded"


def test_runner_object_has_all_required_fields(client: TestClient):
    runner = _runner()
    with patch("src.fleet.router.FleetService") as MockSvc:
        MockSvc.return_value.list_runners.return_value = [runner]
        resp = client.get("/api/v1/fleet/runners")

    item = resp.json()["runners"][0]
    required_keys = {
        "agent_id", "hostname", "scanner_types", "in_flight_jobs",
        "processed_total", "last_heartbeat_at", "seconds_since_heartbeat", "status",
    }
    assert required_keys.issubset(item.keys())
    assert isinstance(item["scanner_types"], list)
    assert isinstance(item["in_flight_jobs"], int)
    assert isinstance(item["processed_total"], int)
    assert isinstance(item["seconds_since_heartbeat"], int)


def test_runner_status_values(client: TestClient):
    runners = [
        _runner("r1", "healthy"),
        _runner("r2", "degraded"),
        _runner("r3", "dead"),
    ]
    with patch("src.fleet.router.FleetService") as MockSvc:
        MockSvc.return_value.list_runners.return_value = runners
        resp = client.get("/api/v1/fleet/runners")

    statuses = {r["agent_id"]: r["status"] for r in resp.json()["runners"]}
    assert statuses["r1"] == "healthy"
    assert statuses["r2"] == "degraded"
    assert statuses["r3"] == "dead"
