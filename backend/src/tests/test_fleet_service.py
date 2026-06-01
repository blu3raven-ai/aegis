"""Unit tests for FleetService — Redis hash parsing and status derivation.

Uses fakeredis to avoid a real Redis dependency.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


_UNSET = object()


def _make_payload(
    agent_id: str = "runner-abc",
    hostname: str = "node-01",
    scanner_types: list[str] | object = _UNSET,
    in_flight_jobs: int = 2,
    processed_total: int = 1450,
    seconds_ago: int = 5,
) -> str:
    last_hb = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    resolved_types = ["dependencies", "sast"] if scanner_types is _UNSET else scanner_types
    return json.dumps({
        "agent_id": agent_id,
        "hostname": hostname,
        "scanner_types": resolved_types,
        "in_flight_jobs": in_flight_jobs,
        "processed_total": processed_total,
        "last_heartbeat_at": last_hb,
    })


@pytest.fixture
def fake_redis():
    """Return a mock Redis client with a pre-populated hgetall."""
    client = MagicMock()
    return client


# ── Status derivation ────────────────────────────────────────────────────────


def test_healthy_status_under_60s():
    from src.fleet.service import _derive_status
    assert _derive_status(30) == "healthy"
    assert _derive_status(0) == "healthy"
    assert _derive_status(59) == "healthy"


def test_degraded_status_60_to_119s():
    from src.fleet.service import _derive_status
    assert _derive_status(60) == "degraded"
    assert _derive_status(90) == "degraded"
    assert _derive_status(119) == "degraded"


def test_dead_status_120s_and_over():
    from src.fleet.service import _derive_status
    assert _derive_status(120) == "dead"
    assert _derive_status(200) == "dead"


# ── Happy-path parsing ───────────────────────────────────────────────────────


def test_list_runners_returns_parsed_entries():
    from src.fleet.service import FleetService

    entries = {
        "runner-abc": _make_payload(agent_id="runner-abc", seconds_ago=10),
        "runner-xyz": _make_payload(agent_id="runner-xyz", seconds_ago=80),
    }

    with patch("src.fleet.service.redis.Redis.from_url") as mock_from_url:
        mock_client = MagicMock()
        mock_client.hgetall.return_value = entries
        mock_from_url.return_value = mock_client

        svc = FleetService(redis_url="redis://localhost:6379/0")
        runners = svc.list_runners()

    assert len(runners) == 2
    # Sorted by agent_id
    assert runners[0].agent_id == "runner-abc"
    assert runners[1].agent_id == "runner-xyz"
    assert runners[0].status == "healthy"
    assert runners[1].status == "degraded"
    assert runners[0].hostname == "node-01"
    assert runners[0].in_flight_jobs == 2
    assert runners[0].processed_total == 1450
    assert runners[0].scanner_types == ["dependencies", "sast"]


def test_list_runners_seconds_since_heartbeat():
    from src.fleet.service import FleetService

    entries = {"runner-abc": _make_payload(seconds_ago=45)}

    with patch("src.fleet.service.redis.Redis.from_url") as mock_from_url:
        mock_client = MagicMock()
        mock_client.hgetall.return_value = entries
        mock_from_url.return_value = mock_client

        svc = FleetService()
        runners = svc.list_runners()

    # Allow a small delta for test execution time
    assert 44 <= runners[0].seconds_since_heartbeat <= 50


# ── Malformed entries ────────────────────────────────────────────────────────


def test_malformed_entry_skipped():
    """Entries that cannot be parsed must not raise — they are silently dropped."""
    from src.fleet.service import FleetService

    entries = {
        "runner-good": _make_payload(agent_id="runner-good"),
        "runner-bad": "not valid json {{{",
        "runner-missing-fields": json.dumps({"agent_id": "x"}),  # missing last_heartbeat_at
    }

    with patch("src.fleet.service.redis.Redis.from_url") as mock_from_url:
        mock_client = MagicMock()
        mock_client.hgetall.return_value = entries
        mock_from_url.return_value = mock_client

        svc = FleetService()
        runners = svc.list_runners()

    assert len(runners) == 1
    assert runners[0].agent_id == "runner-good"


def test_empty_hash_returns_empty_list():
    from src.fleet.service import FleetService

    with patch("src.fleet.service.redis.Redis.from_url") as mock_from_url:
        mock_client = MagicMock()
        mock_client.hgetall.return_value = {}
        mock_from_url.return_value = mock_client

        svc = FleetService()
        assert svc.list_runners() == []


# ── Scanner types ────────────────────────────────────────────────────────────


def test_empty_scanner_types_handled():
    from src.fleet.service import FleetService

    entries = {"runner-abc": _make_payload(scanner_types=[])}

    with patch("src.fleet.service.redis.Redis.from_url") as mock_from_url:
        mock_client = MagicMock()
        mock_client.hgetall.return_value = entries
        mock_from_url.return_value = mock_client

        svc = FleetService()
        runners = svc.list_runners()

    assert runners[0].scanner_types == []
