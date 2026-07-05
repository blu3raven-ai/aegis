"""Fleet service — reads per-agent state from the Redis hash written by FleetHeartbeat."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

import redis


FLEET_HASH_KEY = "aegis.runners.fleet"

# Status thresholds mirror the TTL window used by FleetHeartbeat
_HEALTHY_THRESHOLD = 60    # < 60s → healthy
_DEGRADED_THRESHOLD = 120  # 60–120s → degraded, >120s → dead


@dataclass
class RunnerStatus:
    agent_id: str
    hostname: str
    scanner_types: list[str]
    in_flight_jobs: int
    processed_total: int
    last_heartbeat_at: str
    seconds_since_heartbeat: int
    status: str  # 'healthy' | 'degraded' | 'dead'


def _derive_status(seconds_since: int) -> str:
    if seconds_since < _HEALTHY_THRESHOLD:
        return "healthy"
    if seconds_since < _DEGRADED_THRESHOLD:
        return "degraded"
    return "dead"


class FleetService:
    """Reads the fleet hash from Redis and assembles RunnerStatus objects."""

    def __init__(self, redis_url: str | None = None) -> None:
        url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client = redis.Redis.from_url(url, decode_responses=True)

    def list_runners(self) -> list[RunnerStatus]:
        """Return all runner entries from the fleet hash.

        Malformed or unparseable entries are silently skipped so one bad
        agent cannot break the fleet view for everyone.
        """
        raw_entries: dict[str, str] = self._client.hgetall(FLEET_HASH_KEY)
        now = datetime.now(timezone.utc)
        results: list[RunnerStatus] = []

        for raw_value in raw_entries.values():
            try:
                payload = json.loads(raw_value)
                last_hb = payload["last_heartbeat_at"]
                last_hb_dt = datetime.fromisoformat(last_hb)
                seconds_since = int((now - last_hb_dt).total_seconds())
                results.append(
                    RunnerStatus(
                        agent_id=str(payload["agent_id"]),
                        hostname=str(payload.get("hostname", "")),
                        scanner_types=list(payload.get("scanner_types") or []),
                        in_flight_jobs=int(payload.get("in_flight_jobs", 0)),
                        processed_total=int(payload.get("processed_total", 0)),
                        last_heartbeat_at=last_hb,
                        seconds_since_heartbeat=max(0, seconds_since),
                        status=_derive_status(max(0, seconds_since)),
                    )
                )
            except (KeyError, ValueError, TypeError):
                # Skip entries that are malformed — fail loudly only in tests
                continue

        # Sort by agent_id for stable ordering
        results.sort(key=lambda r: r.agent_id)
        return results
