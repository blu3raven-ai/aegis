"""Redis pub/sub notification for queued jobs.

Backend publishes a tiny message ({job_id, scanner_type}) on
`aegis.jobs.queued.<scanner_type>` whenever a job is enqueued. Runner
agents subscribe and pull the actual job via JobQueue. This replaces
the 5-second poll with sub-100ms instant pickup.

Pub/sub is "fire-and-forget" — if a subscriber isn't connected, the
message is lost. The runner falls back to a slower catch-up poll on
reconnect (handled in agent.py subscription mode).
"""
from __future__ import annotations

import json
import os
from typing import Any, Iterator

import redis


_CHANNEL_PREFIX = "aegis.jobs.queued."


class JobQueuedPubSub:
    def __init__(self, redis_url: str | None = None) -> None:
        url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client = redis.Redis.from_url(url)

    def _channel(self, scanner_type: str) -> str:
        return f"{_CHANNEL_PREFIX}{scanner_type}"

    def publish(self, scanner_type: str, *, job_id: str) -> None:
        message = json.dumps({"scanner_type": scanner_type, "job_id": job_id})
        self._client.publish(self._channel(scanner_type), message)

    def subscribe(
        self, scanner_type: str, timeout: float = 1.0,
    ) -> Iterator[dict[str, Any]]:
        """Yield each pub/sub message as a decoded dict.

        Polls for messages until `timeout` seconds have elapsed with no new
        message. Each `get_message` call blocks for at most `_POLL_INTERVAL`
        seconds; we loop until the total idle time exceeds `timeout`. Caller
        is responsible for re-entering subscribe() in a loop for continuous
        listening.
        """
        import time as _time

        _POLL_INTERVAL = 0.1  # seconds per get_message blocking call

        ps = self._client.pubsub()
        ps.subscribe(self._channel(scanner_type))
        deadline = _time.monotonic() + timeout
        try:
            while _time.monotonic() < deadline:
                remaining = deadline - _time.monotonic()
                poll = min(_POLL_INTERVAL, remaining)
                msg = ps.get_message(ignore_subscribe_messages=True, timeout=poll)
                if msg is not None:
                    yield json.loads(msg["data"].decode())
                    # Reset deadline after receiving a message so caller gets
                    # a full timeout window for the next message.
                    deadline = _time.monotonic() + timeout
        finally:
            ps.unsubscribe()
            ps.close()
