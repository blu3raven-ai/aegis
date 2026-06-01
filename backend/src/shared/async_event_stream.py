"""Async-aware Redis Streams wrapper.

Mirror of EventStream (in event_stream.py) using redis.asyncio for callers
running in asyncio contexts. The sync version is preferred where callers
are sync; this version exists so a FastAPI request handler or asyncio
background task doesn't block the event loop on Redis I/O.

Same serialization (default=str) and stream-naming convention as
EventStream, so consumers can read from either path interchangeably.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import redis.asyncio as aioredis

from src.shared.event_types.base import Event

logger = logging.getLogger(__name__)


class AsyncEventStream:
    """Async wrapper around Redis Streams for asyncio contexts.

    One stream per event_type, prefixed by config['stream_prefix'].
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._client = aioredis.from_url(config["url"])

    def _stream_name(self, event_type: str) -> str:
        return f"{self._cfg['stream_prefix']}{event_type}"

    async def publish(self, event: Event) -> str:
        """Append an event to its per-type stream. Returns Redis stream ID."""
        stream = self._stream_name(event.event_type)
        fields = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "org_id": event.org_id,
            "source_component": event.source_component,
            "timestamp_utc": event.timestamp_utc.isoformat(),
            "payload": json.dumps(event.payload, default=str),
        }
        result = await self._client.xadd(
            stream, fields, maxlen=self._cfg["max_len"], approximate=True
        )
        return result.decode() if isinstance(result, bytes) else result

    async def close(self) -> None:
        """Close the Redis connection."""
        await self._client.aclose()
