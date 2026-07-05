"""Redis Streams–backed durable event bus.

Distinct from the in-memory SSE EventBus in event_bus.py — that one fans out
to live UI clients only. This one is the persistent log read by background
workers and the correlation engine in later phases.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import redis

from src.shared.event_types.base import Event

logger = logging.getLogger(__name__)


class EventStream:
    """Thin wrapper around Redis Streams.

    One stream per event_type, prefixed by config['stream_prefix'].
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._client = redis.Redis.from_url(config["url"])

    def _stream_name(self, event_type: str) -> str:
        return f"{self._cfg['stream_prefix']}{event_type}"

    def publish(self, event: Event) -> str:
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
        return self._client.xadd(
            stream, fields, maxlen=self._cfg["max_len"], approximate=True
        ).decode()

    def _ensure_group(self, stream: str, group: str, start_at_new: bool) -> None:
        try:
            start_id = "$" if start_at_new else "0"
            self._client.xgroup_create(stream, group, id=start_id, mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                return
            raise

    def subscribe(
        self,
        event_type: str,
        group: str,
        consumer: str,
        block_ms: int = 1000,
        count: int = 100,
        start_at_new: bool = True,
    ):
        """Yield decoded events read from the per-type stream.

        Reads via XREADGROUP with the given consumer group. Caller is
        responsible for calling ack() after successful processing.
        """
        stream = self._stream_name(event_type)
        self._ensure_group(stream, group, start_at_new)
        response = self._client.xreadgroup(
            group, consumer, {stream: ">"}, count=count, block=block_ms
        ) or []
        for _, entries in response:
            for stream_id, fields in entries:
                fields = {k.decode(): v.decode() for k, v in fields.items()}
                yield {
                    "_stream_id": stream_id.decode(),
                    "event_id": fields["event_id"],
                    "event_type": fields["event_type"],
                    "org_id": fields["org_id"],
                    "source_component": fields["source_component"],
                    "timestamp_utc": fields["timestamp_utc"],
                    "payload": json.loads(fields["payload"]),
                }

    def ack(self, event_type: str, group: str, stream_id: str) -> None:
        """Acknowledge a processed message so it leaves the pending list."""
        stream = self._stream_name(event_type)
        self._client.xack(stream, group, stream_id)
