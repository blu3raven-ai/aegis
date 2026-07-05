# backend/src/shared/event_bus.py
"""In-memory pub/sub event bus for SSE streaming."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, AsyncGenerator

logger = logging.getLogger(__name__)

MAX_QUEUE_SIZE = 256
MAX_CONNECTIONS_PER_USER = 3
SUBSCRIBER_TTL_SECONDS = 120


@dataclass
class Event:
    """A single event to be published to SSE clients."""
    event_type: str
    data: dict[str, Any]
    require_admin: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_sse(self, event_id: int) -> str:
        """Serialize to SSE wire format."""
        payload = json.dumps(self.data, separators=(",", ":"))
        return f"id:{event_id}\nevent:{self.event_type}\ndata:{payload}\n\n"


@dataclass
class _Subscriber:
    user_id: str
    role: str
    queue: asyncio.Queue[Event | None]
    created_at: float = field(default_factory=time.time)
    last_read_at: float = field(default_factory=time.time)


class EventBus:
    """Fan-out pub/sub. One asyncio.Queue per connected SSE client."""

    def __init__(self) -> None:
        self._subscribers: dict[int, _Subscriber] = {}
        self._lock = Lock()
        self._next_id = 0
        self._event_counter = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listeners: dict[int, Any] = {}
        self._listener_counter = 0

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Store the main event loop for sync->async bridging."""
        self._loop = loop

    def register_listener(self, callback: Any) -> int:
        """Register a synchronous callback to receive all published events.

        Returns a token (int) that can be passed to unregister_listener() to stop
        receiving events. The callback will be called with each Event object,
        synchronously during publish().

        If the callback raises an exception, it is logged and does not affect
        other listeners or the publish() call.
        """
        with self._lock:
            token = self._listener_counter
            self._listener_counter += 1
            self._listeners[token] = callback
            return token

    def unregister_listener(self, token: int) -> None:
        """Stop receiving events for a registered listener token."""
        with self._lock:
            self._listeners.pop(token, None)

    def _count_user_connections(self, user_id: str) -> int:
        return sum(1 for s in self._subscribers.values() if s.user_id == user_id)

    def subscribe(
        self, user_id: str, role: str,
    ) -> tuple["_Subscriber", AsyncGenerator[Event, None]]:
        """Return (subscriber, async-generator) for this connection.

        Raises ConnectionError if the per-user connection limit is reached.
        """
        with self._lock:
            if self._count_user_connections(user_id) >= MAX_CONNECTIONS_PER_USER:
                raise ConnectionError(
                    f"Too many SSE connections for user {user_id} "
                    f"(max {MAX_CONNECTIONS_PER_USER})"
                )
            sub_id = self._next_id
            self._next_id += 1
            queue: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
            sub = _Subscriber(
                user_id=user_id,
                role=role,
                queue=queue,
            )
            self._subscribers[sub_id] = sub

        return sub, self._drain(sub_id, sub)

    async def _drain(
        self, sub_id: int, sub: _Subscriber
    ) -> AsyncGenerator[Event, None]:
        """Internal async generator that drains a subscriber's queue."""
        is_admin = sub.role in ("admin", "owner")
        try:
            while True:
                event = await sub.queue.get()
                if event is None:
                    break
                sub.last_read_at = time.time()
                if event.require_admin and not is_admin:
                    continue
                yield event
        finally:
            with self._lock:
                self._subscribers.pop(sub_id, None)

    def publish(self, event: Event) -> None:
        """Fan out event to all subscriber queues. Thread-safe."""
        with self._lock:
            dead: list[int] = []
            for sub_id, sub in self._subscribers.items():
                # Skip stale subscribers
                if time.time() - sub.last_read_at > SUBSCRIBER_TTL_SECONDS:
                    dead.append(sub_id)
                    continue
                try:
                    sub.queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Drop oldest event to make room
                    try:
                        sub.queue.get_nowait()
                        sub.queue.put_nowait(event)
                    except (asyncio.QueueEmpty, asyncio.QueueFull):
                        dead.append(sub_id)
            for sub_id in dead:
                self._subscribers.pop(sub_id, None)
                logger.debug("Removed stale/dead subscriber %d", sub_id)

            # Fan out to synchronous listeners
            listeners = list(self._listeners.values())

        for cb in listeners:
            try:
                cb(event)
            except Exception:
                logger.exception("EventBus listener raised — continuing")

    def publish_sync(self, event: Event) -> None:
        """Publish from a synchronous (non-async) thread context."""
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self.publish, event)
        else:
            self.publish(event)

    def next_event_id(self) -> int:
        with self._lock:
            self._event_counter += 1
            return self._event_counter

    def disconnect_user(self, user_id: str) -> None:
        """Close all subscriptions for a user (e.g., on session expiry)."""
        with self._lock:
            for sub in self._subscribers.values():
                if sub.user_id == user_id:
                    try:
                        sub.queue.put_nowait(None)  # sentinel to stop generator
                    except asyncio.QueueFull:
                        pass

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# Module-level singleton — eager init avoids thread-safety issues
_bus = EventBus()


def get_event_bus() -> EventBus:
    return _bus
