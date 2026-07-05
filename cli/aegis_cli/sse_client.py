"""Minimal SSE (Server-Sent Events) parser for the Aegis CLI.

Backends speak the standard SSE wire format:

    id:42
    event:finding.created
    data:{"event_id":"...","payload":{...}}
    \n

This module implements just enough of the spec to stream events from
`/events/api/stream` without pulling in a heavier dependency.  It
keeps the wire-level parsing isolated from the Click command so it
can be unit-tested against synthetic byte streams.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

import httpx


_SSE_ENDPOINT = "/events/api/stream"


@dataclass
class SseMessage:
    """A single fully-assembled SSE event."""

    event_type: str
    data: dict[str, Any]
    event_id: str | None = None


@dataclass
class _PartialMessage:
    event_type: str | None = None
    data_lines: list[str] = field(default_factory=list)
    event_id: str | None = None

    def is_empty(self) -> bool:
        return self.event_type is None and not self.data_lines

    def finalize(self) -> SseMessage | None:
        """Materialize the buffered fields, JSON-decoding data when present.

        Lines starting with ``:`` are comments/heartbeats and never become
        messages.  A block missing both ``event:`` and ``data:`` is dropped
        instead of yielding an empty event.
        """
        if self.event_type is None and not self.data_lines:
            return None
        raw = "\n".join(self.data_lines)
        try:
            decoded: dict[str, Any] = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            decoded = {"_raw": raw}
        if not isinstance(decoded, dict):
            decoded = {"_raw": raw}
        return SseMessage(
            event_type=self.event_type or "message",
            data=decoded,
            event_id=self.event_id,
        )


def parse_sse_lines(lines: Iterable[str]) -> Iterator[SseMessage]:
    """Parse an iterable of SSE-format lines into SseMessage objects.

    A blank line delimits one event.  Lines beginning with ``:`` are
    heartbeats and yield nothing.  Unknown field names are ignored
    per the SSE spec.
    """
    buf = _PartialMessage()
    for line in lines:
        # Strip a single trailing newline if the source kept it.
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]

        if line == "":
            msg = buf.finalize()
            if msg is not None:
                yield msg
            buf = _PartialMessage()
            continue

        if line.startswith(":"):
            # Comment / heartbeat
            continue

        field_name, sep, value = line.partition(":")
        if not sep:
            # Field without a colon — treat whole line as field name with empty value
            field_name, value = line, ""
        # Strip a single leading space from the value per the SSE spec.
        if value.startswith(" "):
            value = value[1:]

        if field_name == "event":
            buf.event_type = value
        elif field_name == "data":
            buf.data_lines.append(value)
        elif field_name == "id":
            buf.event_id = value
        # retry: and other fields are ignored on purpose


def stream_events(
    base_url: str,
    api_token: str,
    *,
    timeout: float = 30.0,
    connect_timeout: float = 10.0,
) -> Iterator[SseMessage]:
    """Connect to the Aegis SSE endpoint and yield parsed messages.

    The HTTP connection stays open for the lifetime of the iterator;
    the caller is responsible for breaking out (KeyboardInterrupt, etc.).
    A non-2xx initial response raises httpx.HTTPStatusError so the CLI
    can surface a clear error.
    """
    url = f"{base_url.rstrip('/')}{_SSE_ENDPOINT}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "text/event-stream",
        "Cache-Control": "no-cache",
    }
    # read=None disables read timeout so an idle stream isn't torn down
    # mid-heartbeat; connect_timeout still guards the initial handshake.
    httpx_timeout = httpx.Timeout(
        timeout, connect=connect_timeout, read=None
    )
    with httpx.Client(timeout=httpx_timeout, headers=headers) as client:
        with client.stream("GET", url) as resp:
            resp.raise_for_status()
            yield from parse_sse_lines(resp.iter_lines())
