"""Event base class shared by every event type on the durable bus."""
from __future__ import annotations

import datetime
import secrets
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Crockford base32 — same alphabet ULID uses, time-sortable when prefixed with
# millisecond timestamp.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """Generate a 26-char ULID (10 timestamp + 16 random)."""
    ts_ms = int(time.time() * 1000)
    ts_part = ""
    for _ in range(10):
        ts_part = _ALPHABET[ts_ms & 0x1F] + ts_part
        ts_ms >>= 5
    rand_part = "".join(_ALPHABET[secrets.randbits(5)] for _ in range(16))
    return ts_part + rand_part


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


class Event(BaseModel):
    """Base for all events on the durable bus.

    Subclasses set a concrete `event_type` literal and a typed `payload`.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=_ulid)
    event_type: str
    timestamp_utc: datetime.datetime = Field(default_factory=_utc_now)
    source_component: str = "unknown"
    # Owning org tag — preserved through the EventBus so downstream listeners
    # can scope their work without re-deriving it from the payload.
    org_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
