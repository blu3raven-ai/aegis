"""New source connections default to an hourly sync + 6h auto-scan cadence."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.sources import store as sources_store  # noqa: E402


def test_new_connection_defaults_to_hourly_sync_and_auto_scan():
    conn = sources_store.create_connection(
        {
            "category": "code-repositories",
            "sourceType": "github",
            "name": "default-schedule-test",
            "auth": {"orgOrOwner": "acme-default-schedule-org", "token": "t"},
        }
    )
    assert conn["syncSchedule"] == "1h"
    assert conn["scanAutoEnabled"] is True
    assert conn["scanScheduleMode"] == "preset"
    assert conn["scanSchedulePreset"] == "6h"


def test_explicit_schedule_overrides_defaults():
    conn = sources_store.create_connection(
        {
            "category": "code-repositories",
            "sourceType": "github",
            "name": "override-schedule-test",
            "auth": {"orgOrOwner": "acme-override-schedule-org", "token": "t"},
            "syncSchedule": "12h",
            "scanAutoEnabled": False,
            "scanSchedulePreset": "24h",
        }
    )
    assert conn["syncSchedule"] == "12h"
    assert conn["scanAutoEnabled"] is False
    assert conn["scanSchedulePreset"] == "24h"
