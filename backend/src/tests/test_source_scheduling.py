"""Unit tests for per-source schedule resolution and cron validation."""
from __future__ import annotations

import os
from datetime import datetime

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.sources.scheduling import (  # noqa: E402
    PRESET_TO_CRON,
    is_schedule_due,
    is_valid_cron,
    resolve_cron,
)


def test_presets_map_to_cron():
    assert PRESET_TO_CRON["1h"] == "0 * * * *"
    assert PRESET_TO_CRON["6h"] == "0 */6 * * *"
    assert PRESET_TO_CRON["24h"] == "0 0 * * *"


def test_is_valid_cron_accepts_standard_expressions():
    assert is_valid_cron("0 2 * * *")
    assert is_valid_cron("*/15 * * * *")
    assert is_valid_cron("30 9 1-5 * 1-5")
    assert is_valid_cron("0 0,12 * * 0")


def test_is_valid_cron_rejects_malformed():
    assert not is_valid_cron("")
    assert not is_valid_cron("0 2 * *")          # too few fields
    assert not is_valid_cron("0 2 * * * *")       # too many fields
    assert not is_valid_cron("99 2 * * *")        # minute out of range
    assert not is_valid_cron("0 24 * * *")        # hour out of range
    assert not is_valid_cron("0 2 * * abc")       # non-numeric
    assert not is_valid_cron("0 2 * * 7")         # dow out of range (0-6)


def test_resolve_cron_uses_preset_or_custom():
    assert resolve_cron("preset", "6h", None) == "0 */6 * * *"
    assert resolve_cron("cron", "6h", "15 3 * * *") == "15 3 * * *"
    # cron mode with an invalid expression resolves to nothing (won't fire)
    assert resolve_cron("cron", "6h", "nonsense") is None
    # unknown preset resolves to nothing
    assert resolve_cron("preset", "weekly", None) is None


def test_is_schedule_due_matches_resolved_time():
    # 6h preset → "0 */6 * * *" fires at 06:00, not 06:30
    assert is_schedule_due("preset", "6h", None, datetime(2026, 6, 21, 6, 0))
    assert not is_schedule_due("preset", "6h", None, datetime(2026, 6, 21, 6, 30))
    # custom cron at 03:15
    assert is_schedule_due("cron", "6h", "15 3 * * *", datetime(2026, 6, 21, 3, 15))
    assert not is_schedule_due("cron", "6h", "15 3 * * *", datetime(2026, 6, 21, 3, 16))
