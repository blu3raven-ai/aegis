from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from src.shared.retention import (
    build_retention_config,
    should_delete_object,
    DEFAULT_RETENTION_DAYS,
)


def test_build_retention_config_defaults():
    config = build_retention_config({})
    assert config["dependencies"] == DEFAULT_RETENTION_DAYS
    assert config["secrets"] == DEFAULT_RETENTION_DAYS
    assert config["code_scanning"] == DEFAULT_RETENTION_DAYS
    assert config["container_scanning"] == DEFAULT_RETENTION_DAYS


def test_build_retention_config_custom():
    app_config = {
        "tools": {
            "dependencies": {"retentionDays": 30},
            "secrets": {"retentionDays": 14},
        }
    }
    config = build_retention_config(app_config)
    assert config["dependencies"] == 30
    assert config["secrets"] == 14
    assert config["code_scanning"] == DEFAULT_RETENTION_DAYS


def test_build_retention_config_clamps_values():
    app_config = {
        "tools": {
            "dependencies": {"retentionDays": 0},
            "secrets": {"retentionDays": 999},
        }
    }
    config = build_retention_config(app_config)
    assert config["dependencies"] == 1
    assert config["secrets"] == 90


def test_should_delete_ingested_object_past_retention():
    tags = {"ingested_at": "2026-05-01T00:00:00Z"}
    now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    assert should_delete_object(tags, retention_days=7, now=now) is True


def test_should_not_delete_ingested_object_within_retention():
    tags = {"ingested_at": "2026-05-08T00:00:00Z"}
    now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    assert should_delete_object(tags, retention_days=7, now=now) is False


def test_should_delete_untagged_object_after_3_days():
    tags = {}
    now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    assert should_delete_object(tags, retention_days=7, now=now, object_last_modified=datetime(2026, 5, 6, tzinfo=timezone.utc)) is True


def test_should_not_delete_untagged_recent_object():
    tags = {}
    now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    assert should_delete_object(tags, retention_days=7, now=now, object_last_modified=datetime(2026, 5, 9, tzinfo=timezone.utc)) is False
