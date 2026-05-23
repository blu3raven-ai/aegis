"""Daily cleanup job for expired scan objects in MinIO."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from src.shared.object_store import list_objects, get_object_tags, get_s3_client, _S3_BUCKET
from src.shared.config import read_app_config

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 7
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 90
UNTAGGED_SAFETY_NET_DAYS = 3
TOOLS = {
    "dependencies":       "dependencies",
    "secrets":            "secrets",
    "code_scanning":      "codeScanning",
    "container_scanning": "containerScanning",
}
CLEANUP_INTERVAL_SECONDS = 86400  # 24 hours


def build_retention_config(app_config: dict[str, Any]) -> dict[str, int]:
    """Build per-tool retention days from app config."""
    tools_config = app_config.get("tools") or {}
    result: dict[str, int] = {}
    for tool, config_key in TOOLS.items():
        tool_config = tools_config.get(config_key) or {}
        days = tool_config.get("retentionDays", DEFAULT_RETENTION_DAYS)
        if not isinstance(days, int) or (days != 0 and days < MIN_RETENTION_DAYS):
            days = MIN_RETENTION_DAYS
        if days > MAX_RETENTION_DAYS:
            days = MAX_RETENTION_DAYS
        result[tool] = days
    return result


def should_delete_object(
    tags: dict[str, str],
    retention_days: int,
    now: datetime | None = None,
    object_last_modified: datetime | None = None,
) -> bool:
    """Determine whether an object should be deleted based on tags and retention policy."""
    now = now or datetime.now(timezone.utc)
    ingested_at = tags.get("ingested_at")

    if ingested_at:
        try:
            ingested_dt = datetime.fromisoformat(ingested_at.replace("Z", "+00:00"))
            return (now - ingested_dt) > timedelta(days=retention_days)
        except (ValueError, TypeError):
            logger.warning("Invalid ingested_at tag value: %s", ingested_at)
            # Treat invalid tags as untagged — fall through to safety net

    # Untagged or invalid-tagged objects: delete after safety net period
    if object_last_modified:
        return (now - object_last_modified) > timedelta(days=UNTAGGED_SAFETY_NET_DAYS)

    return True  # No tag and no modified date — safe to delete


def run_cleanup_once() -> dict[str, int]:
    """Run one cleanup cycle. Returns {tool: deleted_count}."""
    app_config = read_app_config()
    retention = build_retention_config(app_config)
    now = datetime.now(timezone.utc)
    results: dict[str, int] = {}

    for tool in TOOLS:
        if retention[tool] == 0:
            results[tool] = 0
            continue
        prefix = f"{tool}/"
        deleted = 0
        try:
            keys = list_objects(prefix)
            for key in keys:
                tags = get_object_tags(key)
                if should_delete_object(tags, retention[tool], now=now):
                    try:
                        get_s3_client().delete_object(
                            Bucket=_S3_BUCKET,
                            Key=key,
                        )
                        deleted += 1
                    except Exception:
                        logger.warning("Failed to delete object: %s", key)
        except Exception:
            logger.exception("Retention cleanup failed for tool: %s", tool)
        results[tool] = deleted

    logger.info("Retention cleanup complete: %s", results)
    return results


def start_retention_background_loop() -> threading.Thread:
    """Start a daemon thread that runs cleanup every 24 hours."""
    def _loop():
        while True:
            try:
                run_cleanup_once()
            except Exception:
                logger.exception("Retention cleanup loop error")
            time.sleep(CLEANUP_INTERVAL_SECONDS)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    logger.info("Retention cleanup background loop started (interval: %ds)", CLEANUP_INTERVAL_SECONDS)
    return thread
