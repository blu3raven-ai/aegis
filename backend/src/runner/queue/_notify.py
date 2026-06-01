"""Shared notification hook used by all JobQueue implementations.

Publishes a queued-job notification after `create()` returns. Swallows
errors so queue.create never fails on pub/sub issues (Redis pub/sub is
best-effort; runners fall back to catch-up poll if a message is missed).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def publish_queued(scanner_type: str, job_id: str) -> None:
    try:
        from src.runner.queue.redis_pubsub import JobQueuedPubSub
        JobQueuedPubSub().publish(scanner_type, job_id=job_id)
    except Exception as exc:
        logger.warning("Failed to publish queued notification for %s: %s", job_id, exc)
