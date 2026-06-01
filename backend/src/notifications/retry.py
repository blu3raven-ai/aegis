"""Exponential back-off retry logic for failed notification deliveries.

The router marks deliveries as 'retry' after a transient failure. A separate
background task (or the router's own loop) calls attempt_retries() to pick up
those rows and re-dispatch using the same sender/formatter path.

Max attempts is configurable; once exhausted the delivery is marked 'failed'
permanently and a warning is logged.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Backoff schedule (seconds between attempts): 5s, 30s, 5m, 30m
_BACKOFF_SECONDS = [5, 30, 300, 1800]
MAX_ATTEMPTS = len(_BACKOFF_SECONDS) + 1  # initial attempt + retries


def _attempt_count_from_delivery(delivery: dict[str, Any]) -> int:
    """Parse attempt count from error field convention: 'attempt N: ...'"""
    error = delivery.get("error") or ""
    if error.startswith("attempt "):
        try:
            return int(error.split(":")[0].split(" ")[1])
        except (ValueError, IndexError):
            pass
    return 1


def with_retry(
    send_fn: Callable[[], tuple[bool, int | None, str | None]],
    *,
    max_attempts: int = MAX_ATTEMPTS,
    backoff: list[int] | None = None,
) -> tuple[bool, int | None, str | None]:
    """Run send_fn up to max_attempts times with exponential back-off.

    send_fn must return (success, response_code, error).
    Returns the final (success, response_code, error) after all attempts.

    Only used for inline synchronous retries; the router's async path uses
    the DB-backed 'retry' status for cross-restart durability.
    """
    schedule = backoff if backoff is not None else _BACKOFF_SECONDS
    last_success, last_code, last_err = False, None, None

    for attempt in range(1, max_attempts + 1):
        success, code, err = send_fn()
        last_success, last_code, last_err = success, code, err

        if success:
            return success, code, err

        if attempt < max_attempts:
            wait = schedule[min(attempt - 1, len(schedule) - 1)]
            logger.debug("delivery attempt %d failed (%s); retrying in %ds", attempt, err, wait)
            time.sleep(wait)

    return last_success, last_code, last_err
