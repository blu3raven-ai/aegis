"""Shared sync HTTP client config — uniform timeout policy across connectors.

Sync because the existing notification senders are sync. A future async
migration can add a parallel `default_async_client` without touching this.
"""
from __future__ import annotations

import contextlib
import time
from typing import Callable, Iterator

import httpx

DEFAULT_TIMEOUT_S = 10.0
"""Default request timeout in seconds for any connector-initiated HTTP call.

Outbound notification senders previously used a mix of 10s and 15s.
Centralising here lets a single SLA change land in one place."""


@contextlib.contextmanager
def default_client(timeout_s: float = DEFAULT_TIMEOUT_S) -> Iterator[httpx.Client]:
    """Yield an httpx.Client with the kernel's default timeout.

    Used as `with default_client() as client: client.post(...)`. Context
    manager so the client gets closed even on exception.
    """
    with httpx.Client(timeout=timeout_s) as client:
        yield client


DEFAULT_BACKOFF_S: list[int] = [5, 30, 300, 1800]
"""Default back-off schedule between retry attempts (seconds).

5s, 30s, 5m, 30m — matches the existing notifications/retry.py schedule
so behaviour is preserved when senders migrate to this kernel."""


def with_retry(
    send_fn: Callable[[], tuple[bool, int | None, str | None]],
    *,
    backoff_s: list[int] | None = None,
) -> tuple[bool, int | None, str | None]:
    """Run `send_fn` with exponential back-off until success or exhaustion.

    Total attempts = 1 + len(backoff_s). The wait after attempt N is
    `backoff_s[N-1]`. `send_fn` must return `(success, response_code, error)`.
    Returns the result of the final attempt.
    """
    schedule = backoff_s if backoff_s is not None else DEFAULT_BACKOFF_S
    last: tuple[bool, int | None, str | None] = (False, None, None)

    for attempt in range(1, len(schedule) + 2):
        last = send_fn()
        if last[0]:
            return last
        if attempt <= len(schedule):
            time.sleep(schedule[attempt - 1])

    return last
