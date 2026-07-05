"""Event-driven refresher for home dashboard materialised views.

Findings change in two paths: scan completion (apply_lifecycle) and
user actions (dismiss_finding, reopen_finding, bulk_dismiss). Each
path calls request_home_views_refresh(). A single asyncio worker
drains the request event with a 5s debounce window so bursts of
concurrent scan completions coalesce into one refresh. No polling.
"""
from __future__ import annotations

import asyncio
import logging

from src.shared.home_views import refresh_all_home_views

logger = logging.getLogger(__name__)
DEBOUNCE_SECONDS = 5

_refresh_event: asyncio.Event | None = None


def _get_event() -> asyncio.Event:
    """Lazy-create the event because asyncio.Event needs a running loop."""
    global _refresh_event
    if _refresh_event is None:
        _refresh_event = asyncio.Event()
    return _refresh_event


def request_home_views_refresh() -> None:
    """Signal that home dashboard views need a refresh.

    Safe to call from sync code. Idempotent (multiple rapid calls
    coalesce into one debounced refresh).
    """
    # If called before the loop is running, just no-op; the startup warm-up
    # in lifespan will pick up the state.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    event = _get_event()
    loop.call_soon_threadsafe(event.set)


async def home_views_refresh_worker(*, debounce: int = DEBOUNCE_SECONDS) -> None:
    """Drain refresh requests with debounce. Run forever.

    On each wake: sleep `debounce` seconds to collect more requests,
    then refresh. Per-iteration failures are logged and retried on
    the next trigger. Never crashes the task.
    """
    event = _get_event()
    while True:
        await event.wait()
        await asyncio.sleep(debounce)
        event.clear()
        try:
            await asyncio.to_thread(refresh_all_home_views)
        except Exception:
            logger.exception("[!] home_views refresh iteration failed")
