"""Job queue factory — selects backend by env var.

Phase 1 now includes PostgresBackedQueue, which wraps the production
jobs.py logic (encryption, status transitions, runner-id persistence,
stale-job recovery). Recommended backends:
  - JOB_QUEUE_BACKEND=postgres — PostgresBackedQueue (production, recommended)
  - JOB_QUEUE_BACKEND=file (default) — FileBackedQueue (dev/test/local,
    JSON on disk, NOT the production storage backend)
  - JOB_QUEUE_BACKEND=redis — RedisBackedQueue (Redis Streams, requires REDIS_URL)
"""
from __future__ import annotations

import os

from src.runner.queue import JobQueue

_cached: JobQueue | None = None


def get_queue() -> JobQueue:
    global _cached
    if _cached is not None:
        return _cached
    backend = os.getenv("JOB_QUEUE_BACKEND", "file").lower()
    if backend == "redis":
        from src.runner.queue.redis_backed import RedisBackedQueue
        _cached = RedisBackedQueue()
    elif backend == "postgres":
        from src.runner.queue.postgres_backed import PostgresBackedQueue
        _cached = PostgresBackedQueue()
    elif backend == "file":
        from pathlib import Path
        from src.runner.queue.file_backed import FileBackedQueue
        storage_dir = None
        if "DATA_DIR" in os.environ:
            storage_dir = Path(os.environ["DATA_DIR"]) / "jobs"
        _cached = FileBackedQueue(storage_dir=storage_dir)
    else:
        raise ValueError(f"Unknown JOB_QUEUE_BACKEND: {backend!r}")
    return _cached


def reset_cache() -> None:
    """For testing only — force re-selection on next get_queue() call."""
    global _cached
    _cached = None
