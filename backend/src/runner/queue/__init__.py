"""Job queue abstraction.

Phase 0 wraps the existing file-based queue (jobs.py) behind this Protocol
so Phase 1 can swap in a Redis-backed implementation without touching
call sites.
"""
from __future__ import annotations

from typing import Any, Protocol


class JobQueue(Protocol):
    def create(
        self,
        *,
        job_type: str,
        org: str,
        run_id: str,
        env_vars: dict[str, str],
    ) -> str:
        """Enqueue a new job; returns its job_id."""
        ...

    def assign_next(self, runner_id: str) -> dict[str, Any] | None:
        """Atomically pull the next queued job and mark it 'assigned' to runner_id.

        runner_id is persisted on the job record (as `runnerId`) for stale-job
        recovery and runner stats downstream.
        """
        ...

    def mark_started(self, job_id: str) -> None: ...

    def mark_completed(self, job_id: str, result: dict[str, Any] | None = None) -> None: ...

    def mark_failed(self, job_id: str, error: str, *, retryable: bool = False) -> None: ...

    def get(self, job_id: str) -> dict[str, Any] | None: ...
