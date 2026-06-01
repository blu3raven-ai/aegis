"""PostgreSQL-backed JobQueue.

Wraps the production jobs.py + storage.py logic (which is already
production-tested for encryption, status transitions, runner-id persistence,
stale-job recovery). PostgresBackedQueue is the Protocol-conformant face;
the existing module-level API in jobs.py routes through the same _inner
helpers, so both interfaces share one set of underlying logic.
"""
from __future__ import annotations

from typing import Any

from src.runner.queue._notify import publish_queued


class PostgresBackedQueue:
    def create(
        self,
        *,
        job_type: str,
        org: str,
        run_id: str,
        docker_image: str,
        env_vars: dict[str, str],
    ) -> str:
        from src.runner.jobs import _create_job_inner
        job_id = _create_job_inner(
            job_type=job_type, org=org, run_id=run_id,
            docker_image=docker_image, env_vars=env_vars,
        )
        publish_queued(job_type, job_id)
        return job_id

    def assign_next(self, runner_id: str) -> dict[str, Any] | None:
        from src.runner.jobs import _assign_next_job_inner
        return _assign_next_job_inner(runner_id=runner_id)

    def mark_started(self, job_id: str) -> None:
        from src.runner.jobs import _update_job_status_inner
        _update_job_status_inner(job_id, "running")

    def mark_completed(self, job_id: str, result: dict[str, Any] | None = None) -> None:
        from src.runner.jobs import _complete_job_inner
        _complete_job_inner(job_id, result=result)

    def mark_failed(self, job_id: str, error: str, *, retryable: bool = False) -> None:
        from src.runner.jobs import _fail_job_inner
        _fail_job_inner(job_id, error=error, retryable=retryable)

    def get(self, job_id: str) -> dict[str, Any] | None:
        from src.runner.jobs import _read_job_inner
        return _read_job_inner(job_id)
