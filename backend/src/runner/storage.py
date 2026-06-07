"""PostgreSQL-based storage for runner records, job records, and registration tokens."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Runner, RunnerHeartbeat, RunnerJob, RunnerToken
from src.shared.paths import dt_to_iso as _dt_to_iso, now_iso as _now_iso


def _runner_to_dict(runner: Runner) -> dict[str, Any]:
    return {
        "id": runner.id,
        "name": runner.name or "",
        "status": runner.status or "pending",
        "os": runner.os or "",
        "arch": runner.arch or "",
        "authTokenHash": runner.auth_token_hash or "",
        "approvedAt": _dt_to_iso(runner.approved_at),
        "lastHeartbeatAt": _dt_to_iso(runner.last_heartbeat),
        "registeredAt": _dt_to_iso(runner.created_at) or _now_iso(),
        "maxConcurrent": runner.max_concurrent or 2,
        "cpuPercent": runner.cpu_percent,
        "memoryUsedGb": runner.memory_used_gb,
        "memoryTotalGb": runner.memory_total_gb,
        "diskUsedGb": runner.disk_used_gb,
        "diskTotalGb": runner.disk_total_gb,
        "cores": runner.cores,
        "jobsCompleted": runner.jobs_completed or 0,
    }


def _job_to_dict(job: RunnerJob) -> dict[str, Any]:
    return {
        "id": job.id,
        "runnerId": job.runner_id,
        "jobType": job.job_type or "",
        "org": job.org or "",
        "runId": job.run_id or "",
        "status": job.status or "pending",
        "envVars": job.env_vars or {},
        "createdAt": _dt_to_iso(job.created_at) or _now_iso(),
        "startedAt": _dt_to_iso(job.started_at),
        "completedAt": _dt_to_iso(job.completed_at),
    }


# ---------------------------------------------------------------------------
# Runner records
# ---------------------------------------------------------------------------

def read_runner(runner_id: str) -> dict[str, Any] | None:
    async def _query(session):
        runner = await session.get(Runner, runner_id)
        return _runner_to_dict(runner) if runner else None

    return run_db(_query)


def write_runner(runner: dict[str, Any]) -> None:
    async def _query(session):
        existing = await session.get(Runner, runner["id"])
        if existing:
            existing.name = runner.get("name", existing.name)
            existing.status = runner.get("status", existing.status)
            existing.os = runner.get("os", existing.os)
            existing.arch = runner.get("arch", existing.arch)
            if runner.get("authTokenHash"):
                existing.auth_token_hash = runner["authTokenHash"]
            if "approvedAt" in runner:
                existing.approved_at = datetime.fromisoformat(runner["approvedAt"].replace("Z", "+00:00")) if runner["approvedAt"] else None
            if runner.get("lastHeartbeatAt"):
                existing.last_heartbeat = datetime.fromisoformat(runner["lastHeartbeatAt"].replace("Z", "+00:00"))
            if "jobsCompleted" in runner:
                existing.jobs_completed = runner["jobsCompleted"]
        else:
            now = datetime.now(timezone.utc)
            session.add(Runner(
                id=runner["id"],
                name=runner.get("name", ""),
                status=runner.get("status", "pending"),
                os=runner.get("os", ""),
                arch=runner.get("arch", ""),
                auth_token_hash=runner.get("authTokenHash", ""),
                created_at=now,
                jobs_completed=runner.get("jobsCompleted", 0),
            ))

    run_db(_query)


def delete_runner(runner_id: str) -> None:
    async def _query(session):
        runner = await session.get(Runner, runner_id)
        if runner:
            await session.delete(runner)

    run_db(_query)


def list_runners() -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(select(Runner).order_by(Runner.created_at.desc()))
        return [_runner_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# ---------------------------------------------------------------------------
# Job records
# ---------------------------------------------------------------------------

def read_job(job_id: str) -> dict[str, Any] | None:
    async def _query(session):
        job = await session.get(RunnerJob, job_id)
        return _job_to_dict(job) if job else None

    return run_db(_query)


def write_job(job: dict[str, Any]) -> None:
    async def _query(session):
        existing = await session.get(RunnerJob, job["id"])
        if existing:
            for key, attr in [
                ("runnerId", "runner_id"), ("jobType", "job_type"), ("org", "org"),
                ("runId", "run_id"), ("status", "status"),
                ("envVars", "env_vars"),
            ]:
                if key in job:
                    setattr(existing, attr, job[key])
            if job.get("startedAt"):
                existing.started_at = datetime.fromisoformat(job["startedAt"].replace("Z", "+00:00"))
            if job.get("completedAt"):
                existing.completed_at = datetime.fromisoformat(job["completedAt"].replace("Z", "+00:00"))
        else:
            session.add(RunnerJob(
                id=job["id"],
                runner_id=job.get("runnerId"),
                job_type=job.get("jobType", ""),
                org=job.get("org", ""),
                run_id=job.get("runId", ""),
                status=job.get("status", "pending"),
                env_vars=job.get("envVars", {}),
                created_at=datetime.now(timezone.utc),
            ))

    run_db(_query)


def list_jobs(status: str | None = None) -> list[dict[str, Any]]:
    async def _query(session):
        stmt = select(RunnerJob)
        if status is not None:
            stmt = stmt.where(RunnerJob.status == status)
        stmt = stmt.order_by(RunnerJob.created_at)
        result = await session.execute(stmt)
        return [_job_to_dict(j) for j in result.scalars().all()]

    return run_db(_query)


# ---------------------------------------------------------------------------
# Registration tokens
# ---------------------------------------------------------------------------

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_registration_token() -> tuple[str, dict[str, Any]]:
    """Generate a single-use registration token with 10-minute expiry."""
    raw = f"vrt_{secrets.token_urlsafe(32)}"
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(minutes=10)
    token_hash = hash_token(raw)

    record: dict[str, Any] = {
        "tokenHash": token_hash,
        "createdAt": _now_iso(),
        "expiresAt": expiry.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "used": False,
    }

    async def _query(session):
        session.add(RunnerToken(
            token_hash=token_hash,
            status="pending",
            expires_at=expiry,
            created_at=now,
        ))

    run_db(_query)
    return raw, record


def validate_registration_token(raw_token: str) -> dict[str, Any] | None:
    """Validate and consume a registration token. Returns the record or None."""
    token_hash = hash_token(raw_token)

    async def _query(session):
        token = await session.get(RunnerToken, token_hash)
        if not token:
            return None
        if token.status != "pending":
            return None
        if datetime.now(timezone.utc) > token.expires_at:
            return None
        # Mark as used
        token.status = "used"
        return {
            "tokenHash": token.token_hash,
            "createdAt": _dt_to_iso(token.created_at),
            "expiresAt": _dt_to_iso(token.expires_at),
            "used": True,
        }

    return run_db(_query)


def generate_auth_token() -> tuple[str, str]:
    """Generate a runner auth token. Returns (raw_token, token_hash)."""
    raw = f"vra_{secrets.token_urlsafe(32)}"
    return raw, hash_token(raw)


# ---------------------------------------------------------------------------
# Heartbeat history
# ---------------------------------------------------------------------------

def record_heartbeat(runner_id: str, cpu: float | None, memory: float | None) -> None:
    """Record a heartbeat entry for history."""
    async def _query(session):
        session.add(RunnerHeartbeat(
            id=f"hb-{secrets.token_hex(8)}",
            runner_id=runner_id,
            received_at=datetime.now(timezone.utc),
            cpu_percent=cpu,
            memory_used_gb=memory,
        ))

    run_db(_query)


def list_heartbeats(runner_id: str, since_minutes: int = 120) -> list[dict[str, Any]]:
    """List heartbeat history for a runner within the last N minutes."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)

    async def _query(session):
        stmt = (
            select(RunnerHeartbeat)
            .where(RunnerHeartbeat.runner_id == runner_id)
            .where(RunnerHeartbeat.received_at >= cutoff)
            .order_by(RunnerHeartbeat.received_at.desc())
        )
        result = await session.execute(stmt)
        return [
            {
                "receivedAt": _dt_to_iso(hb.received_at),
                "cpuPercent": hb.cpu_percent,
                "memoryUsedGb": hb.memory_used_gb,
            }
            for hb in result.scalars().all()
        ]

    return run_db(_query)


def count_heartbeats(runner_id: str, window_minutes: int = 60) -> int:
    """Count heartbeats received in the last N minutes."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    async def _query(session):
        from sqlalchemy import func
        stmt = (
            select(func.count())
            .select_from(RunnerHeartbeat)
            .where(RunnerHeartbeat.runner_id == runner_id)
            .where(RunnerHeartbeat.received_at >= cutoff)
        )
        result = await session.execute(stmt)
        return result.scalar() or 0

    return run_db(_query)


def prune_old_heartbeats(keep_minutes: int = 120) -> int:
    """Delete heartbeat records older than keep_minutes. Returns count deleted."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=keep_minutes)

    async def _query(session):
        from sqlalchemy import delete
        stmt = delete(RunnerHeartbeat).where(RunnerHeartbeat.received_at < cutoff)
        result = await session.execute(stmt)
        return result.rowcount

    return run_db(_query)


# ---------------------------------------------------------------------------
# Runner metrics & settings
# ---------------------------------------------------------------------------

def update_runner_metrics(runner_id: str, metrics: dict[str, Any]) -> None:
    """Update runner's live metric columns."""
    async def _query(session):
        runner = await session.get(Runner, runner_id)
        if not runner:
            return
        if metrics.get("cpuPercent") is not None:
            runner.cpu_percent = metrics["cpuPercent"]
        if metrics.get("memoryUsedGb") is not None:
            runner.memory_used_gb = metrics["memoryUsedGb"]
        if metrics.get("memoryTotalGb") is not None:
            runner.memory_total_gb = metrics["memoryTotalGb"]
        if metrics.get("diskUsedGb") is not None:
            runner.disk_used_gb = metrics["diskUsedGb"]
        if metrics.get("diskTotalGb") is not None:
            runner.disk_total_gb = metrics["diskTotalGb"]
        if metrics.get("cores") is not None:
            runner.cores = metrics["cores"]
        if metrics.get("os") and not runner.os:
            runner.os = metrics["os"]
        if metrics.get("arch") and not runner.arch:
            runner.arch = metrics["arch"]

    run_db(_query)


def update_runner_settings(runner_id: str, settings: dict[str, Any]) -> dict[str, Any] | None:
    """Update runner settings (maxConcurrent, name). Returns updated runner dict."""
    async def _query(session):
        runner = await session.get(Runner, runner_id)
        if not runner:
            return None
        if "maxConcurrent" in settings:
            val = int(settings["maxConcurrent"])
            runner.max_concurrent = max(1, min(16, val))
        if "name" in settings:
            runner.name = settings["name"]
        return _runner_to_dict(runner)

    return run_db(_query)


def list_jobs_for_runner(runner_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """List recent jobs assigned to a specific runner."""
    async def _query(session):
        stmt = (
            select(RunnerJob)
            .where(RunnerJob.runner_id == runner_id)
            .order_by(RunnerJob.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return [_job_to_dict(j) for j in result.scalars().all()]

    return run_db(_query)
