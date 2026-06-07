"""Deep health probes — per-subsystem connectivity and sanity checks.

Each probe is independent, idempotent, and safe to call from any context.
Probes return a ProbeResult rather than raising so that a single subsystem
failure cannot prevent the rest from running.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass
class ProbeResult:
    name: str
    status: str  # 'ok' | 'degraded' | 'fail' | 'skipped'
    duration_ms: int
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


async def probe_postgres() -> ProbeResult:
    """Check connectivity by running SELECT 1."""
    import sqlalchemy as sa
    from src.db.engine import async_session_factory

    t0 = time.monotonic()
    try:
        async with async_session_factory() as session:
            await session.execute(sa.text("SELECT 1"))
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(name="postgres", status="ok", duration_ms=elapsed, details={})
    except Exception as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="postgres", status="fail", duration_ms=elapsed, details={}, error=str(exc)
        )


async def probe_minio() -> ProbeResult:
    """Check connectivity by listing buckets using the project object-store client."""
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    endpoint = os.getenv("S3_ENDPOINT", "http://localhost:9000")
    access_key = os.getenv("S3_ACCESS_KEY", "")
    secret_key = os.getenv("S3_SECRET_KEY", "")
    region = os.getenv("S3_REGION", "us-east-1")

    t0 = time.monotonic()
    try:
        def _list():
            client = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
                config=Config(signature_version="s3v4", connect_timeout=2, read_timeout=3),
            )
            return client.list_buckets()

        resp = await asyncio.get_event_loop().run_in_executor(None, _list)
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="minio",
            status="ok",
            duration_ms=elapsed,
            details={"bucket_count": len(buckets)},
        )
    except (BotoCoreError, ClientError, Exception) as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="minio", status="fail", duration_ms=elapsed, details={}, error=str(exc)
        )


async def probe_connected_runners() -> ProbeResult:
    """Check if at least one runner has heartbeated within the last 60 seconds."""
    import sqlalchemy as sa
    from datetime import datetime, timedelta, timezone

    from src.db.engine import async_session_factory
    from src.db.models import Runner

    t0 = time.monotonic()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        async with async_session_factory() as session:
            connected = (
                await session.execute(
                    sa.select(sa.func.count())
                    .select_from(Runner)
                    .where(Runner.last_heartbeat >= cutoff)
                )
            ).scalar_one()
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="connected_runners",
            status="ok" if connected > 0 else "degraded",
            duration_ms=elapsed,
            details={"connected_count": connected},
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="connected_runners", status="fail", duration_ms=elapsed, details={}, error=str(exc)
        )


async def probe_recent_scans() -> ProbeResult:
    """Query scan_runs: success rate over the last 24 h. Degraded if <80%."""
    import sqlalchemy as sa
    from src.db.engine import async_session_factory
    from src.db.models import ScanRun

    t0 = time.monotonic()
    try:
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        async with async_session_factory() as session:
            result = await session.execute(
                sa.select(
                    sa.func.count().label("total"),
                    sa.func.sum(
                        sa.case((ScanRun.status == "completed", 1), else_=0)
                    ).label("succeeded"),
                ).where(ScanRun.started_at >= cutoff)
            )
            row = result.one()

        total = row.total or 0
        succeeded = int(row.succeeded or 0)
        elapsed = int((time.monotonic() - t0) * 1000)

        if total == 0:
            return ProbeResult(
                name="recent_scans",
                status="ok",
                duration_ms=elapsed,
                details={"total_24h": 0, "succeeded_24h": 0, "success_rate": None},
            )

        rate = succeeded / total
        status = "ok" if rate >= 0.80 else "degraded"
        return ProbeResult(
            name="recent_scans",
            status=status,
            duration_ms=elapsed,
            details={
                "total_24h": total,
                "succeeded_24h": succeeded,
                "success_rate": round(rate, 4),
            },
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="recent_scans", status="fail", duration_ms=elapsed, details={}, error=str(exc)
        )


async def probe_argus() -> ProbeResult:
    """If ARGUS_ENDPOINT is configured, issue a lightweight GET to confirm reachability.

    Uses httpx with a short timeout so a slow Argus instance shows up as
    degraded rather than blocking the entire health response.
    """
    endpoint = os.getenv("ARGUS_ENDPOINT", "")
    if not endpoint:
        return ProbeResult(
            name="argus",
            status="skipped",
            duration_ms=0,
            details={"reason": "ARGUS_ENDPOINT not configured"},
        )

    import httpx

    api_key = os.getenv("ARGUS_API_KEY", "")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    url = f"{endpoint.rstrip('/')}/v1/ping"

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url, headers=headers)
        elapsed = int((time.monotonic() - t0) * 1000)
        if resp.status_code < 500:
            return ProbeResult(
                name="argus",
                status="ok",
                duration_ms=elapsed,
                details={"status_code": resp.status_code, "endpoint": endpoint},
            )
        return ProbeResult(
            name="argus",
            status="degraded",
            duration_ms=elapsed,
            details={"status_code": resp.status_code, "endpoint": endpoint},
            error=f"HTTP {resp.status_code}",
        )
    except httpx.TimeoutException:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="argus",
            status="degraded",
            duration_ms=elapsed,
            details={"endpoint": endpoint},
            error="request timeout",
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(
            name="argus",
            status="fail",
            duration_ms=elapsed,
            details={"endpoint": endpoint},
            error=str(exc),
        )


async def run_all_probes() -> list[ProbeResult]:
    """Run all probes concurrently with a per-probe 5-second timeout."""
    probes: list[tuple[str, Callable[[], Awaitable[ProbeResult]]]] = [
        ("postgres", probe_postgres),
        ("minio", probe_minio),
        ("connected_runners", probe_connected_runners),
        ("recent_scans", probe_recent_scans),
        ("argus", probe_argus),
    ]

    async def _run_one(name: str, fn: Callable[[], Awaitable[ProbeResult]]) -> ProbeResult:
        try:
            return await asyncio.wait_for(fn(), timeout=5.0)
        except asyncio.TimeoutError:
            return ProbeResult(name=name, status="fail", duration_ms=5000, details={}, error="probe timeout")
        except Exception as exc:
            return ProbeResult(name=name, status="fail", duration_ms=0, details={}, error=str(exc))

    return list(await asyncio.gather(*[_run_one(name, fn) for name, fn in probes]))
