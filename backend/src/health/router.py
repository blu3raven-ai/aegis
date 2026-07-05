"""Health check endpoint — runs all subsystem probes concurrently.

Always returns 200 so monitoring systems can parse the JSON even when a
subsystem is degraded.  Callers must inspect the per-probe `status` field
for failures.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from src.health.probes import run_all_probes

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Run all subsystem probes concurrently and return their status."""
    results = await run_all_probes()

    statuses = [r.status for r in results]
    if all(s in ("ok", "skipped") for s in statuses):
        overall = "ok"
    elif any(s == "fail" for s in statuses):
        overall = "fail"
    else:
        overall = "degraded"

    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "probes": [
            {
                "name": r.name,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "details": r.details,
                "error": r.error,
            }
            for r in results
        ],
    }
