"""Health check endpoints — component status, readiness, liveness, and deep probes.

Intentionally thin for the shallow checks: reads env vars and app.state to
reflect configuration. No DB calls, no I/O — must return quickly even when
dependencies are degraded.

The /deep endpoint runs all subsystem probes concurrently and always returns
200 so that monitoring systems can parse the JSON even when a subsystem fails.
Use /ready and /live for binary K8s-style probes.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter

from src.health.probes import run_all_probes

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check() -> dict:
    """Full component status: Argus, queue backend, runner."""
    argus_endpoint = os.getenv("ARGUS_ENDPOINT", "")
    queue_backend = os.getenv("JOB_QUEUE_BACKEND", "file")
    runner_dispatch = os.getenv("RUNNER_DISPATCH_MODE", "poll")

    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "argus": {
                "status": "connected" if argus_endpoint else "disabled-fallback-heuristics",
                "endpoint_configured": bool(argus_endpoint),
            },
            "queue_backend": {
                "backend": queue_backend,
            },
            "runner": {
                "dispatch_mode": runner_dispatch,
            },
        },
    }


@router.get("/deep")
async def deep_health_check() -> dict:
    """Run all subsystem probes concurrently.

    Always returns 200 — callers must inspect per-probe status for failures.
    Binary up/down signalling is handled by /ready and /live (unchanged).
    """
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


@router.get("/ready")
async def readiness_check() -> dict:
    """K8s-style readiness probe: returns 200 when the app is ready to serve traffic."""
    return {"ready": True}


@router.get("/live")
async def liveness_check() -> dict:
    """K8s-style liveness probe: returns 200 when the process is alive."""
    return {"alive": True}
