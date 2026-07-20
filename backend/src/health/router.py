"""Health endpoints.

Two surfaces: an unauthenticated liveness probe (`/healthz`) that returns only
the overall status, and an authenticated detail endpoint (`/health`) that
returns per-probe internals. Splitting them keeps operational internals
(internal service URLs, fleet size, scan volume, raw error strings) out of an
unauthenticated response. Both return 200 so monitors parse the JSON even when
a subsystem is degraded.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.health.probes import run_all_probes

router = APIRouter()


def _overall(statuses: list[str]) -> str:
    if all(s in ("ok", "skipped") for s in statuses):
        return "ok"
    if any(s == "fail" for s in statuses):
        return "fail"
    return "degraded"


@router.get("/healthz")
async def liveness() -> dict:
    """Unauthenticated liveness probe — overall status only, no internals."""
    results = await run_all_probes()
    return {"status": _overall([r.status for r in results])}


@router.get("/health")
async def health_check(_: None = Depends(Permission(MANAGE_SETTINGS))) -> dict:
    """Full per-probe detail — authenticated (MANAGE_SETTINGS) only."""
    results = await run_all_probes()

    overall = _overall([r.status for r in results])

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
