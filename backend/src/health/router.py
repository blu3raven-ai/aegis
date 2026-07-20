"""Health endpoint.

`/health` is unauthenticated (monitors and load balancers poll it) and always
returns 200 so they can parse the JSON even when a subsystem is degraded. It
returns only the overall status to an unauthenticated caller; the per-probe
internals (internal service URLs, fleet size, scan volume, raw error strings)
are included only for an operator holding `manage_settings`, so they never leak
to an anonymous request.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request

from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.authz.permissions.service import has_role_permission
from src.health.probes import run_all_probes

router = APIRouter()


def _overall(statuses: list[str]) -> str:
    if all(s in ("ok", "skipped") for s in statuses):
        return "ok"
    if any(s == "fail" for s in statuses):
        return "fail"
    return "degraded"


@router.get("/health")
async def health_check(request: Request) -> dict:
    """Overall status for anyone; full probe detail only for `manage_settings`."""
    results = await run_all_probes()
    body: dict = {"status": _overall([r.status for r in results])}

    role = getattr(request.state, "user_role", None)
    role_id = getattr(request.state, "user_role_id", None)
    if has_role_permission(role, role_id, MANAGE_SETTINGS):
        body["timestamp"] = datetime.now(timezone.utc).isoformat()
        body["probes"] = [
            {
                "name": r.name,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "details": r.details,
                "error": r.error,
            }
            for r in results
        ]
    return body
