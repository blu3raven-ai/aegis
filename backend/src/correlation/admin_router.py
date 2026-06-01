"""Admin endpoints for the correlation engine.

These endpoints are gated by the manage_settings permission (same RBAC gate
used by runner admin and settings management). They are only meaningful when
the correlation engine is running (AEGIS_CORRELATION_ENABLED=true); calling
them when dormant returns a 503.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.audit_log.decorators import audited
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/admin", tags=["correlation-admin"])


def _get_engine(request: Request):
    """Return the running CorrelationEngine from app.state, or raise 503."""
    engine = getattr(request.app.state, "correlation_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="correlation engine is not running (set AEGIS_CORRELATION_ENABLED=true)",
        )
    return engine


@audited(action="correlation.rules.reloaded", resource_type="correlation_rules")
@router.post("/correlation/reload-rules")
def reload_rules(request: Request) -> dict:
    """Reload all correlation rule packs without restarting the engine.

    Pulls fresh builtin rules and any packs available from the Argus connector,
    then atomically swaps the engine's trigger index. Safe to call while the
    engine is processing events.

    Requires manage_settings permission.
    """
    require_permission(request, "manage_settings")
    engine = _get_engine(request)
    pack_count = engine.reload_rules()
    rule_count = len(engine._rules)
    return {"reloaded_packs": pack_count, "active_rules": rule_count}
