"""Audit-stream admin endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import AuditStreamConfig
from src.security.crypto import encrypt
from src.settings.router import require_permission
from src.settings.schemas import AuditStreamConfigRequest

audit_stream_router = APIRouter(prefix="/api/v1/settings/audit-stream", tags=["audit-stream"])


def _serialize(row: AuditStreamConfig) -> dict:
    return {
        "enabled": row.enabled,
        "targetType": row.target_type,
        "endpointUrl": row.endpoint_url,
        "authTokenSet": row.auth_token_enc is not None,
        "lastEventId": row.last_event_id,
        "lastSuccessAt": row.last_success_at.isoformat() if row.last_success_at else None,
        "lastError": row.last_error,
        "updatedAt": row.updated_at.isoformat() if row.updated_at else None,
    }


async def _get_singleton(session) -> AuditStreamConfig:
    row = (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one_or_none()
    if row is None:
        row = AuditStreamConfig(id=1)
        session.add(row)
        await session.flush()
    return row


@audit_stream_router.get("")
def get_audit_stream(request: Request) -> JSONResponse:
    async def _q(session):
        return _serialize(await _get_singleton(session))
    return JSONResponse(run_db(_q), status_code=200)


@audit_stream_router.patch("")
def patch_audit_stream(request: Request, body: AuditStreamConfigRequest) -> JSONResponse:
    require_permission(request, "manage_settings")

    async def _q(session):
        row = await _get_singleton(session)
        if body.enabled is not None:
            row.enabled = body.enabled
        if body.targetType is not None:
            row.target_type = body.targetType
        if body.endpointUrl is not None:
            row.endpoint_url = body.endpointUrl or None
        if body.authToken:
            row.auth_token_enc = encrypt(body.authToken)
        return _serialize(row)

    return JSONResponse(run_db(_q), status_code=200)


@audit_stream_router.post("/test")
def test_audit_stream(request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")

    from src.audit_stream.adapters import deliver_test_event

    async def _q(session):
        cfg = await _get_singleton(session)
        if cfg.target_type is None or cfg.endpoint_url is None:
            return {"ok": False, "error": "Target type and endpoint URL are required."}
        return await deliver_test_event(cfg)

    return JSONResponse(run_db(_q), status_code=200)
