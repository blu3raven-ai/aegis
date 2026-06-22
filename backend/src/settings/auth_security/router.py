"""Auth-security policy endpoints.

GET moved to GraphQL (Query.authSecuritySettings); PATCH stays on REST.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from src.audit_log.decorators import audited
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.settings.general.schemas import AuthSecuritySettingsRequest
from src.shared.config import (
    read_app_config,
    sync_runtime_env_from_config,
    write_app_config,
)

auth_security_router = APIRouter(prefix="/api/v1/settings/auth-security", tags=["settings"])


@auth_security_router.patch("")
@audited(action="auth_security.config_updated", resource_type="auth_security_config")
def save_auth_security_settings(
    request: Request,
    body: AuthSecuritySettingsRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> JSONResponse:
    config = read_app_config()
    config["authSecurity"] = body.model_dump()
    write_app_config(config, "settings.auth_security.updated")
    sync_runtime_env_from_config(config)
    return JSONResponse({"ok": True}, status_code=200)
