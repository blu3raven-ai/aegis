"""GraphQL resolver for the auth-security settings surface."""
from __future__ import annotations

import strawberry

from src.authz.enforcement import has_permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.graphql.resolver_utils import raise_permission_denied, raise_unauthenticated
from src.settings.general.schemas import AuthSecuritySettingsRequest
from src.shared.config import read_app_config


@strawberry.type
class AuthSecuritySettings:
    require_mfa_manual_users: bool
    require_mfa_admins: bool
    trusted_session_duration_days: int
    recovery_code_policy: str


def _gate(info_context: dict):
    request = info_context.get("request") if info_context else None
    if request is None:
        raise_unauthenticated()
    if not has_permission(request, MANAGE_SETTINGS):
        raise_permission_denied("Permission denied: manage_settings")
    return request


def auth_security_settings(*, info_context: dict) -> AuthSecuritySettings:
    _gate(info_context)
    config = read_app_config()
    raw = config.get("authSecurity") or {}
    parsed = AuthSecuritySettingsRequest(**raw).model_dump()
    return AuthSecuritySettings(
        require_mfa_manual_users=parsed["requireMfaManualUsers"],
        require_mfa_admins=parsed["requireMfaAdmins"],
        trusted_session_duration_days=parsed["trustedSessionDurationDays"],
        recovery_code_policy=parsed["recoveryCodePolicy"],
    )
