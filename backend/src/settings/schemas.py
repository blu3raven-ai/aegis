from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, EmailStr


class OrgCredential(BaseModel):
    name: str
    token: str


class GeneralSettingsRequest(BaseModel):
    orgs: list[OrgCredential]
    username: str


class AccountSettingsRequest(BaseModel):
    username: str
    current_password: str | None = None
    new_password: str | None = None
    confirm_new_password: str | None = None


class ToolSettingsRequest(BaseModel):
    enabled: bool
    settings: dict[str, str]


class RateLimitResponse(BaseModel):
    remaining: int
    limit: int
    reset_at: str
    used: int


class ScannerPrerequisitesResponse(BaseModel):
    runner_connected: bool = False
    error: str | None = None
    scanner_status: str | None = None  # ready | no_runner
    runner_name: str | None = None
    runner_platform: str | None = None


class DirectGrantRequest(BaseModel):
    userId: str
    assetId: str


class RoleRequest(BaseModel):
    id: str | None = None
    name: str
    description: str
    permissions: list[str]


class DeleteRoleRequest(BaseModel):
    replacementRoleId: str | None = None




class AuthSecuritySettingsRequest(BaseModel):
    requireMfaManualUsers: bool
    requireMfaAdmins: bool
    trustedSessionDurationDays: int
    recoveryCodePolicy: Literal["mandatory", "optional", "disabled"]


class EmailChangeRequest(BaseModel):
    """Email may be `null` to clear (modal allows blank submission)."""
    email: EmailStr | None = None


class AvatarChangeRequest(BaseModel):
    """`avatarUrl` is a `data:image/...;base64,...` URL produced by the modal."""
    avatarUrl: str


class ProfileSettingsRequest(BaseModel):
    """All fields optional — PATCH applies only the provided keys."""
    theme: Literal["system", "dark", "light"] | None = None
    timezone: str | None = None


class NotificationSettingsRequest(BaseModel):
    """All fields optional — PATCH applies only the provided keys."""
    assignments: bool | None = None
    mentions: bool | None = None
    kev: bool | None = None
    weeklyDigest: bool | None = None
    marketing: bool | None = None


class OrgSettingsRequest(BaseModel):
    """All fields optional — PATCH applies only the provided keys."""
    name: str | None = None


class OrgLogoRequest(BaseModel):
    """dataUrl is a `data:image/...;base64,...` URL, ≤100 KB."""
    dataUrl: str


class TotpEnrollResponse(BaseModel):
    qrDataUrl: str
    secret: str


class TotpVerifyRequest(BaseModel):
    code: str


class SsoConfigResponse(BaseModel):
    """Admin GET response. Secret fields appear as `{set: bool}` placeholders."""
    enabled: bool
    protocol: Literal["saml", "oidc"] | None
    defaultRoleId: str | None
    samlMetadataUrl: str | None
    samlMetadataXml: str | None
    samlSpCertificate: str | None
    samlSpPrivateKeySet: bool
    samlAcsUrl: str
    samlSpEntityId: str
    samlSpMetadataUrl: str
    oidcDiscoveryUrl: str | None
    oidcClientId: str | None
    oidcClientSecretSet: bool
    oidcScopes: str
    oidcRedirectUri: str
    updatedAt: str | None


class SsoConfigRequest(BaseModel):
    """Admin PATCH body. All fields optional. Secret fields only overwrite when non-empty."""
    enabled: bool | None = None
    protocol: Literal["saml", "oidc"] | None = None
    defaultRoleId: str | None = None
    samlMetadataUrl: str | None = None
    samlMetadataXml: str | None = None
    oidcDiscoveryUrl: str | None = None
    oidcClientId: str | None = None
    oidcClientSecret: str | None = None
    oidcScopes: str | None = None


class SamlKeypairResponse(BaseModel):
    certificate: str
    updatedAt: str


class ScimConfigResponse(BaseModel):
    enabled: bool
    defaultRoleId: str | None
    tokenSet: bool
    scimEndpointUrl: str
    updatedAt: str | None


class ScimConfigRequest(BaseModel):
    enabled: bool | None = None
    defaultRoleId: str | None = None


class ScimTokenResponse(BaseModel):
    token: str
    updatedAt: str


class AuditStreamConfigResponse(BaseModel):
    enabled: bool
    targetType: Literal["webhook", "splunk_hec", "syslog"] | None
    endpointUrl: str | None
    authTokenSet: bool
    lastEventId: int
    lastSuccessAt: str | None
    lastError: str | None
    updatedAt: str | None


class AuditStreamConfigRequest(BaseModel):
    enabled: bool | None = None
    targetType: Literal["webhook", "splunk_hec", "syslog"] | None = None
    endpointUrl: str | None = None
    authToken: str | None = None


class AuditStreamTestResponse(BaseModel):
    ok: bool
    error: str | None = None
