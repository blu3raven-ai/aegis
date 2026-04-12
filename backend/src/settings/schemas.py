from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


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
    docker_image_present: bool = False
    signature_valid: bool = False
    image_name: str = ""
    registry_image: str = ""
    signature: str | None = None
    digest: str | None = None
    error: str | None = None
    # Scanner image lifecycle status for richer UI guidance
    scanner_status: str | None = None  # ready | building | missing | invalid | pull_failed | build_failed | no_runner
    scanner_source: str | None = None  # local | registry — how the runner acquires images
    runner_name: str | None = None
    runner_platform: str | None = None


class DirectGrantRequest(BaseModel):
    userId: str
    resourceType: Literal["repository", "containerImage"]
    resourceKey: str


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
