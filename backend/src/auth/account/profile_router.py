"""Account profile, notification-prefs and avatar endpoints.

Moved off GraphQL so all self-service account state lives alongside the rest
of the auth REST surface — uniform HTTP-level audit, CSRF and rate-limit hooks
without a separate GraphQL transport for what are simple single-row PATCH/PUT
operations.

The notification *preferences* (opt-in toggles for assignments / mentions /
kev / weekly digest / marketing) live at `/notification-prefs` to keep them
clear of `src.notifications.router` (`/notifications/*`), which serves the
inbox items.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Response, status
from graphql import GraphQLError
from pydantic import BaseModel, ConfigDict, Field

from src.auth._gql_errors import raise_for_gql
from src.authz.enforcement import require_caller_identity
from src.auth.account.service import (
    account_notifications as _account_notifications,
    account_profile as _account_profile,
    clear_avatar as _clear_avatar,
    set_avatar as _set_avatar,
    update_account_notifications as _update_account_notifications,
    update_account_profile as _update_account_profile,
)

_logger = logging.getLogger(__name__)

profile_router = APIRouter(prefix="/api/v1/settings/account", tags=["settings"])


class ProfilePatchRequest(BaseModel):
    theme: Optional[str] = None
    timezone: Optional[str] = None


class ProfileResponse(BaseModel):
    theme: str
    timezone: str


class NotificationsPatchRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assignments: Optional[bool] = None
    mentions: Optional[bool] = None
    kev: Optional[bool] = None
    weekly_digest: Optional[bool] = Field(default=None, alias="weeklyDigest")
    marketing: Optional[bool] = None


class NotificationsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assignments: bool
    mentions: bool
    kev: bool
    weekly_digest: bool = Field(serialization_alias="weeklyDigest")
    marketing: bool


class AvatarPutRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    avatar_url: str = Field(alias="avatarUrl")


@profile_router.get("/profile", response_model=ProfileResponse)
def get_profile(ctx: dict = Depends(require_caller_identity)) -> ProfileResponse:
    try:
        result = _account_profile(info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return ProfileResponse(theme=result.theme, timezone=result.timezone)


@profile_router.patch("/profile", response_model=ProfileResponse)
def update_profile(
    body: ProfilePatchRequest,
    ctx: dict = Depends(require_caller_identity),
) -> ProfileResponse:
    try:
        result = _update_account_profile(
            theme=body.theme,
            timezone=body.timezone,
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return ProfileResponse(theme=result.theme, timezone=result.timezone)


@profile_router.get("/notification-prefs", response_model=NotificationsResponse)
def get_notification_prefs(ctx: dict = Depends(require_caller_identity)) -> NotificationsResponse:
    try:
        result = _account_notifications(info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return NotificationsResponse(
        assignments=result.assignments,
        mentions=result.mentions,
        kev=result.kev,
        weekly_digest=result.weekly_digest,
        marketing=result.marketing,
    )


@profile_router.patch("/notification-prefs", response_model=NotificationsResponse)
def update_notification_prefs(
    body: NotificationsPatchRequest,
    ctx: dict = Depends(require_caller_identity),
) -> NotificationsResponse:
    try:
        result = _update_account_notifications(
            assignments=body.assignments,
            mentions=body.mentions,
            kev=body.kev,
            weekly_digest=body.weekly_digest,
            marketing=body.marketing,
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return NotificationsResponse(
        assignments=result.assignments,
        mentions=result.mentions,
        kev=result.kev,
        weekly_digest=result.weekly_digest,
        marketing=result.marketing,
    )


@profile_router.put("/avatar", status_code=status.HTTP_204_NO_CONTENT)
def set_avatar(
    body: AvatarPutRequest,
    ctx: dict = Depends(require_caller_identity),
) -> Response:
    try:
        _set_avatar(avatar_url=body.avatar_url, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@profile_router.delete("/avatar", status_code=status.HTTP_204_NO_CONTENT)
def clear_avatar(ctx: dict = Depends(require_caller_identity)) -> Response:
    try:
        _clear_avatar(info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
