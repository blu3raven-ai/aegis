"""Account email-change endpoint.

Moved off GraphQL so this security-recovery channel lives next to
PATCH /api/v1/settings/account (password) on the auth REST surface —
both belong behind the same HTTP-level audit and CSRF hooks (where
rate-limit middleware can be applied uniformly when needed).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from graphql import GraphQLError
from pydantic import BaseModel

from src.auth._gql_errors import raise_for_gql
from src.authz.enforcement import require_caller_identity
from src.auth.account.service import (
    change_email as _change_email,
    confirm_email_change as _confirm_email_change,
)

_logger = logging.getLogger(__name__)

email_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class EmailChangeRequest(BaseModel):
    email: str
    # Current-password re-auth; ignored for password-less SSO accounts.
    current_password: str = ""


class EmailVerifyRequest(BaseModel):
    token: str


@email_router.patch("/email")
def change_email(
    body: EmailChangeRequest,
    ctx: dict = Depends(require_caller_identity),
) -> dict:
    try:
        _change_email(
            email=body.email, current_password=body.current_password, info_context=ctx
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}


@email_router.post("/email/verify")
def verify_email(body: EmailVerifyRequest) -> dict:
    # Intentionally unauthenticated: the single-use, expiring token delivered to
    # the new address is the capability — the recipient proving inbox control is
    # exactly the check, and they may open the link without an active session.
    try:
        _confirm_email_change(token=body.token)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}
