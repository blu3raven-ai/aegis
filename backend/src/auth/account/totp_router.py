"""Account TOTP enrollment endpoints.

Moved off GraphQL so the secret-bearing enroll response lives on the auth REST
surface alongside POST /auth/login/verify — keeping every channel that carries
a fresh TOTP secret behind the same HTTP-level audit and CSRF hooks (where
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
    begin_totp_enrollment as _begin_totp_enrollment,
    disable_totp as _disable_totp,
    verify_totp_enrollment as _verify_totp_enrollment,
)

_logger = logging.getLogger(__name__)

totp_router = APIRouter(prefix="/api/v1/auth/totp", tags=["auth"])


class TotpEnrollResponse(BaseModel):
    qrDataUrl: str
    secret: str


class TotpVerifyRequest(BaseModel):
    code: str


@totp_router.post("/enroll", response_model=TotpEnrollResponse)
def enroll(ctx: dict = Depends(require_caller_identity)) -> TotpEnrollResponse:
    try:
        result = _begin_totp_enrollment(info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return TotpEnrollResponse(qrDataUrl=result.qr_data_url, secret=result.secret)


@totp_router.post("/verify")
def verify(
    body: TotpVerifyRequest,
    ctx: dict = Depends(require_caller_identity),
) -> dict:
    try:
        _verify_totp_enrollment(code=body.code, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}


@totp_router.post("/disable")
def disable(
    body: TotpVerifyRequest,
    ctx: dict = Depends(require_caller_identity),
) -> dict:
    try:
        _disable_totp(code=body.code, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}
