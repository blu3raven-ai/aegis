"""Translate `GraphQLError` raised by service helpers into `HTTPException`.

The auth REST routers (`account/*_router.py`, `workspace/*_router.py`) call
shared service functions that historically lived on the GraphQL surface and
still raise `GraphQLError(extensions={"code": "..."})` for coded failures.
This helper maps those codes to the corresponding HTTP status so each REST
endpoint behaves like a native REST endpoint without each handler having to
hand-roll the same try/except.
"""
from __future__ import annotations

import logging
from typing import NoReturn

from fastapi import HTTPException
from graphql import GraphQLError

_logger = logging.getLogger(__name__)


GQL_CODE_TO_STATUS: dict[str, int] = {
    "UNAUTHENTICATED": 401,
    "PERMISSION_DENIED": 403,
    "BAD_USER_INPUT": 400,
    "VALIDATION_ERROR": 400,
    "NOT_FOUND": 404,
    "CONFLICT": 409,
}


def raise_for_gql(
    err: GraphQLError,
    *,
    logger: logging.Logger | None = None,
) -> NoReturn:
    code = (err.extensions or {}).get("code")
    status = GQL_CODE_TO_STATUS.get(code) if isinstance(code, str) else None
    if status is None:
        # Never echo resolver-internal messages on unmapped errors — those can
        # leak stack-trace fragments or implementation hints into client bodies.
        (logger or _logger).exception(
            "Unmapped GraphQL error in auth router",
            extra={"gql_code": code},
        )
        raise HTTPException(status_code=500, detail="internal server error")
    raise HTTPException(status_code=status, detail=err.message)
