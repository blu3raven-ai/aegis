"""Signed double-submit CSRF middleware."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Awaitable, Callable

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from src.auth.authentication.cookies import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME

logger = logging.getLogger(__name__)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_DEV_DOCS_BYPASS_PATHS = frozenset({"/api/v1/graphql"})

_CSRF_BYPASS_PATHS = frozenset({
    "/api/v1/auth/login",
    "/api/v1/auth/login/verify",
    "/api/v1/auth/logout",
    "/auth/sso/saml/acs",
    "/auth/sso/saml/slo",
    "/auth/sso/oidc/callback",
})

_CSRF_BYPASS_PREFIXES = (
    "/scim/v2/",
)


def _docs_enabled() -> bool:
    return os.getenv("ENABLE_BACKEND_DOCS", "").lower() == "true"


def _hmac(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def compute_csrf_token(session_id: str, *, secret: str) -> str:
    """Compute the CSRF token bound to a session id."""
    return _hmac(secret, session_id)


def verify_csrf_token(session_id: str, token: str, *, secret: str) -> bool:
    expected = compute_csrf_token(session_id, secret=secret)
    return hmac.compare_digest(token, expected)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforces CSRF on non-safe requests."""

    def __init__(self, app: ASGIApp, *, secret: str) -> None:
        super().__init__(app)
        self.secret = secret

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method in _SAFE_METHODS:
            return await call_next(request)

        path = request.url.path
        if path in _CSRF_BYPASS_PATHS:
            return await call_next(request)

        if any(path.startswith(p) for p in _CSRF_BYPASS_PREFIXES):
            return await call_next(request)

        if path in _DEV_DOCS_BYPASS_PATHS and _docs_enabled():
            return await call_next(request)

        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if session_id is None:
            return await call_next(request)

        header_token = request.headers.get("X-CSRF-Token")
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

        if header_token is None or cookie_token is None:
            logger.info(
                "csrf rejected: token missing (header=%s cookie=%s)",
                header_token is not None,
                cookie_token is not None,
            )
            return JSONResponse({"detail": "csrf check failed"}, status_code=403)

        if not hmac.compare_digest(header_token, cookie_token):
            logger.info("csrf rejected: header/cookie mismatch")
            return JSONResponse({"detail": "csrf check failed"}, status_code=403)

        if not verify_csrf_token(session_id, header_token, secret=self.secret):
            logger.info("csrf rejected: hmac verification failed")
            return JSONResponse({"detail": "csrf check failed"}, status_code=403)

        return await call_next(request)
