"""Signed double-submit CSRF — HMAC binds the token to the session ID.

For non-GET requests on routes that carry a session cookie, the token submitted
via X-CSRF-Token header must HMAC-match a token derived from the session id.
The token is bound to the session for the session's lifetime: the cookie is
issued at login alongside the session and expires with it, so rotating the
verifier independently of the cookie would silently break every session past
the grace window.

Login endpoints (no session yet) intentionally bypass this — they're protected
by rate limiting + a separate pre-session token mechanism.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Awaitable, Callable

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from src.auth.cookies import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME

logger = logging.getLogger(__name__)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Paths that always bypass CSRF. The login endpoints accept POST without an
# active session and must work even when the browser is carrying a stale
# session cookie from a previous run (e.g. SESSION_SECRET rotated). The logout
# endpoint clears the session and likewise needs no CSRF.
_CSRF_BYPASS_PATHS = frozenset({
    "/auth/login",
    "/auth/login/verify",
    "/auth/logout",
})


def _hmac(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def compute_csrf_token(session_id: str, *, secret: str) -> str:
    """Compute the CSRF token bound to a session id."""
    return _hmac(secret, session_id)


def verify_csrf_token(session_id: str, token: str, *, secret: str) -> bool:
    expected = compute_csrf_token(session_id, secret=secret)
    return hmac.compare_digest(token, expected)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforces signed double-submit CSRF on non-GET requests carrying a session.

    Bypass cases (no-op): safe methods (GET/HEAD/OPTIONS), and requests with
    no session cookie (login flow — defended by rate limiting + pre-session
    token).
    """

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

        if request.url.path in _CSRF_BYPASS_PATHS:
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
