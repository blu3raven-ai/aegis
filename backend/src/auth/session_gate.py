"""Session auth gate — Starlette middleware enforcing cookie-based auth.

Decision matrix (see PR 1 spec for rationale):
- Public path / prefix       → pass
- No cookie, /api or /graphql → 401 JSON
- No cookie, page request    → 302 to /login
- Invalid/revoked/expired    → same 401/302 split
- session.user.status == "pending", /api or /graphql → 401 JSON {"detail": "pending"}
- session.user.status == "pending", not on /pending  → 302 to /pending
- session.user.status == "active",  on /pending      → 302 to /
- otherwise                  → pass, attach request.state.user/session

DORMANT in PR 1: defined but not registered on the FastAPI app. Goes live
in PR 3 cutover when the BFF auth is deleted.
"""
from __future__ import annotations

from typing import Awaitable, Callable, Protocol

from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from src.auth.cookies import SESSION_COOKIE_NAME

# "/" and "/pending" are intentionally absent:
# - Unauthenticated GET / must redirect to /login per the decision matrix.
# - /pending must be session-gated so the middleware can enforce the
#   active-user-on-/pending → / redirect (the matrix can't fire if the path
#   is public). Unauthenticated requests to /pending fall through to the
#   standard 302-to-login branch.
PUBLIC_PATHS = frozenset({
    "/login", "/login/verify",
    "/auth/login", "/auth/login/verify", "/auth/logout",
    "/auth/sso/saml/login", "/auth/sso/saml/acs", "/auth/sso/saml/metadata",
    "/auth/sso/oidc/login", "/auth/sso/oidc/callback",
    "/health/live", "/health/ready",
    "/openapi.json", "/docs", "/redoc",
    "/api/v1/branding",
    "/api/v1/sso/sso-availability",
})

PUBLIC_PREFIXES = (
    "/_next/static/",
    "/assets/",
    "/favicon",
    # Self-hosted Swagger UI assets backing /docs
    "/swagger/",
    # Runner agent endpoints authenticate via runner Bearer tokens (not sessions)
    "/api/v1/runner/",
    # SCM webhook endpoints authenticate via HMAC signatures (not sessions)
    "/integrations/",
    # SCIM endpoints authenticate via their own bearer-token dependency
    "/scim/v2/",
)

# /graphql is a valid bare path; /graphql/anything is also API.
# Use an exact-match set for bare paths and a prefix set for path trees so
# that /graphqlinjector and similar typosquats don't accidentally match.
API_PATHS = frozenset({"/graphql"})
# Primary API path trees — anything under /api/ or /graphql/. The substring
# check below still matches legacy /*/api/* shapes if any reappear, so
# machine clients always see 401 JSON rather than a 302 redirect.
API_PREFIXES = ("/api/", "/graphql/")


def _is_public(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(p) for p in PUBLIC_PREFIXES)


def _is_api(path: str) -> bool:
    if path in API_PATHS:
        return True
    if any(path.startswith(p) for p in API_PREFIXES):
        return True
    # Defensive fallback: any path containing "/api/" is treated as API so
    # legacy or tool-namespaced shapes still return 401 JSON for unauthenticated
    # machine clients rather than a 302 page redirect.
    return "/api/" in path


class _UserLike(Protocol):
    status: str


class _SessionLike(Protocol):
    user_id: str
    user: "_UserLike"


class _SessionServiceLike(Protocol):
    """Structural type so the middleware can be tested with an in-memory fake."""
    async def lookup(self, session_id: str) -> "_SessionLike | None": ...


async def _release_service(service: object) -> None:
    """Close any DB session held by the service so the pooled connection is
    returned to the pool deterministically — otherwise SQLAlchemy logs
    'garbage collector is trying to clean up non-checked-in connection'
    warnings when the service is GC'd while still holding a connection.

    Tolerates fakes (in-memory test doubles) that have no `db` attribute.
    """
    db = getattr(service, "db", None)
    if db is None:
        return
    close = getattr(db, "close", None)
    if close is None:
        return
    await close()


class SessionAuthMiddleware(BaseHTTPMiddleware):
    """Enforces cookie-based auth gate on non-public requests.

    Looks up the session via an injected service factory so the middleware
    is testable without a database. In production the factory yields a real
    SessionService bound to the request's DB session.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        session_service_factory: Callable[[], _SessionServiceLike],
    ) -> None:
        super().__init__(app)
        self._make_service = session_service_factory

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path

        if _is_public(path):
            return await call_next(request)

        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            return self._unauth(path)

        service = self._make_service()
        try:
            session = await service.lookup(session_id)
            if session is None:
                return self._unauth(path)

            user_status = session.user.status
            if user_status == "pending":
                # Pending users have no API access — return 401 so clients get a
                # clear machine-readable signal rather than an unexpected redirect.
                if _is_api(path):
                    return JSONResponse({"detail": "pending"}, status_code=401)
                if not path.startswith("/pending"):
                    return RedirectResponse("/pending", status_code=302)
            if user_status == "active" and path.startswith("/pending"):
                return RedirectResponse("/", status_code=302)

            request.state.session = session
            request.state.user = session.user
            return await call_next(request)
        finally:
            await _release_service(service)

    def _unauth(self, path: str) -> Response:
        if _is_api(path):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=302)
