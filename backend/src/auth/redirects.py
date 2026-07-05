"""Legacy URL redirects — ported from frontend/next.config.ts redirects().

After PR 4 deletes the Next.js redirects() block, FastAPI owns these
permanent redirects. Pattern-based using a small dispatch table.

Dormant in this PR — Task 6 registers the middleware on the app.
"""
from __future__ import annotations

import re
from typing import Awaitable, Callable

from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# Each entry: (compiled regex on path, target template). Match groups may be
# referenced in the target via \g<name>.
_REDIRECTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/settings/sources/code-repositories/?$"),
     "/sources/code-repositories"),
    (re.compile(r"^/settings/sources/code-repositories/(?P<id>[^/]+)$"),
     "/sources/code-repositories/\\g<id>"),

    (re.compile(r"^/settings/sources/container-images/?$"),
     "/sources/container-registry"),
    (re.compile(r"^/settings/sources/container-images/(?P<id>[^/]+)$"),
     "/sources/container-registry/\\g<id>"),

    # ci-cd-pipelines and any sub-path redirect to /sources/code-repositories.
    # Sub-path is intentionally dropped — matches Next.js destination behavior
    # when the redirect target has no :path* template.
    (re.compile(r"^/settings/sources/ci-cd-pipelines(/.*)?$"),
     "/sources/code-repositories"),

    (re.compile(r"^/settings/dependencies/?$"),
     "/dependencies/dashboard?tab=settings"),
    (re.compile(r"^/settings/containers/?$"),
     "/containers/dashboard?tab=settings"),
    (re.compile(r"^/settings/code/?$"),
     "/code/dashboard?tab=settings"),
    (re.compile(r"^/settings/secrets/?$"),
     "/secrets/dashboard?tab=settings"),
]


class LegacyRedirectMiddleware(BaseHTTPMiddleware):
    """Permanent 308 redirects for legacy URLs.

    Registered before the auth gate so redirects fire even for
    unauthenticated requests — users following a stale bookmark or
    link should be sent to the new URL before being challenged for auth.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        for pattern, target in _REDIRECTS:
            match = pattern.match(path)
            if match:
                # `re.sub` resolves named back-references like \g<id>; using it
                # ensures escaping is consistent with the regex engine.
                resolved = pattern.sub(target, path)
                return RedirectResponse(resolved, status_code=308)
        return await call_next(request)
