"""Defense-in-depth security headers including hash-based CSP.

The CSP allow-list uses `'sha256-<hash>'` entries (no `'unsafe-inline'`)
because Next.js static export produces deterministic inline scripts whose
hashes can be computed at startup (see auth.csp).
"""
from __future__ import annotations

import re
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Base64 of SHA-256 is exactly 44 chars: 43 base64 chars + 1 padding '='.
_SHA256_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def _build_csp(script_hashes: list[str]) -> str:
    for h in script_hashes:
        if not _SHA256_BASE64_RE.match(h):
            raise ValueError(
                f"invalid script hash format: expected base64-encoded SHA-256, "
                f"got {h!r}"
            )
    parts: list[str] = ["default-src 'self'"]

    script_src = ["'self'"]
    if script_hashes:
        # 'strict-dynamic' lets scripts loaded by hash-allowed scripts also
        # execute — needed for Next.js to load its lazy chunks.
        script_src.append("'strict-dynamic'")
        script_src.extend(f"'sha256-{h}'" for h in script_hashes)
    parts.append("script-src " + " ".join(script_src))

    parts.extend([
        # 'unsafe-inline' on style-src is the lower-risk concession Next.js
        # still requires for CSS-in-JS hydration.
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "require-trusted-types-for 'script'",
    ])
    return "; ".join(parts)


def _build_docs_csp() -> str:
    """Relaxed CSP for Swagger UI routes (self-hosted assets at /swagger).

    Swagger UI ships an inline initialiser script and renders via innerHTML,
    which the strict app-wide CSP (strict-dynamic + Trusted Types) blocks.
    The exemption is scoped to /docs only; everything else keeps the strict
    policy. No external host allowlist is needed — bundle + CSS are served
    from /swagger on the same origin.
    """
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ])


def _is_docs_path(path: str) -> bool:
    return path == "/docs" or path.startswith("/docs/")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defense-in-depth security headers to every response.

    Includes hash-based CSP (no 'unsafe-inline' in script-src), HSTS,
    X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy,
    and Permissions-Policy.

    The script-src hash list is precomputed at construction and immutable
    thereafter — refreshing requires app restart.
    """

    def __init__(self, app: ASGIApp, *, script_hashes: list[str]) -> None:
        super().__init__(app)
        self._csp = _build_csp(script_hashes)
        self._docs_csp = _build_docs_csp()

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if _is_docs_path(request.url.path):
            response.headers["Content-Security-Policy"] = self._docs_csp
        else:
            response.headers["Content-Security-Policy"] = self._csp
        return response
