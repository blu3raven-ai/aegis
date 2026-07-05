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

    # 'self' authorises the same-origin Next.js chunks (entry + lazily loaded);
    # the per-page hashes authorise the inline bootstrap/RSC scripts so we keep
    # 'unsafe-inline' out. We deliberately do NOT use 'strict-dynamic': it makes
    # the browser ignore 'self' and demand a nonce on every parser-inserted
    # <script src>, which a static export cannot emit per request — that blocks
    # the chunks outright.
    script_src = ["'self'"]
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
    ])
    # NB: no 'require-trusted-types-for' — React writes to innerHTML during
    # reconciliation without producing a TrustedHTML, so enforcing it crashes
    # rendering. XSS defence stays on script-src ('self' + per-page hashes,
    # no 'unsafe-inline'), object-src, and base-uri.
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


def _build_graphiql_csp() -> str:
    """Relaxed CSP for Strawberry's GraphiQL page.

    GraphiQL loads React, the GraphiQL bundle, and js-cookie from unpkg.com
    and runs an inline initialiser. The HTML page is only ever served when
    ENABLE_BACKEND_DOCS=true (the GET is JWT-gated in require_jwt). Scoped
    to /api/v1/graphql so the rest of the app keeps the strict policy.
    """
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://unpkg.com",
        "style-src 'self' 'unsafe-inline' https://unpkg.com",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ])


def _is_docs_path(path: str) -> bool:
    return path == "/docs" or path.startswith("/docs/")


def _is_graphiql_path(path: str) -> bool:
    return path == "/api/v1/graphql"


def _resolve_html_csp(path: str, by_path: dict[str, str], default: str) -> str:
    """Return the CSP for an HTML response at *path*.

    Exact match first; then try replacing each path segment with the stub
    placeholder "_" that generateStaticParams emits for dynamic routes
    (e.g. /sources/abc123 → /sources/_ → sources/_.html's CSP).
    This mirrors the spa_fallback stub-substitution added in main.py.
    """
    if path in by_path:
        return by_path[path]
    parts = [p for p in path.strip("/").split("/") if p]
    for i in range(len(parts)):
        stub = "/" + "/".join(parts[:i] + ["_"] + parts[i + 1:])
        if stub in by_path:
            return by_path[stub]
    return default


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defense-in-depth security headers to every response.

    Includes hash-based CSP (no 'unsafe-inline' in script-src), HSTS,
    X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy,
    and Permissions-Policy.

    Each exported HTML page carries its own script hashes (inline bootstrap +
    RSC flight data differ per page), so the CSP is resolved per request path.
    Non-HTML responses (JSON, static assets) execute no inline scripts and get
    a minimal script-less policy, which also keeps their headers small. The
    maps are precomputed at construction and immutable thereafter — refreshing
    requires app restart.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        html_csp_by_path: dict[str, str],
        default_html_csp: str,
        base_csp: str,
    ) -> None:
        super().__init__(app)
        self._html_csp_by_path = html_csp_by_path
        # Served for unmatched routes, which spa_fallback serves the 404 document.
        self._default_html_csp = default_html_csp
        # Served for everything that isn't an HTML document.
        self._base_csp = base_csp
        self._docs_csp = _build_docs_csp()
        self._graphiql_csp = _build_graphiql_csp()

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
        path = request.url.path
        if _is_docs_path(path):
            response.headers["Content-Security-Policy"] = self._docs_csp
        elif _is_graphiql_path(path):
            response.headers["Content-Security-Policy"] = self._graphiql_csp
        elif "text/html" in response.headers.get("content-type", ""):
            # An HTML document: resolve using exact path first, then stub
            # substitution for dynamic routes (e.g. /sources/<id> → /sources/_).
            response.headers["Content-Security-Policy"] = _resolve_html_csp(
                path, self._html_csp_by_path, self._default_html_csp
            )
        else:
            response.headers["Content-Security-Policy"] = self._base_csp
        return response
