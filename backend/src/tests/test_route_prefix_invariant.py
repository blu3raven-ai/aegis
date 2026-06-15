"""Locks in the API path convention from
.claude/tmp/specs/2026-06-15-backend-api-path-standardization-design.md.

Every application-API route must live under /api/v1/. Endpoints with an external
contract (webhooks, OAuth callbacks, SCIM, health, FastAPI built-ins) are
allow-listed by exact path or by prefix.
"""
from __future__ import annotations

from fastapi.routing import APIRoute

from src.main import app


# Exact-path exemptions — bare endpoints (no descendants).
EXEMPT_EXACT = (
    # FastAPI built-ins (only registered when ENABLE_BACKEND_DOCS=true)
    "/openapi.json",
    "/docs",
    "/redoc",
    # GraphQL endpoint (mounted under /api with its own version semantics)
    "/api/graphql",
    # k8s probe root — sub-routes match the "/health/" prefix entry below
    "/health",
)


# Prefix exemptions — entire trees rooted at these paths.
# Every entry MUST end with "/" so the matcher forces a path-segment boundary.
EXEMPT_PREFIXES = (
    # k8s liveness/readiness probes — convention is unversioned
    "/health/",
    # Auth / SSO browser-redirect URLs (cookie scope, registered with IdPs)
    "/auth/",
    # SCIM v2 protocol (RFC 7644)
    "/scim/v2/",
    # External webhook URLs (registered with third-party providers)
    "/integrations/github/",
    "/integrations/gitlab/",
    "/integrations/bitbucket/",
    "/argus/",
)


def test_every_application_route_lives_under_api_v1() -> None:
    offenders: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if path.startswith("/api/v1/"):
            continue
        if path in EXEMPT_EXACT:
            continue
        if any(path.startswith(p) for p in EXEMPT_PREFIXES):
            continue
        offenders.append(path)
    assert not offenders, (
        "These routes violate the /api/v1 convention. Either move them under "
        f"/api/v1/ or add their prefix to EXEMPT_PREFIXES (with trailing /) "
        f"or EXEMPT_EXACT, with a comment explaining the external contract:\n  - "
        + "\n  - ".join(sorted(offenders))
    )
