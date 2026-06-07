"""FastAPI middleware that auto-records audit events for state-changing admin routes.

Only POST/PUT/PATCH/DELETE requests on paths matching the configured prefix list
are audited — GET requests and health/runner endpoints are ignored. This keeps
the audit log focused on sensitive mutations rather than becoming a request log.

For routes where automatic inference of action/resource is impossible or too
ambiguous, use the @audited decorator instead (or in addition).
"""
from __future__ import annotations

import logging
import re
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.audit_log.recorder import ActorInfo, AuditRecorder, RequestContext

logger = logging.getLogger(__name__)

# Mutating methods we care about — GET is never auto-audited via middleware
# (use @audited for sensitive reads).
_AUDIT_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Path prefixes whose mutating requests get auto-audited.
_AUDITABLE_PREFIXES = (
    "/api/v1/notifications/",
    "/api/v1/admin/",
    "/api/v1/integrations/",
    "/api/v1/audit/",
    "/settings/api/",
)

# Derive a human-readable action from method + path:
#   POST   /api/v1/notifications/destinations      → notification.destination.created
#   PUT    /api/v1/notifications/destinations/42   → notification.destination.updated
#   DELETE /api/v1/notifications/destinations/42   → notification.destination.deleted
#
# The mapping below handles known high-value paths explicitly; everything else
# falls back to a generic "<segment>.<method>" name.
_EXPLICIT_ACTION_MAP: dict[tuple[str, str], tuple[str, str]] = {
    # (METHOD, path_pattern): (action, resource_type)
    ("POST",   "/api/v1/notifications/destinations"):       ("notification.destination.created",  "notification_destination"),
    ("PUT",    r"/api/v1/notifications/destinations/\d+"):  ("notification.destination.updated",  "notification_destination"),
    ("DELETE", r"/api/v1/notifications/destinations/\d+"):  ("notification.destination.deleted",  "notification_destination"),
    ("POST",   "/argus/webhook"):                           ("argus.webhook.received",             "argus_event"),
}


def _match_explicit(method: str, path: str) -> tuple[str, str] | None:
    for (m, pattern), (action, rtype) in _EXPLICIT_ACTION_MAP.items():
        if m != method:
            continue
        # Treat as regex if it contains special chars, otherwise exact match
        if any(c in pattern for c in r"\^$[]{}()*+?|"):
            if re.fullmatch(pattern, path):
                return action, rtype
        else:
            if path == pattern:
                return action, rtype
    return None


def _infer_action(method: str, path: str) -> tuple[str, str]:
    """Derive (action, resource_type) when no explicit mapping exists."""
    suffix = {
        "POST": "created",
        "PUT": "updated",
        "PATCH": "updated",
        "DELETE": "deleted",
    }.get(method, method.lower())

    # Strip leading /api/v1/ or /settings/api/ and trailing numeric IDs
    clean = re.sub(r"^(/api/v1|/settings/api)", "", path)
    clean = re.sub(r"/\d+(/|$)", "/", clean).strip("/")
    segments = [s.replace("-", "_") for s in clean.split("/") if s and not s.isdigit()]
    resource_type = segments[-1] if segments else "unknown"
    action_base = ".".join(segments) if segments else "unknown"
    return f"{action_base}.{suffix}", resource_type


def _extract_resource_id(path: str) -> str | None:
    """Pull the last path segment if it looks like an ID (numeric or UUID-ish)."""
    parts = path.rstrip("/").split("/")
    last = parts[-1] if parts else ""
    if re.fullmatch(r"\d+|[0-9a-f\-]{32,}", last):
        return last
    return None


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, recorder: AuditRecorder | None = None) -> None:
        super().__init__(app)
        # Accept an injected recorder to allow test overrides
        from src.audit_log.recorder import get_recorder
        self._recorder = recorder or get_recorder()

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        method = request.method.upper()
        path = request.url.path

        if method not in _AUDIT_METHODS:
            return response

        if not any(path.startswith(p) for p in _AUDITABLE_PREFIXES):
            return response

        # Best-effort — never let a failed audit affect the response
        try:
            match = _match_explicit(method, path)
            if match:
                action, resource_type = match
            else:
                action, resource_type = _infer_action(method, path)

            actor = ActorInfo(
                user_id=getattr(request.state, "user_sub", None) or None,
                role=str(getattr(request.state, "user_role", "") or ""),
            )
            req_ctx = RequestContext(
                method=method,
                path=path,
                ip=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                status_code=response.status_code,
            )
            resource_id = _extract_resource_id(path)

            self._recorder.record(
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                actor=actor,
                request=req_ctx,
            )
        except Exception:
            logger.warning("audit_middleware: unexpected error recording event", exc_info=True)

        return response
