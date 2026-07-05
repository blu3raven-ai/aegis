"""@audited decorator for explicit route-level audit events.

Use this for routes that the middleware can't handle automatically — e.g.
sensitive GET endpoints, or routes where the action name must be more precise
than what path inference produces.

Usage:

    @audited(action="argus.api_key.read", resource_type="argus_config")
    @router.get("/argus/config")
    async def get_argus_config(request: Request, ...): ...

The decorator wraps the function and fires a post-call audit event carrying the
actor extracted from request.state. For async route functions it uses await; for
sync functions it calls directly.
"""
from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


def audited(
    *,
    action: str,
    resource_type: str,
    resource_id_param: str | None = None,
) -> Callable:
    """Decorator that records an AuditEvent after the wrapped route returns.

    Args:
        action:            Dot-separated action name, e.g. "argus.api_key.read".
        resource_type:     Resource category, e.g. "argus_config".
        resource_id_param: Name of the route parameter to use as resource_id.
                           If None, no resource_id is recorded.
    """
    def decorator(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await fn(*args, **kwargs)
                _fire(args, kwargs, result)
                return result
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = fn(*args, **kwargs)
                _fire(args, kwargs, result)
                return result
            return sync_wrapper

    def _fire(args: tuple, kwargs: dict, result: Any) -> None:
        try:
            from fastapi import Request
            from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder

            request: Request | None = None
            # FastAPI injects Request via keyword arg "request" or positional
            for v in list(args) + list(kwargs.values()):
                if isinstance(v, Request):
                    request = v
                    break

            actor = ActorInfo()
            req_ctx = RequestContext()
            if request is not None:
                actor = ActorInfo(
                    user_id=getattr(request.state, "user_sub", None) or None,
                    role=str(getattr(request.state, "user_role", "") or ""),
                )
                req_ctx = RequestContext(
                    method=request.method.upper(),
                    path=request.url.path,
                    ip=_client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                )

            resource_id: str | None = None
            if resource_id_param:
                resource_id = str(kwargs.get(resource_id_param, "") or "")

            get_recorder().record(
                action=action,
                resource_type=resource_type,
                resource_id=resource_id or None,
                actor=actor,
                request=req_ctx,
            )
        except Exception:
            logger.warning("audited: failed to record event action=%s", action, exc_info=True)

    return decorator


def _client_ip(request: Any) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
