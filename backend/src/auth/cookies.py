"""Cookie helpers enforcing __Host- prefix and security attributes.

The __Host- cookie prefix is a browser-enforced security feature. ANY cookie
named __Host-* MUST: be Secure-only, have Path=/, and have no Domain attribute.
The browser will silently drop cookies that violate these rules — defends against
cookie injection from subdomain takeover.

Session cookie is HttpOnly (JS cannot read). CSRF cookie is NOT HttpOnly because
the double-submit pattern requires client JS to read the value and echo it in
an X-CSRF-Token header.
"""
from __future__ import annotations

import re

from fastapi import Response

SESSION_COOKIE_NAME = "__Host-session"
CSRF_COOKIE_NAME = "__Host-csrf"

# RFC 6265 cookie-octet allows token-urlsafe chars; we explicitly enforce the
# subset that `secrets.token_urlsafe` produces. Anything else is a programmer
# error — fail loudly at the boundary rather than silently mangling.
_COOKIE_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _validate_cookie_value(value: str, *, field: str) -> None:
    if not value:
        raise ValueError(f"{field} must be non-empty")
    if not _COOKIE_VALUE_RE.match(value):
        raise ValueError(f"{field} contains characters not allowed in a cookie value")


def set_session_cookie(response: Response, *, session_id: str, max_age: int) -> None:
    _validate_cookie_value(session_id, field="session_id")
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=max_age,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
    )


def set_csrf_cookie(response: Response, *, csrf_token: str, max_age: int) -> None:
    _validate_cookie_value(csrf_token, field="csrf_token")
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age,
        path="/",
        httponly=False,
        secure=True,
        samesite="lax",
    )


def clear_auth_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE_NAME, CSRF_COOKIE_NAME):
        response.set_cookie(
            key=name,
            value="",
            max_age=0,
            path="/",
            httponly=False,
            secure=True,
            samesite="lax",
        )
