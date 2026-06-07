"""Cookie helper tests — verifies __Host- prefix attributes and clearing."""
import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from src.auth.cookies import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    clear_auth_cookies,
    set_csrf_cookie,
    set_session_cookie,
)


def _build_app():
    app = FastAPI()

    @app.post("/set-session")
    def _set_session(response: Response):
        set_session_cookie(response, session_id="sess123", max_age=3600)
        return {"ok": True}

    @app.post("/set-csrf")
    def _set_csrf(response: Response):
        set_csrf_cookie(response, csrf_token="csrf123", max_age=3600)
        return {"ok": True}

    @app.post("/clear")
    def _clear(response: Response):
        clear_auth_cookies(response)
        return {"ok": True}

    return app


def test_session_cookie_has_host_prefix_and_secure_attrs():
    client = TestClient(_build_app())
    response = client.post("/set-session")
    set_cookie_header = response.headers.get("set-cookie", "")
    assert SESSION_COOKIE_NAME == "__Host-session"
    assert "__Host-session=sess123" in set_cookie_header
    assert "HttpOnly" in set_cookie_header
    assert "Secure" in set_cookie_header
    # Starlette emits "SameSite=lax" (mixed-case key, lowercase value) in practice;
    # allow either real-world casing
    assert ("SameSite=Lax" in set_cookie_header) or ("SameSite=lax" in set_cookie_header)
    assert "Path=/" in set_cookie_header
    # __Host- prefix forbids Domain
    assert "Domain=" not in set_cookie_header
    assert "Max-Age=3600" in set_cookie_header


def test_csrf_cookie_is_not_httponly():
    """CSRF cookie must be JS-readable for the double-submit pattern."""
    client = TestClient(_build_app())
    response = client.post("/set-csrf")
    set_cookie_header = response.headers.get("set-cookie", "")
    assert CSRF_COOKIE_NAME == "__Host-csrf"
    assert "__Host-csrf=csrf123" in set_cookie_header
    assert "HttpOnly" not in set_cookie_header
    assert "Secure" in set_cookie_header
    assert "Path=/" in set_cookie_header


def test_clear_auth_cookies_emits_expired_cookies():
    client = TestClient(_build_app())
    response = client.post("/clear")
    headers = response.headers.get_list("set-cookie")
    session_cleared = any("__Host-session=" in h and "Max-Age=0" in h for h in headers)
    csrf_cleared = any("__Host-csrf=" in h and "Max-Age=0" in h for h in headers)
    assert session_cleared
    assert csrf_cleared


def test_set_session_cookie_rejects_empty_id():
    response = Response()
    with pytest.raises(ValueError, match="session_id must be non-empty"):
        set_session_cookie(response, session_id="", max_age=3600)


def test_set_session_cookie_rejects_unsafe_chars():
    response = Response()
    with pytest.raises(ValueError, match="session_id contains characters not allowed"):
        set_session_cookie(response, session_id="abc;def", max_age=3600)


def test_set_csrf_cookie_rejects_empty_token():
    response = Response()
    with pytest.raises(ValueError, match="csrf_token must be non-empty"):
        set_csrf_cookie(response, csrf_token="", max_age=3600)


def test_set_csrf_cookie_rejects_unsafe_chars():
    response = Response()
    with pytest.raises(ValueError, match="csrf_token contains characters not allowed"):
        set_csrf_cookie(response, csrf_token="abc\ndef", max_age=3600)
