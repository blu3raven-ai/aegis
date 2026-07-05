"""CSRF tests — HMAC-bound token, session-lifetime stability, double-submit middleware."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.authentication.cookies import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME
from src.auth.authentication.csrf import (
    CSRFMiddleware,
    compute_csrf_token,
    verify_csrf_token,
)

SECRET = "test-secret-32-bytes-fixed-for-test"


def test_csrf_token_is_session_bound():
    t1 = compute_csrf_token("session-A", secret=SECRET)
    t2 = compute_csrf_token("session-B", secret=SECRET)
    assert t1 != t2


def test_csrf_token_is_stable_for_a_given_session():
    # The token is bound to the session id, not to wall-clock time. Rotating
    # the verifier without rotating the cookie would silently break every
    # session past the grace window.
    t1 = compute_csrf_token("session-A", secret=SECRET)
    t2 = compute_csrf_token("session-A", secret=SECRET)
    assert t1 == t2
    assert verify_csrf_token("session-A", t1, secret=SECRET)


def test_csrf_token_rejected_for_different_session():
    t = compute_csrf_token("session-A", secret=SECRET)
    assert not verify_csrf_token("session-B", t, secret=SECRET)


def test_csrf_token_rejected_for_tampered_token():
    t = compute_csrf_token("session-A", secret=SECRET)
    tampered = "0" * len(t)
    assert not verify_csrf_token("session-A", tampered, secret=SECRET)


def _build_app_with_middleware():
    app = FastAPI()
    app.add_middleware(CSRFMiddleware, secret=SECRET)

    @app.post("/state-change")
    def state_change():
        return {"ok": True}

    @app.post("/api/v1/auth/login")
    def login():
        return {"ok": True}

    @app.post("/api/v1/auth/login/verify")
    def login_verify():
        return {"ok": True}

    @app.post("/api/v1/auth/logout")
    def logout():
        return {"ok": True}

    @app.get("/safe")
    def safe():
        return {"ok": True}

    @app.post("/api/v1/graphql")
    def graphql():
        return {"ok": True}

    return app


def test_get_request_passes_without_csrf():
    client = TestClient(_build_app_with_middleware())
    response = client.get("/safe")
    assert response.status_code == 200


def test_post_without_session_passes_without_csrf():
    """No session = nothing to defend against; login endpoints are rate-limited."""
    client = TestClient(_build_app_with_middleware())
    response = client.post("/state-change")
    assert response.status_code == 200


def test_post_with_session_but_no_csrf_returns_403():
    client = TestClient(_build_app_with_middleware())
    client.cookies.set(SESSION_COOKIE_NAME, "session-A")
    response = client.post("/state-change")
    assert response.status_code == 403
    assert response.json()["detail"] == "csrf check failed"


def test_post_with_matching_csrf_passes():
    client = TestClient(_build_app_with_middleware())
    token = compute_csrf_token("session-A", secret=SECRET)
    client.cookies.set(SESSION_COOKIE_NAME, "session-A")
    client.cookies.set(CSRF_COOKIE_NAME, token)
    response = client.post("/state-change", headers={"X-CSRF-Token": token})
    assert response.status_code == 200


def test_post_with_mismatched_csrf_returns_403():
    client = TestClient(_build_app_with_middleware())
    token = compute_csrf_token("session-A", secret=SECRET)
    client.cookies.set(SESSION_COOKIE_NAME, "session-A")
    client.cookies.set(CSRF_COOKIE_NAME, token)
    response = client.post("/state-change", headers={"X-CSRF-Token": "wrong-token"})
    assert response.status_code == 403
    assert response.json()["detail"] == "csrf check failed"


def test_login_bypasses_csrf_even_with_stale_session_cookie():
    """Stale __Host-session cookie from a previous run must not break login.

    Chrome treats localhost as a secure context, so __Host-session cookies
    survive backend restarts (and SESSION_SECRET rotations). The login path
    must remain callable in that state.
    """
    client = TestClient(_build_app_with_middleware())
    client.cookies.set(SESSION_COOKIE_NAME, "stale-session-from-previous-run")
    response = client.post("/api/v1/auth/login")
    assert response.status_code == 200


def test_login_verify_bypasses_csrf_with_stale_session():
    client = TestClient(_build_app_with_middleware())
    client.cookies.set(SESSION_COOKIE_NAME, "stale-session")
    response = client.post("/api/v1/auth/login/verify")
    assert response.status_code == 200


def test_logout_bypasses_csrf_with_stale_session():
    client = TestClient(_build_app_with_middleware())
    client.cookies.set(SESSION_COOKIE_NAME, "stale-session")
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 200


def test_graphql_post_requires_csrf_when_docs_disabled(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    client = TestClient(_build_app_with_middleware())
    client.cookies.set(SESSION_COOKIE_NAME, "session-A")
    response = client.post("/api/v1/graphql", json={})
    assert response.status_code == 403


def test_graphql_post_bypasses_csrf_when_docs_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    client = TestClient(_build_app_with_middleware())
    client.cookies.set(SESSION_COOKIE_NAME, "session-A")
    response = client.post("/api/v1/graphql", json={})
    assert response.status_code == 200
