"""Tests for /api/v1/settings/profile (per-user theme + timezone)."""
from __future__ import annotations


def test_get_profile_returns_defaults_on_first_read():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="prefs-user-1")
    resp = client.get("/api/v1/settings/profile")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["theme"] == "system"
    assert body["timezone"] == "UTC"


def test_patch_profile_updates_theme_only():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="prefs-user-2")
    resp = client.patch("/api/v1/settings/profile", json={"theme": "dark"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["theme"] == "dark"
    assert body["timezone"] == "UTC"  # unchanged


def test_patch_profile_updates_timezone_only():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="prefs-user-3")
    resp = client.patch("/api/v1/settings/profile", json={"timezone": "Asia/Tokyo"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["timezone"] == "Asia/Tokyo"


def test_patch_profile_rejects_bad_theme():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="prefs-user-4")
    resp = client.patch("/api/v1/settings/profile", json={"theme": "neon"})
    assert resp.status_code == 422


def test_get_profile_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    resp = client.get("/api/v1/settings/profile")
    # SessionAuthMiddleware redirects unauthenticated browser navigations to
    # /login (302) and returns 401 for XHR/api callers without a session.
    assert resp.status_code in (302, 401)


def test_get_notifications_returns_defaults_on_first_read():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="notif-user-1")
    resp = client.get("/api/v1/settings/notifications")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {
        "assignments": True,
        "mentions": True,
        "kev": True,
        "weeklyDigest": True,
        "marketing": False,
    }


def test_patch_notifications_updates_only_provided_fields():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="notif-user-2")
    resp = client.patch("/api/v1/settings/notifications", json={"marketing": True, "kev": False})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["marketing"] is True
    assert body["kev"] is False
    assert body["assignments"] is True  # unchanged
