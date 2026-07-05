"""Tests for /api/v1/workspace/users/* admin endpoints."""
from __future__ import annotations

from datetime import datetime, timezone

from src.db.helpers import run_db
from src.db.models import User


def _get_user(user_id: str) -> User | None:
    async def _q(session):
        return await session.get(User, user_id)
    return run_db(_q)


def _seed_user(
    user_id: str,
    *,
    username: str | None = None,
    email: str | None = None,
    role_id: str = "role_viewer",
    status: str = "active",
) -> None:
    async def _insert(session):
        existing = await session.get(User, user_id)
        if existing is not None:
            return
        now = datetime.now(timezone.utc)
        session.add(User(
            id=user_id,
            username=username or f"user-{user_id}",
            email=email or f"{user_id}@test.example",
            password_hash="",
            role_id=role_id,
            status=status,
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)


# ---------------------------------------------------------------------------
# GET /api/v1/workspace/users
# ---------------------------------------------------------------------------

def test_get_users_returns_user_list():
    from conftest import make_authed_client

    actor_id = "wsu-list-admin"
    target_id = "wsu-list-target"
    _seed_user(target_id, username="list-target", email="list-target@test.example")
    client = make_authed_client(role="admin", user_id=actor_id)

    resp = client.get("/api/v1/workspace/users")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = {u["id"] for u in body["users"]}
    assert actor_id in ids
    assert target_id in ids

    target = next(u for u in body["users"] if u["id"] == target_id)
    assert target["username"] == "list-target"
    assert target["email"] == "list-target@test.example"
    assert target["status"] == "active"
    assert "roleId" in target and "createdAt" in target


def test_get_users_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).get("/api/v1/workspace/users")
    assert resp.status_code == 401


def test_get_users_requires_manage_users_permission():
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="wsu-list-viewer")

    resp = client.get("/api/v1/workspace/users")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/users
# ---------------------------------------------------------------------------

def test_post_users_creates_user():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsu-create-admin")

    resp = client.post(
        "/api/v1/workspace/users",
        json={
            "username": "freshly-invited",
            "email": "fresh@test.example",
            "password": "long-enough-password",
            "role": "viewer",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["username"] == "freshly-invited"
    assert body["email"] == "fresh@test.example"
    assert body["status"] == "active"
    assert body["roleId"] == "role_viewer"

    created = _get_user(body["id"])
    assert created is not None
    assert created.role_id == "role_viewer"


def test_post_users_rejects_short_password():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsu-create-admin-2")

    resp = client.post(
        "/api/v1/workspace/users",
        json={
            "username": "short-pw",
            "email": "shortpw@test.example",
            "password": "tooshort",
            "role": "viewer",
        },
    )
    assert resp.status_code == 400, resp.text


def test_post_users_requires_manage_users_permission():
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="wsu-create-viewer")

    resp = client.post(
        "/api/v1/workspace/users",
        json={
            "username": "should-not-create",
            "email": "denied@test.example",
            "password": "long-enough-password",
            "role": "viewer",
        },
    )
    assert resp.status_code == 403


def test_post_users_promote_to_owner_requires_manage_owner_role():
    from conftest import make_authed_client
    # admin role does NOT have manage_owner_role permission
    client = make_authed_client(role="admin", user_id="wsu-create-admin-3")

    resp = client.post(
        "/api/v1/workspace/users",
        json={
            "username": "would-be-owner",
            "email": "wouldbe@test.example",
            "password": "long-enough-password",
            "role": "owner",
        },
    )
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/users/{user_id}/enable
# ---------------------------------------------------------------------------

def test_post_enable_user_activates_disabled_user():
    from conftest import make_authed_client
    target_id = "wsu-enable-target"
    _seed_user(target_id, status="disabled")
    client = make_authed_client(role="admin", user_id="wsu-enable-admin")

    resp = client.post(f"/api/v1/workspace/users/{target_id}/enable")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}
    assert _get_user(target_id).status == "active"


def test_post_enable_user_not_found():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsu-enable-admin-2")

    resp = client.post("/api/v1/workspace/users/usr_nonexistent/enable")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/users/{user_id}/disable
# ---------------------------------------------------------------------------

def test_post_disable_user_deactivates_active_user():
    from conftest import make_authed_client
    target_id = "wsu-disable-target"
    _seed_user(target_id, status="active")
    client = make_authed_client(role="admin", user_id="wsu-disable-admin")

    resp = client.post(f"/api/v1/workspace/users/{target_id}/disable")
    assert resp.status_code == 200, resp.text
    assert _get_user(target_id).status == "disabled"


# ---------------------------------------------------------------------------
# PATCH /api/v1/workspace/users/{user_id}/role
# ---------------------------------------------------------------------------

def test_patch_user_role_changes_role():
    from conftest import make_authed_client
    target_id = "wsu-role-target"
    _seed_user(target_id, role_id="role_viewer")
    # owner can assign any role
    client = make_authed_client(role="owner", user_id="wsu-role-owner")

    resp = client.patch(
        f"/api/v1/workspace/users/{target_id}/role",
        json={"roleId": "role_security"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["roleId"] == "role_security"
    assert _get_user(target_id).role_id == "role_security"


def test_patch_user_role_requires_manage_users_permission():
    from conftest import make_authed_client
    target_id = "wsu-role-denied-target"
    _seed_user(target_id, role_id="role_viewer")
    client = make_authed_client(role="viewer", user_id="wsu-role-viewer")

    resp = client.patch(
        f"/api/v1/workspace/users/{target_id}/role",
        json={"roleId": "role_security"},
    )
    assert resp.status_code == 403


def test_patch_user_role_owner_change_requires_manage_owner_role():
    from conftest import make_authed_client
    target_id = "wsu-role-promote-target"
    _seed_user(target_id, role_id="role_viewer")
    # admin lacks manage_owner_role
    client = make_authed_client(role="admin", user_id="wsu-role-admin-promote")

    resp = client.patch(
        f"/api/v1/workspace/users/{target_id}/role",
        json={"roleId": "role_owner"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/users/{user_id}/reset-password
# ---------------------------------------------------------------------------

def test_post_reset_password_updates_hash():
    from conftest import make_authed_client
    target_id = "wsu-reset-target"
    _seed_user(target_id)
    before = _get_user(target_id).password_hash

    client = make_authed_client(role="admin", user_id="wsu-reset-admin")
    resp = client.post(
        f"/api/v1/workspace/users/{target_id}/reset-password",
        json={"password": "long-enough-password"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}

    after = _get_user(target_id).password_hash
    assert after and after != before
    assert after.startswith("scrypt:v1:")


def test_post_reset_password_rejects_short_password():
    from conftest import make_authed_client
    target_id = "wsu-reset-short-target"
    _seed_user(target_id)

    client = make_authed_client(role="admin", user_id="wsu-reset-admin-2")
    resp = client.post(
        f"/api/v1/workspace/users/{target_id}/reset-password",
        json={"password": "tooshort"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# DELETE /api/v1/workspace/users/{user_id}
# ---------------------------------------------------------------------------

def test_delete_user_removes_row():
    from conftest import make_authed_client
    target_id = "wsu-delete-target"
    _seed_user(target_id)
    assert _get_user(target_id) is not None

    client = make_authed_client(role="admin", user_id="wsu-delete-admin")
    resp = client.delete(f"/api/v1/workspace/users/{target_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}
    assert _get_user(target_id) is None


def test_delete_user_rejects_self_delete():
    from conftest import make_authed_client
    actor_id = "wsu-delete-self"
    client = make_authed_client(role="admin", user_id=actor_id)

    resp = client.delete(f"/api/v1/workspace/users/{actor_id}")
    assert resp.status_code == 400
    assert _get_user(actor_id) is not None


def test_delete_user_not_found():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsu-delete-admin-2")

    resp = client.delete("/api/v1/workspace/users/usr_nonexistent")
    assert resp.status_code == 404
