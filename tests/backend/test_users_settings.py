from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import src.settings.users_router as users_router
from src.db.helpers import run_db
from src.db.models import AuditEvent, DirectGrant, Role, User
from src.db.seed import DEFAULT_ROLES
from src.main import app
from sqlalchemy import delete, select


def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def make_jwt(sub: str, role: str, secret: str) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload = _b64url(json.dumps({"sub": sub, "role": role, "iat": now, "exp": now + 60}))
    if len(secret) == 64:
        try:
            key = bytes.fromhex(secret)
        except ValueError:
            key = secret.encode("utf-8")
    else:
        key = secret.encode("utf-8")
    signature = _b64url(hmac.new(key, f"{header}.{payload}".encode("utf-8"), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


@pytest.fixture
def client():
    c = TestClient(app)
    c.headers.update(auth_headers(sub="usr_admin", role="admin"))
    return c


def _seed_builtin_roles() -> None:
    """Ensure the four built-in roles exist in the DB."""
    async def _query(session):
        for role_data in DEFAULT_ROLES:
            existing = await session.get(Role, role_data["id"])
            if not existing:
                session.add(Role(
                    id=role_data["id"],
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                    protected=role_data["protected"],
                    created_at=datetime.now(timezone.utc),
                ))
    run_db(_query)


def _seed_users(users: list[dict]) -> None:
    """Insert users into the database."""
    async def _query(session):
        for u in users:
            now = datetime.now(timezone.utc)
            session.add(User(
                id=u["id"],
                username=u["username"],
                email=u.get("email", ""),
                password_hash=u.get("passwordHash", ""),
                role=u.get("role", "viewer"),
                status=u.get("status", "active"),
                password_reset_required=u.get("passwordResetRequired", False),
                created_at=now,
                updated_at=now,
            ))
    run_db(_query)


def _get_users() -> list[dict]:
    """Read all users from the database."""
    async def _query(session):
        result = await session.execute(select(User))
        return [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email or "",
                "passwordHash": u.password_hash or "",
                "role": u.role or "viewer",
                "status": u.status or "active",
                "passwordResetRequired": u.password_reset_required or False,
            }
            for u in result.scalars().all()
        ]
    return run_db(_query)


def _get_audit_events() -> list[dict]:
    """Read all audit events from the database."""
    async def _query(session):
        result = await session.execute(select(AuditEvent).order_by(AuditEvent.id))
        return [
            {
                "action": e.action,
                "actor_user_id": e.actor_user_id,
                "target": e.target,
                "metadata": e.metadata_json or {},
            }
            for e in result.scalars().all()
        ]
    return run_db(_query)


def _cleanup_db() -> None:
    """Remove all users, audit events, and direct grants (but NOT roles)."""
    async def _query(session):
        await session.execute(delete(DirectGrant))
        await session.execute(delete(AuditEvent))
        await session.execute(delete(User))
    run_db(_query)


@pytest.fixture(autouse=True)
def clean_db(monkeypatch: pytest.MonkeyPatch):
    """Clean up DB before and after each test; seed built-in roles; clear auth env vars."""
    monkeypatch.setenv("JWT_SHARED_SECRET", "a" * 64)
    monkeypatch.delenv("FASTAPI_ENV", raising=False)
    _cleanup_db()
    _seed_builtin_roles()
    yield
    _cleanup_db()


def auth_headers(sub: str, role: str, secret: str = "a" * 64) -> dict[str, str]:
    return {"Authorization": f"Bearer {make_jwt(sub=sub, role=role, secret=secret)}"}


def test_get_users_strips_password_hash_for_authenticated_user(client):
    _seed_users([
        {
            "id": "usr_1",
            "username": "Admin",
            "passwordHash": "scrypt:v1:deadbeef:feedface",
            "role": "owner",
            "status": "active",
        }
    ])

    response = client.get("/settings/api/users")

    assert response.status_code == 200
    users = response.json()["users"]
    assert len(users) == 1
    assert users[0]["id"] == "usr_1"
    assert users[0]["username"] == "Admin"
    assert users[0]["role"] == "owner"
    assert users[0]["status"] == "active"
    assert "passwordHash" not in users[0]


@pytest.mark.parametrize("role", ["security", "viewer"])
def test_get_users_rejects_non_admin(client, monkeypatch, role):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.get(
        "/settings/api/users",
        headers=auth_headers(sub=f"usr_{role}", role=role, secret="b" * 64),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied: manage_users"


def test_post_users_creates_user_hashes_password_and_writes_audit(client):
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        }
    ])

    response = client.post(
        "/settings/api/users",
        headers={"Content-Type": "application/json"},
        json={"username": "NewUser", "email": "new@example.com", "password": "secret-pass!!", "role": "viewer"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["user"]["username"] == "NewUser"
    assert payload["user"]["role"] == "viewer"
    assert payload["user"]["status"] == "active"
    assert "passwordHash" not in payload["user"]

    # Verify the password hash was stored correctly in the DB
    users = _get_users()
    created = next(user for user in users if user["username"] == "NewUser")
    assert created["passwordHash"].startswith("scrypt:v1:")
    assert len(created["passwordHash"].split(":")) == 4
    assert len(created["passwordHash"].split(":")[2]) == 32
    assert len(created["passwordHash"].split(":")[3]) == 128

    # Verify audit event — filter by domain action since middleware also auto-audits
    audit = _get_audit_events()
    user_events = [e for e in audit if e["action"].startswith("user.")]
    assert user_events[-1]["action"] == "user.created"
    assert user_events[-1]["target"] == created["id"]
    assert user_events[-1]["metadata"] == {"username": "NewUser", "email": "new@example.com", "role": "viewer"}


def test_post_users_rejects_case_insensitive_duplicate_usernames(client):
    _seed_users([
        {
            "id": "usr_1",
            "username": "Admin",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        }
    ])

    response = client.post(
        "/settings/api/users",
        headers={"Content-Type": "application/json"},
        json={"username": "admin", "email": "admin@example.com", "password": "secret-pass!!", "role": "viewer"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User already exists."


def test_post_users_rejects_non_admin_create(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.post(
        "/settings/api/users",
        headers={
            "Content-Type": "application/json",
            **auth_headers(sub="usr_viewer", role="viewer", secret="b" * 64),
        },
        json={"username": "NewUser", "email": "new@example.com", "password": "secret-pass!!", "role": "viewer"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied: manage_users"


def test_post_users_rejects_admin_creating_owner(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.post(
        "/settings/api/users",
        headers={
            "Content-Type": "application/json",
            **auth_headers(sub="usr_admin", role="admin", secret="b" * 64),
        },
        json={"username": "NewOwner", "email": "owner@example.com", "password": "secret-pass!!", "role": "owner"},
    )

    assert response.status_code == 403


def test_post_disable_rejects_last_active_owner(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        }
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.post(
        "/settings/api/users/usr_owner/disable",
        headers=auth_headers(sub="usr_owner", role="owner", secret="b" * 64),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot disable the last active owner."


def test_post_enable_sets_user_active_and_audits(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        },
        {
            "id": "usr_user",
            "username": "user",
            "passwordHash": "existing",
            "role": "viewer",
            "status": "disabled",
        },
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.post(
        "/settings/api/users/usr_user/enable",
        headers=auth_headers(sub="usr_admin", role="admin", secret="b" * 64),
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    users = _get_users()
    user = next(entry for entry in users if entry["id"] == "usr_user")
    assert user["status"] == "active"

    audit = _get_audit_events()
    user_events = [e for e in audit if e["action"].startswith("user.")]
    assert user_events[-1]["action"] == "user.enabled"


def test_patch_role_requires_owner_for_owner_target(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        },
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        },
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.patch(
        "/settings/api/users/usr_owner/role",
        headers={**auth_headers(sub="usr_admin", role="admin", secret="b" * 64), "Content-Type": "application/json"},
        json={"role": "viewer"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only owners can update owner users."


def test_patch_role_rejects_demoting_last_active_owner(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        }
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.patch(
        "/settings/api/users/usr_owner/role",
        headers={**auth_headers(sub="usr_actor", role="owner", secret="b" * 64), "Content-Type": "application/json"},
        json={"role": "admin"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot demote the last active owner."


def test_patch_role_rejects_self_role_change(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        }
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.patch(
        "/settings/api/users/usr_admin/role",
        headers={**auth_headers(sub="usr_admin", role="admin", secret="b" * 64), "Content-Type": "application/json"},
        json={"role": "viewer"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "You cannot change your own role."


def test_get_direct_grants_requires_workspace_admin(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.get(
        "/settings/api/direct-grants",
        headers=auth_headers(sub="usr_viewer", role="viewer", secret="b" * 64),
    )
    assert response.status_code == 403


def test_manage_direct_grants_flow(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)
    headers = auth_headers(sub="usr_admin", role="admin", secret="b" * 64)

    # 1. List (empty)
    response = client.get("/settings/api/direct-grants", headers=headers)
    assert response.status_code == 200
    assert response.json()["grants"] == []

    # 2. Add repository grant
    response = client.post(
        "/settings/api/direct-grants",
        headers=headers,
        json={
            "userId": "usr_1",
            "resourceType": "repository",
            "resourceKey": "org/repo"
        }
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True

    # 3. Add container image grant
    response = client.post(
        "/settings/api/direct-grants",
        headers=headers,
        json={
            "userId": "usr_1",
            "resourceType": "containerImage",
            "resourceKey": "ghcr.io/org/image"
        }
    )
    assert response.status_code == 200

    # 4. List again
    response = client.get("/settings/api/direct-grants", headers=headers)
    grants = response.json()["grants"]
    assert len(grants) == 2
    assert any(g["resourceKey"] == "org/repo" and g["source"] == "manual-direct" for g in grants)
    assert any(g["resourceKey"] == "ghcr.io/org/image" and g["source"] == "manual-direct" for g in grants)

    # 5. Remove grant
    response = client.delete(
        "/settings/api/direct-grants/usr_1/repository/org/repo",
        headers=headers
    )
    assert response.status_code == 200

    # 6. Final check
    response = client.get("/settings/api/direct-grants", headers=headers)
    grants = response.json()["grants"]
    assert len(grants) == 1
    assert grants[0]["resourceKey"] == "ghcr.io/org/image"


def test_delete_user_removes_user_and_writes_audit(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        },
        {
            "id": "usr_user",
            "username": "user",
            "passwordHash": "existing",
            "role": "viewer",
            "status": "active",
        },
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.delete(
        "/settings/api/users/usr_user",
        headers=auth_headers(sub="usr_admin", role="admin", secret="b" * 64),
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    users = _get_users()
    assert [user["id"] for user in users] == ["usr_admin"]

    audit = _get_audit_events()
    user_events = [e for e in audit if e["action"].startswith("user.")]
    assert user_events[-1]["action"] == "user.deleted"
    assert user_events[-1]["target"] == "usr_user"
    assert user_events[-1]["metadata"] == {"username": "user", "role": "viewer"}


def test_delete_user_rejects_non_admin(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.delete(
        "/settings/api/users/usr_user",
        headers=auth_headers(sub="usr_viewer", role="viewer", secret="b" * 64),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied: manage_users"


def test_delete_user_rejects_self_delete(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        }
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.delete(
        "/settings/api/users/usr_admin",
        headers=auth_headers(sub="usr_admin", role="admin", secret="b" * 64),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "You cannot delete your own account."


def test_delete_user_rejects_last_active_owner(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        },
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        },
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.delete(
        "/settings/api/users/usr_owner",
        headers=auth_headers(sub="usr_actor", role="owner", secret="b" * 64),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot delete the last active owner."


def test_delete_user_requires_owner_for_owner_target(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_owner_1",
            "username": "owner-one",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        },
        {
            "id": "usr_owner_2",
            "username": "owner-two",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        },
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        },
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.delete(
        "/settings/api/users/usr_owner_2",
        headers=auth_headers(sub="usr_admin", role="admin", secret="b" * 64),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only owners can delete owner users."


def test_delete_user_returns_not_found_for_unknown_user(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.delete(
        "/settings/api/users/usr_missing",
        headers=auth_headers(sub="usr_admin", role="admin", secret="b" * 64),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


def test_get_users_directory_allows_workspace_admin(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_1",
            "username": "Admin",
            "email": "admin@example.com",
            "passwordHash": "hash",
            "role": "owner",
            "status": "active",
        },
        {
            "id": "usr_2",
            "username": "Viewer",
            "email": "viewer@example.com",
            "passwordHash": "hash",
            "role": "viewer",
            "status": "active",
        },
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    response = client.get(
        "/settings/api/users/directory",
        headers=auth_headers(sub="usr_1", role="owner", secret="b" * 64),
    )

    assert response.status_code == 200
    users = response.json()["users"]
    assert len(users) == 2
    # Check fields (order may vary, so find by id)
    admin_user = next(u for u in users if u["id"] == "usr_1")
    assert admin_user == {
        "id": "usr_1",
        "username": "Admin",
        "email": "admin@example.com",
        "role": "owner",
        "status": "active",
    }


def test_get_users_directory_allows_team_admin(client, monkeypatch):
    _seed_users([
        {
            "id": "usr_1",
            "username": "User1",
            "email": "u1@example.com",
            "passwordHash": "hash",
            "role": "viewer",
            "status": "active",
        }
    ])
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    # Mock list_admin_team_ids to return something, meaning the user is a team admin
    monkeypatch.setattr(users_router, "list_admin_team_ids", lambda user_id: ["team_1"])

    response = client.get(
        "/settings/api/users/directory",
        headers=auth_headers(sub="usr_1", role="viewer", secret="b" * 64),
    )

    assert response.status_code == 200
    assert len(response.json()["users"]) == 1


def test_get_users_directory_rejects_regular_user(client, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.setenv("JWT_SHARED_SECRET", "b" * 64)

    # Mock list_admin_team_ids to return empty, meaning the user is NOT a team admin
    monkeypatch.setattr(users_router, "list_admin_team_ids", lambda user_id: [])

    response = client.get(
        "/settings/api/users/directory",
        headers=auth_headers(sub="usr_viewer", role="viewer", secret="b" * 64),
    )

    assert response.status_code == 403


def test_patch_user_role_assigns_role_id(client, monkeypatch):
    from src.settings import roles_store

    secret = "b" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    monkeypatch.setenv("FASTAPI_ENV", "production")

    # Create a custom role
    new_role = roles_store.create_role({
        "name": "Custom Role",
        "slug": "custom_role",
        "description": "",
        "permissions": ["view_dashboards"]
    })

    # Create target users
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        },
        {
            "id": "usr_viewer",
            "username": "viewer",
            "passwordHash": "existing",
            "role": "viewer",
            "status": "active",
        }
    ])

    # Try assigning the roleId
    response = client.patch(
        "/settings/api/users/usr_viewer/role",
        headers=auth_headers(sub="usr_admin", role="owner", secret=secret),
        json={"roleId": new_role["id"]},
    )

    assert response.status_code == 200


def test_password_reset_required_flag_behavior(client):
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
            "passwordResetRequired": False,
        }
    ])

    # 1. New local user should not force a reset before sign-in
    response = client.post(
        "/settings/api/users",
        headers={"Content-Type": "application/json"},
        json={"username": "LocalUser", "email": "local@example.com", "password": "password12345", "role": "viewer"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["passwordResetRequired"] is False

    # 2. Verify in DB
    users = _get_users()
    local_user = next(u for u in users if u["username"] == "LocalUser")
    assert local_user["passwordResetRequired"] is False


def test_create_user_with_role_id_applies_correct_role(client):
    """When roleId is provided, the user should get that role, not the default."""
    _seed_users([{"id": "usr_owner", "username": "owner", "passwordHash": "x", "role": "owner", "status": "active"}])

    response = client.post(
        "/settings/api/users",
        json={
            "username": "ViewerUser",
            "email": "viewer@example.com",
            "password": "strong-pass-123!",
            "role": "viewer",
            "roleId": "role_viewer",
        },
    )

    assert response.status_code == 200
    user = response.json()["user"]
    assert user["role"] == "viewer"
    assert user["roleId"] == "role_viewer"
