from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import src.settings.users_router as users_router
from src.db.helpers import run_db
from src.db.models import AuditEvent, DirectGrant, Role, User
from src.db.seed import DEFAULT_ROLES
from src.main import app
from sqlalchemy import delete, select


@pytest.fixture
def client():
    from conftest import make_authed_client
    return make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)


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
def clean_db():
    """Clean up DB before and after each test; seed built-in roles."""
    _cleanup_db()
    _seed_builtin_roles()
    yield
    _cleanup_db()


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
    # The session user (usr_admin) is also present; find the seeded one by id
    seeded = next(u for u in users if u["id"] == "usr_1")
    assert seeded["username"] == "Admin"
    assert seeded["role"] == "owner"
    assert seeded["status"] == "active"
    assert "passwordHash" not in seeded


@pytest.mark.parametrize("role", ["security", "viewer"])
def test_get_users_rejects_non_admin(role):
    from conftest import make_authed_client
    c = make_authed_client(role=role, user_id=f"usr_{role}", raise_server_exceptions=True)

    response = c.get("/settings/api/users")

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
        json={"username": "admin", "email": "admin@example.com", "password": "secret-pass!!", "role": "viewer"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User already exists."


def test_post_users_rejects_non_admin_create():
    from conftest import make_authed_client
    c = make_authed_client(role="viewer", user_id="usr_viewer", raise_server_exceptions=True)

    response = c.post(
        "/settings/api/users",
        json={"username": "NewUser", "email": "new@example.com", "password": "secret-pass!!", "role": "viewer"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied: manage_users"


def test_post_users_rejects_admin_creating_owner(client):
    response = client.post(
        "/settings/api/users",
        json={"username": "NewOwner", "email": "owner@example.com", "password": "secret-pass!!", "role": "owner"},
    )

    assert response.status_code == 403


def test_post_disable_rejects_last_active_owner():
    from conftest import make_authed_client
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        }
    ])
    c = make_authed_client(role="owner", user_id="usr_owner", raise_server_exceptions=True)

    response = c.post("/settings/api/users/usr_owner/disable")

    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot disable the last active owner."


def test_post_enable_sets_user_active_and_audits(client):
    # usr_admin is already created by the client fixture (make_authed_client)
    _seed_users([
        {
            "id": "usr_user",
            "username": "user",
            "passwordHash": "existing",
            "role": "viewer",
            "status": "disabled",
        },
    ])

    response = client.post("/settings/api/users/usr_user/enable")

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    users = _get_users()
    user = next(entry for entry in users if entry["id"] == "usr_user")
    assert user["status"] == "active"

    audit = _get_audit_events()
    user_events = [e for e in audit if e["action"].startswith("user.")]
    assert user_events[-1]["action"] == "user.enabled"


def test_patch_role_requires_owner_for_owner_target():
    from conftest import make_authed_client
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
    c = make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)

    response = c.patch(
        "/settings/api/users/usr_owner/role",
        json={"role": "viewer"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only owners can update owner users."


def test_patch_role_owner_target_requires_owner_actor():
    """An admin-role actor cannot demote an owner user — only owners can."""
    from conftest import make_authed_client
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        }
    ])
    # Actor has admin role (not owner) — should be denied before reaching last-owner check
    c = make_authed_client(role="admin", user_id="usr_actor_admin", raise_server_exceptions=True)

    response = c.patch(
        "/settings/api/users/usr_owner/role",
        json={"role": "admin"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only owners can update owner users."


def test_patch_role_rejects_self_role_change():
    from conftest import make_authed_client
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        }
    ])
    # Actor user_id matches target user_id — should be rejected
    c = make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)

    response = c.patch(
        "/settings/api/users/usr_admin/role",
        json={"role": "viewer"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "You cannot change your own role."


def test_get_direct_grants_requires_workspace_admin():
    from conftest import make_authed_client
    c = make_authed_client(role="viewer", user_id="usr_viewer", raise_server_exceptions=True)

    response = c.get("/settings/api/direct-grants")
    assert response.status_code == 403


def test_manage_direct_grants_flow(client):
    # 1. List (empty)
    response = client.get("/settings/api/direct-grants")
    assert response.status_code == 200
    assert response.json()["grants"] == []

    # 2. Add repository grant
    response = client.post(
        "/settings/api/direct-grants",
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
        json={
            "userId": "usr_1",
            "resourceType": "containerImage",
            "resourceKey": "ghcr.io/org/image"
        }
    )
    assert response.status_code == 200

    # 4. List again
    response = client.get("/settings/api/direct-grants")
    grants = response.json()["grants"]
    assert len(grants) == 2
    assert any(g["resourceKey"] == "org/repo" and g["source"] == "manual-direct" for g in grants)
    assert any(g["resourceKey"] == "ghcr.io/org/image" and g["source"] == "manual-direct" for g in grants)

    # 5. Remove grant
    response = client.delete("/settings/api/direct-grants/usr_1/repository/org/repo")
    assert response.status_code == 200

    # 6. Final check
    response = client.get("/settings/api/direct-grants")
    grants = response.json()["grants"]
    assert len(grants) == 1
    assert grants[0]["resourceKey"] == "ghcr.io/org/image"


def test_delete_user_removes_user_and_writes_audit(client):
    # usr_admin already created by client fixture; only seed the target user
    _seed_users([
        {
            "id": "usr_user",
            "username": "user",
            "passwordHash": "existing",
            "role": "viewer",
            "status": "active",
        },
    ])

    response = client.delete("/settings/api/users/usr_user")

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    users = _get_users()
    user_ids = [user["id"] for user in users]
    assert "usr_user" not in user_ids
    assert "usr_admin" in user_ids

    audit = _get_audit_events()
    user_events = [e for e in audit if e["action"].startswith("user.")]
    assert user_events[-1]["action"] == "user.deleted"
    assert user_events[-1]["target"] == "usr_user"
    assert user_events[-1]["metadata"] == {"username": "user", "role": "viewer"}


def test_delete_user_rejects_non_admin():
    from conftest import make_authed_client
    c = make_authed_client(role="viewer", user_id="usr_viewer", raise_server_exceptions=True)

    response = c.delete("/settings/api/users/usr_user")

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied: manage_users"


def test_delete_user_rejects_self_delete():
    from conftest import make_authed_client
    _seed_users([
        {
            "id": "usr_admin",
            "username": "admin",
            "passwordHash": "existing",
            "role": "admin",
            "status": "active",
        }
    ])
    # Actor user_id matches target — should be rejected
    c = make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)

    response = c.delete("/settings/api/users/usr_admin")

    assert response.status_code == 400
    assert response.json()["detail"] == "You cannot delete your own account."


def test_delete_user_owner_target_requires_owner_actor():
    """An admin-role actor cannot delete an owner user — only owners can."""
    from conftest import make_authed_client
    _seed_users([
        {
            "id": "usr_owner",
            "username": "owner",
            "passwordHash": "existing",
            "role": "owner",
            "status": "active",
        },
    ])
    # Actor has admin role — should get 403 before reaching the last-owner check
    c = make_authed_client(role="admin", user_id="usr_actor_admin", raise_server_exceptions=True)

    response = c.delete("/settings/api/users/usr_owner")

    assert response.status_code == 403
    assert response.json()["detail"] == "Only owners can delete owner users."


def test_delete_user_requires_owner_for_owner_target():
    from conftest import make_authed_client
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
    c = make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)

    response = c.delete("/settings/api/users/usr_owner_2")

    assert response.status_code == 403
    assert response.json()["detail"] == "Only owners can delete owner users."


def test_delete_user_returns_not_found_for_unknown_user(client):
    response = client.delete("/settings/api/users/usr_missing")

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


def test_get_users_directory_allows_workspace_admin():
    from conftest import make_authed_client
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
    c = make_authed_client(role="owner", user_id="usr_1", raise_server_exceptions=True)

    response = c.get("/settings/api/users/directory")

    assert response.status_code == 200
    users = response.json()["users"]
    assert len(users) == 2
    admin_user = next(u for u in users if u["id"] == "usr_1")
    assert admin_user == {
        "id": "usr_1",
        "username": "Admin",
        "email": "admin@example.com",
        "role": "owner",
        "status": "active",
    }


def test_get_users_directory_allows_team_admin(monkeypatch):
    from conftest import make_authed_client
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
    monkeypatch.setattr(users_router, "list_admin_team_ids", lambda user_id: ["team_1"])
    c = make_authed_client(role="viewer", user_id="usr_1", raise_server_exceptions=True)

    response = c.get("/settings/api/users/directory")

    assert response.status_code == 200
    assert len(response.json()["users"]) == 1


def test_get_users_directory_rejects_regular_user(monkeypatch):
    from conftest import make_authed_client
    monkeypatch.setattr(users_router, "list_admin_team_ids", lambda user_id: [])
    c = make_authed_client(role="viewer", user_id="usr_viewer", raise_server_exceptions=True)

    response = c.get("/settings/api/users/directory")

    assert response.status_code == 403


def test_patch_user_role_assigns_role_id():
    from conftest import make_authed_client
    from src.settings import roles_store

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

    c = make_authed_client(role="owner", user_id="usr_admin", raise_server_exceptions=True)
    response = c.patch(
        "/settings/api/users/usr_viewer/role",
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
