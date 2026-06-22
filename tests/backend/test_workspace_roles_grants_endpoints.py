"""Tests for /api/v1/workspace/roles/* and /api/v1/workspace/grants/* endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Asset, Grant, Role, User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_role(role_id: str, *, name: str | None = None, protected: bool = False) -> None:
    async def _insert(session):
        existing = await session.get(Role, role_id)
        if existing is not None:
            return
        session.add(Role(
            id=role_id,
            name=name or role_id,
            description="",
            permissions=["view_findings"],
            protected=protected,
            created_at=datetime.now(timezone.utc),
        ))

    run_db(_insert)


def _get_role(role_id: str) -> Role | None:
    async def _q(session):
        return await session.get(Role, role_id)
    return run_db(_q)


def _seed_user(user_id: str, *, role_id: str = "role_viewer") -> None:
    async def _insert(session):
        existing = await session.get(User, user_id)
        if existing is not None:
            return
        now = datetime.now(timezone.utc)
        session.add(User(
            id=user_id,
            username=f"user-{user_id}",
            email=f"{user_id}@test.example",
            password_hash="",
            role_id=role_id,
            status="active",
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)


def _get_user(user_id: str) -> User | None:
    async def _q(session):
        return await session.get(User, user_id)
    return run_db(_q)


def _seed_asset(external_ref: str | None = None) -> str:
    asset_id = str(uuid4())
    ref = external_ref or f"test/{asset_id}"

    async def _insert(session):
        session.add(Asset(
            id=asset_id,
            type="repo",
            source="manual_upload",
            external_ref=ref,
            display_name=ref,
        ))

    run_db(_insert)
    return asset_id


def _grant_exists(*, subject_type: str, subject_id: str, asset_id: str) -> bool:
    async def _q(session):
        result = await session.execute(
            select(Grant).where(
                Grant.subject_type == subject_type,
                Grant.subject_id == subject_id,
                Grant.asset_id == asset_id,
            )
        )
        return result.scalar_one_or_none() is not None

    return run_db(_q)


def _seed_grant(*, subject_type: str, subject_id: str, asset_id: str) -> None:
    async def _insert(session):
        session.add(Grant(
            subject_type=subject_type,
            subject_id=subject_id,
            asset_id=asset_id,
            source="manual",
            created_at=datetime.now(timezone.utc),
        ))

    run_db(_insert)


# ---------------------------------------------------------------------------
# GET /api/v1/workspace/roles
# ---------------------------------------------------------------------------

def test_get_roles_returns_list():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-list-admin")

    resp = client.get("/api/v1/workspace/roles")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = {r["id"] for r in body["roles"]}
    # Built-in roles must always be present.
    assert {"role_owner", "role_admin", "role_security", "role_viewer"}.issubset(ids)
    owner = next(r for r in body["roles"] if r["id"] == "role_owner")
    assert owner["isSystem"] is True
    assert owner["isLocked"] is True
    assert "permissions" in owner


def test_get_roles_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).get("/api/v1/workspace/roles")
    assert resp.status_code == 401


def test_get_roles_requires_view_roles_permission():
    from conftest import make_authed_client
    # viewer role lacks view_roles
    client = make_authed_client(role="viewer", user_id="wsr-list-viewer")

    resp = client.get("/api/v1/workspace/roles")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/v1/workspace/roles/{role_id}
# ---------------------------------------------------------------------------

def test_get_role_returns_role():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-get-admin")

    resp = client.get("/api/v1/workspace/roles/role_admin")
    assert resp.status_code == 200, resp.text
    role = resp.json()["role"]
    assert role["id"] == "role_admin"
    assert "manage_users" in role["permissions"]


def test_get_role_not_found():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-get-admin-2")

    resp = client.get("/api/v1/workspace/roles/role_does_not_exist")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/roles
# ---------------------------------------------------------------------------

def test_post_roles_creates_role():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-create-admin")

    resp = client.post(
        "/api/v1/workspace/roles",
        json={
            "name": "Auditor",
            "description": "Read-only auditor",
            "permissions": ["view_findings", "view_dashboards"],
        },
    )
    assert resp.status_code == 201, resp.text
    role = resp.json()["role"]
    assert role["name"] == "Auditor"
    assert role["isSystem"] is False
    assert set(role["permissions"]) == {"view_findings", "view_dashboards"}

    saved = _get_role(role["id"])
    assert saved is not None
    assert saved.name == "Auditor"


def test_post_roles_requires_manage_roles_permission():
    from conftest import make_authed_client
    # security role lacks manage_roles
    client = make_authed_client(role="security", user_id="wsr-create-security")

    resp = client.post(
        "/api/v1/workspace/roles",
        json={"name": "X", "description": "", "permissions": []},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# PATCH /api/v1/workspace/roles/{role_id}
# ---------------------------------------------------------------------------

def test_patch_role_updates_fields():
    from conftest import make_authed_client
    role_id = f"role_{uuid4().hex[:12]}"
    _seed_role(role_id, name="Initial")
    client = make_authed_client(role="admin", user_id="wsr-update-admin")

    resp = client.patch(
        f"/api/v1/workspace/roles/{role_id}",
        json={
            "name": "Renamed",
            "description": "New desc",
            "permissions": ["view_dashboards"],
        },
    )
    assert resp.status_code == 200, resp.text
    role = resp.json()["role"]
    assert role["name"] == "Renamed"
    assert role["description"] == "New desc"
    assert role["permissions"] == ["view_dashboards"]

    saved = _get_role(role_id)
    assert saved.name == "Renamed"


def test_patch_role_owner_role_is_protected():
    """The owner role is locked — even admin cannot edit it."""
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-update-admin-owner")

    resp = client.patch(
        "/api/v1/workspace/roles/role_owner",
        json={"name": "NewOwner", "description": "", "permissions": []},
    )
    assert resp.status_code == 403


def test_patch_role_not_found():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-update-admin-404")

    resp = client.patch(
        "/api/v1/workspace/roles/role_missing",
        json={"name": "x", "description": "", "permissions": []},
    )
    assert resp.status_code == 404


def test_patch_role_requires_manage_roles_permission():
    from conftest import make_authed_client
    role_id = f"role_{uuid4().hex[:12]}"
    _seed_role(role_id)
    client = make_authed_client(role="viewer", user_id="wsr-update-viewer")

    resp = client.patch(
        f"/api/v1/workspace/roles/{role_id}",
        json={"name": "x", "description": "", "permissions": []},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /api/v1/workspace/roles/{role_id}
# ---------------------------------------------------------------------------

def test_delete_role_removes_unused_role():
    from conftest import make_authed_client
    role_id = f"role_{uuid4().hex[:12]}"
    _seed_role(role_id)
    client = make_authed_client(role="admin", user_id="wsr-delete-admin")

    resp = client.delete(f"/api/v1/workspace/roles/{role_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}
    assert _get_role(role_id) is None


def test_delete_role_with_replacement_reassigns_users():
    from conftest import make_authed_client
    role_id = f"role_{uuid4().hex[:12]}"
    replacement_id = f"role_{uuid4().hex[:12]}"
    _seed_role(role_id)
    _seed_role(replacement_id)
    user_id = f"wsr-reassign-user-{uuid4().hex[:8]}"
    _seed_user(user_id, role_id=role_id)
    client = make_authed_client(role="admin", user_id="wsr-delete-admin-reassign")

    resp = client.delete(
        f"/api/v1/workspace/roles/{role_id}",
        params={"replacement_role_id": replacement_id},
    )
    assert resp.status_code == 200, resp.text
    assert _get_role(role_id) is None
    assert _get_user(user_id).role_id == replacement_id


def test_delete_role_in_use_without_replacement_rejected():
    from conftest import make_authed_client
    role_id = f"role_{uuid4().hex[:12]}"
    _seed_role(role_id)
    user_id = f"wsr-inuse-user-{uuid4().hex[:8]}"
    _seed_user(user_id, role_id=role_id)
    client = make_authed_client(role="admin", user_id="wsr-delete-admin-inuse")

    resp = client.delete(f"/api/v1/workspace/roles/{role_id}")
    assert resp.status_code == 400
    assert _get_role(role_id) is not None


def test_delete_role_owner_is_protected():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-delete-owner-admin")

    resp = client.delete("/api/v1/workspace/roles/role_owner")
    assert resp.status_code == 403
    assert _get_role("role_owner") is not None


def test_delete_role_not_found():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-delete-404")

    resp = client.delete("/api/v1/workspace/roles/role_missing")
    assert resp.status_code == 404


def test_delete_role_requires_manage_roles_permission():
    from conftest import make_authed_client
    role_id = f"role_{uuid4().hex[:12]}"
    _seed_role(role_id)
    client = make_authed_client(role="viewer", user_id="wsr-delete-viewer")

    resp = client.delete(f"/api/v1/workspace/roles/{role_id}")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/v1/workspace/grants
# ---------------------------------------------------------------------------

def test_get_grants_returns_list_filtered_by_subject():
    from conftest import make_authed_client
    asset_id = _seed_asset()
    subject_id = f"wsr-list-grants-subj-{uuid4().hex[:8]}"
    _seed_grant(subject_type="user", subject_id=subject_id, asset_id=asset_id)
    client = make_authed_client(role="admin", user_id="wsr-list-grants-admin")

    resp = client.get(
        "/api/v1/workspace/grants",
        params={"subject_type": "user", "subject_id": subject_id},
    )
    assert resp.status_code == 200, resp.text
    grants = resp.json()["grants"]
    assert len(grants) == 1
    assert grants[0]["subjectId"] == subject_id
    assert grants[0]["assetId"] == asset_id


def test_get_grants_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).get("/api/v1/workspace/grants")
    assert resp.status_code == 401


def test_get_grants_requires_manage_organisations_permission():
    from conftest import make_authed_client
    # security role lacks manage_organisations
    client = make_authed_client(role="security", user_id="wsr-list-grants-security")

    resp = client.get("/api/v1/workspace/grants")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/grants
# ---------------------------------------------------------------------------

def test_post_grants_creates_grant():
    from conftest import make_authed_client
    asset_id = _seed_asset()
    subject_id = f"wsr-add-grant-subj-{uuid4().hex[:8]}"
    client = make_authed_client(role="admin", user_id="wsr-add-grant-admin")

    resp = client.post(
        "/api/v1/workspace/grants",
        json={"subject_type": "user", "subject_id": subject_id, "asset_id": asset_id},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json() == {"ok": True}
    assert _grant_exists(subject_type="user", subject_id=subject_id, asset_id=asset_id)


def test_post_grants_rejects_invalid_subject_type():
    from conftest import make_authed_client
    asset_id = _seed_asset()
    client = make_authed_client(role="admin", user_id="wsr-add-grant-admin-2")

    resp = client.post(
        "/api/v1/workspace/grants",
        json={"subject_type": "bogus", "subject_id": "x", "asset_id": asset_id},
    )
    assert resp.status_code == 400


def test_post_grants_asset_not_found():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="wsr-add-grant-admin-3")

    resp = client.post(
        "/api/v1/workspace/grants",
        json={
            "subject_type": "user",
            "subject_id": "anyone",
            "asset_id": str(uuid4()),
        },
    )
    assert resp.status_code == 404


def test_post_grants_requires_manage_organisations_permission():
    from conftest import make_authed_client
    asset_id = _seed_asset()
    client = make_authed_client(role="security", user_id="wsr-add-grant-security")

    resp = client.post(
        "/api/v1/workspace/grants",
        json={"subject_type": "user", "subject_id": "x", "asset_id": asset_id},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /api/v1/workspace/grants
# ---------------------------------------------------------------------------

def test_delete_grants_removes_grant():
    from conftest import make_authed_client
    asset_id = _seed_asset()
    subject_id = f"wsr-rm-grant-subj-{uuid4().hex[:8]}"
    _seed_grant(subject_type="user", subject_id=subject_id, asset_id=asset_id)
    assert _grant_exists(subject_type="user", subject_id=subject_id, asset_id=asset_id)
    client = make_authed_client(role="admin", user_id="wsr-rm-grant-admin")

    resp = client.request(
        "DELETE",
        "/api/v1/workspace/grants",
        json={"subject_type": "user", "subject_id": subject_id, "asset_id": asset_id},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}
    assert not _grant_exists(
        subject_type="user", subject_id=subject_id, asset_id=asset_id,
    )


def test_delete_grants_requires_manage_organisations_permission():
    from conftest import make_authed_client
    asset_id = _seed_asset()
    client = make_authed_client(role="security", user_id="wsr-rm-grant-security")

    resp = client.request(
        "DELETE",
        "/api/v1/workspace/grants",
        json={"subject_type": "user", "subject_id": "x", "asset_id": asset_id},
    )
    assert resp.status_code == 403
