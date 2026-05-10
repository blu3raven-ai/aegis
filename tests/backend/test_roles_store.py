import pytest
import src.settings.roles_store as roles_store


def _seed_default_roles():
    """Seed the default roles into the test database using run_db."""
    from src.db.seed import DEFAULT_ROLES
    from src.db.helpers import run_db
    from src.db.models import Role
    from datetime import datetime, timezone

    for role_data in DEFAULT_ROLES:
        def _make_inserter(rd):
            async def _insert(session):
                existing = await session.get(Role, rd["id"])
                if not existing:
                    session.add(Role(
                        id=rd["id"],
                        name=rd["name"],
                        description=rd["description"],
                        permissions=rd["permissions"],
                        protected=rd["protected"],
                        created_at=datetime.now(timezone.utc),
                    ))
            return _insert
        run_db(_make_inserter(role_data))


@pytest.fixture(autouse=True)
def ensure_seeded_roles():
    """Ensure default roles exist in the DB before each test."""
    _seed_default_roles()


def test_seed_roles_creates_locked_owner_and_default_roles():
    roles = roles_store.list_roles()
    owner = next(role for role in roles if role["id"] == "role_owner")
    admin = next(role for role in roles if role["id"] == "role_admin")

    assert owner["isSystem"] is True
    assert owner["isLocked"] is True
    assert "view_dashboards" in owner["permissions"]

    assert admin["isSystem"] is True
    assert admin["isLocked"] is False
    assert "manage_users" in admin["permissions"]


def test_cannot_update_or_delete_owner():
    with pytest.raises(ValueError, match="Owner role is protected"):
        roles_store.update_role("role_owner", {"name": "New Owner", "description": "", "permissions": []})

    with pytest.raises(ValueError, match="Owner role is protected"):
        roles_store.delete_role("role_owner")


def test_create_custom_role():
    new_role = roles_store.create_role({
        "name": "Custom Role",
        "description": "Test description",
        "permissions": ["view_dashboards"]
    })

    assert new_role["name"] == "Custom Role"
    assert new_role["isSystem"] is False
    assert new_role["id"].startswith("role_")

    roles = roles_store.list_roles()
    assert any(r["id"] == new_role["id"] for r in roles)


def test_update_custom_role():
    role = roles_store.create_role({
        "name": "Initial",
        "description": "",
        "permissions": []
    })

    updated = roles_store.update_role(role["id"], {
        "name": "Updated",
        "description": "desc",
        "permissions": ["view_audit"]
    })

    assert updated["name"] == "Updated"
    assert "view_audit" in updated["permissions"]


def test_delete_custom_role():
    role = roles_store.create_role({
        "name": "To Delete",
        "description": "",
        "permissions": []
    })

    roles_store.delete_role(role["id"])

    with pytest.raises(ValueError, match="Role not found"):
        roles_store.get_role(role["id"])
