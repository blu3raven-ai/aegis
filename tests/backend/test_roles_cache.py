import pytest
from unittest.mock import patch, MagicMock


def test_get_role_caches_result():
    from src.settings.roles_store import get_role, _role_cache
    _role_cache.invalidate()

    mock_result = {
        "id": "role_admin", "name": "Admin", "description": "",
        "permissions": ["view_dashboards", "manage_settings"],
        "isSystem": True, "isLocked": False,
        "createdAt": "2026-01-01T00:00:00.000Z",
        "updatedAt": "2026-01-01T00:00:00.000Z",
    }

    call_count = 0
    def counting_run_db(fn):
        nonlocal call_count
        call_count += 1
        return mock_result

    with patch("src.settings.roles_store.run_db", side_effect=counting_run_db):
        result1 = get_role("role_admin")
        result2 = get_role("role_admin")

    assert call_count == 1
    assert result1["id"] == "role_admin"
    assert result2["id"] == "role_admin"


def test_cache_invalidated_on_update():
    from src.settings.roles_store import _role_cache
    _role_cache.set("role:role_admin", {"id": "role_admin"})
    assert _role_cache.get("role:role_admin") is not None
    _role_cache.invalidate()
    assert _role_cache.get("role:role_admin") is None
