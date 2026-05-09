import pytest
from unittest.mock import patch


def _make_request(role: str, role_id: str):
    class FakeState:
        user_role = role
        user_role_id = role_id
    class FakeRequest:
        state = FakeState()
    return FakeRequest()


def test_owner_passes_via_role_lookup_not_bypass():
    from src.settings.router import require_permission

    request = _make_request("owner", "role_owner")
    mock_role = {
        "id": "role_owner",
        "permissions": [
            "view_dashboards", "view_findings", "review_findings",
            "export_findings", "run_scans", "cancel_scans",
            "view_scan_history", "view_reports", "export_reports",
            "view_settings", "manage_settings", "view_users",
            "manage_users", "view_roles", "manage_roles",
            "view_access_scope", "manage_access_scope",
            "view_sources", "manage_sources", "view_audit",
            "manage_organisations", "refresh_dashboard",
        ],
    }
    with patch("src.settings.roles_store.get_role", return_value=mock_role):
        require_permission(request, "manage_settings")
        require_permission(request, "manage_sources")
        require_permission(request, "view_dashboards")


def test_viewer_denied_admin_permission():
    from src.settings.router import require_permission

    request = _make_request("viewer", "role_viewer")
    mock_role = {"id": "role_viewer", "permissions": ["view_dashboards", "view_findings"]}

    with patch("src.settings.roles_store.get_role", return_value=mock_role):
        with pytest.raises(Exception, match="Permission denied"):
            require_permission(request, "manage_settings")


def test_has_permission_returns_bool():
    from src.settings.router import has_permission

    request = _make_request("viewer", "role_viewer")
    mock_role = {"id": "role_viewer", "permissions": ["view_dashboards", "view_findings"]}

    with patch("src.settings.roles_store.get_role", return_value=mock_role):
        assert has_permission(request, "view_dashboards") is True
        assert has_permission(request, "manage_settings") is False


def test_has_permission_owner_returns_true():
    from src.settings.router import has_permission

    request = _make_request("owner", "role_owner")
    mock_role = {
        "id": "role_owner",
        "permissions": [
            "view_dashboards", "manage_settings", "manage_sources",
            "view_findings", "review_findings", "export_findings",
            "run_scans", "cancel_scans", "view_scan_history",
            "view_reports", "export_reports", "view_users",
            "manage_users", "view_roles", "manage_roles",
            "view_access_scope", "manage_access_scope",
            "view_sources", "view_audit", "manage_organisations",
            "refresh_dashboard",
        ],
    }

    with patch("src.settings.roles_store.get_role", return_value=mock_role):
        assert has_permission(request, "manage_settings") is True
        assert has_permission(request, "view_dashboards") is True


def test_has_role_permission_without_request():
    from src.settings.router import has_role_permission

    mock_admin = {"id": "role_admin", "permissions": ["manage_sources", "view_dashboards"]}
    mock_viewer = {"id": "role_viewer", "permissions": ["view_dashboards"]}

    with patch("src.settings.roles_store.get_role_by_slug") as mock_get:
        mock_get.return_value = mock_admin
        assert has_role_permission("admin", None, "manage_sources") is True

        mock_get.return_value = mock_viewer
        assert has_role_permission("viewer", None, "manage_sources") is False

    assert has_role_permission(None, None, "manage_sources") is False
