from unittest.mock import patch

from src.settings.team_access import (
    can_manage_team,
    can_review_repository,
    get_effective_team_role_for_repository,
    user_has_repository_access,
    user_has_any_scoped_access,
)
from src.settings.direct_access_store import user_has_direct_repository_access

def test_can_manage_team():
    # Delegates to has_role_permission with manage_organisations
    with patch("src.settings.router.has_role_permission", return_value=True) as mock:
        assert can_manage_team("owner") is True
        mock.assert_called_with("owner", None, "manage_organisations")

    with patch("src.settings.router.has_role_permission", return_value=False) as mock:
        assert can_manage_team("viewer") is False

def test_can_review_repository():
    # manage_access_scope grants access regardless of membership
    with patch("src.settings.router.has_role_permission", side_effect=lambda role, rid, perm: perm == "manage_access_scope"):
        assert can_review_repository("owner", False) is True
        assert can_review_repository("owner", True) is True

    # review_findings + member grants access
    with patch("src.settings.router.has_role_permission", side_effect=lambda role, rid, perm: perm == "review_findings"):
        assert can_review_repository("security", True) is True
        assert can_review_repository("security", False) is False

    # No permissions at all
    with patch("src.settings.router.has_role_permission", return_value=False):
        assert can_review_repository("viewer", True) is False
        assert can_review_repository("viewer", False) is False


def test_repository_access_depends_on_membership_not_team_role():
    teams = [{
        "id": "team_1",
        "name": "AppSec",
        "description": "",
        "members": [{"userId": "usr_1", "source": "manual"}],
        "repositories": [{"org": "octo", "repo": "repo", "source": "manual"}],
        "containerImages": [],
        "createdAt": "2026-04-21T00:00:00.000Z",
        "updatedAt": "2026-04-21T00:00:00.000Z",
    }]

    assert get_effective_team_role_for_repository(teams, "usr_1", "octo", "repo") is None
    assert user_has_repository_access(teams, "usr_1", "octo", "repo") is True

def test_manual_direct_grant_keeps_user_active_without_team_membership():
    grants = [{
        "userId": "usr_1",
        "resourceType": "repository",
        "resourceKey": "octo/repo",
        "source": "manual-direct",
    }]

    assert user_has_direct_repository_access(grants, "usr_1", "octo", "repo") is True

def test_user_has_repository_access_includes_direct_grants():
    teams = [] # No teams
    grants = [{
        "userId": "usr_1",
        "resourceType": "repository",
        "resourceKey": "octo/repo",
        "source": "manual-direct",
    }]
    
    # This should be true if we incorporate direct grants into the check
    assert user_has_repository_access(teams, "usr_1", "octo", "repo", direct_grants=grants) is True

def test_user_has_any_scoped_access_honors_direct_grants():
    teams = [] # No teams
    grants = [{
        "userId": "usr_1",
        "resourceType": "repository",
        "resourceKey": "octo/repo",
        "source": "manual-direct",
    }]
    
    assert user_has_any_scoped_access(teams, "usr_1", direct_grants=grants) is True
    assert user_has_any_scoped_access(teams, "usr_2", direct_grants=grants) is False
