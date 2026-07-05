"""Tests for POST/PATCH/DELETE /api/v1/workspace/teams and membership endpoints."""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.auth.workspace.teams_router import router as teams_router  # noqa: E402

_MANAGE_PERM = "manage_organisations"


def _allow_all(role, role_id, permission):
    return True


def _deny_all(role, role_id, permission):
    return False


# Minimal fake team dict returned by the underlying service functions.
_FAKE_TEAM_DICT: dict[str, Any] = {
    "id": "team_abc123",
    "name": "Alpha Team",
    "description": "A test team",
    "source": "manual",
    "members": [{"userId": "user-1", "source": "manual"}],
    "assets": [],
    "createdAt": "2026-01-01T00:00:00.000Z",
    "updatedAt": "2026-01-01T00:00:00.000Z",
}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(teams_router)

    @app.middleware("http")
    async def inject_state(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.tier = "enterprise"
        return await call_next(request)

    return app


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/teams — create
# ---------------------------------------------------------------------------

def test_create_team_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_deny_all):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "New Team"})
        assert resp.status_code == 403


def test_create_team_happy_path():
    from src.auth.workspace.service import WorkspaceTeam, WorkspaceTeamMember

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="Alpha Team",
        description="A test team",
        source="manual",
        members=[WorkspaceTeamMember(user_id="user-1", source="manual")],
        assets=[],
        is_shared=False,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-01-01T00:00:00.000Z",
    )

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.create_team", return_value=fake_team):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "Alpha Team", "description": "A test team"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["id"] == "team_abc123"
        assert body["name"] == "Alpha Team"
        assert body["members"][0]["userId"] == "user-1"
        assert "isShared" in body


def test_create_team_validation_empty_name():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "  "})
        assert resp.status_code == 422


def test_create_team_validation_missing_name():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={})
        assert resp.status_code == 422


def test_create_team_404_when_service_raises_not_found():
    from graphql import GraphQLError

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.create_team", side_effect=GraphQLError("not found", extensions={"code": "NOT_FOUND"})):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "X"})
        assert resp.status_code == 404


def test_create_team_400_when_service_raises_validation_error():
    from graphql import GraphQLError

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.create_team", side_effect=GraphQLError("Team already exists.", extensions={"code": "VALIDATION_ERROR"})):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "Duplicate"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# PATCH /api/v1/workspace/teams/{team_id} — update
# ---------------------------------------------------------------------------

def test_update_team_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_deny_all):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/team_abc123", json={"name": "Renamed"})
        assert resp.status_code == 403


def test_update_team_happy_path():
    from src.auth.workspace.service import WorkspaceTeam

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="Renamed",
        description="Updated",
        source="manual",
        members=[],
        assets=[],
        is_shared=False,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-06-01T00:00:00.000Z",
    )

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.update_team", return_value=fake_team):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/team_abc123", json={"name": "Renamed", "description": "Updated"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Renamed"


def test_update_team_404_for_nonexistent_team():
    from graphql import GraphQLError

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.update_team", side_effect=GraphQLError("team not found", extensions={"code": "NOT_FOUND"})), \
         patch("src.auth.workspace.teams_router.list_teams", return_value=[{"id": "team_missing", "name": "Old Name", "description": "Old desc"}]):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/team_missing", json={"name": "X"})
        assert resp.status_code == 404


def test_update_team_validation_empty_name():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/team_abc123", json={"name": ""})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# DELETE /api/v1/workspace/teams/{team_id} — delete
# ---------------------------------------------------------------------------

def test_delete_team_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_deny_all):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/workspace/teams/team_abc123")
        assert resp.status_code == 403


def test_delete_team_happy_path():
    from src.auth.workspace.service import WorkspaceMutationResult

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.delete_team", return_value=WorkspaceMutationResult(ok=True)):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/workspace/teams/team_abc123")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


def test_delete_team_404_for_nonexistent_team():
    from graphql import GraphQLError

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.delete_team", side_effect=GraphQLError("team not found", extensions={"code": "NOT_FOUND"})):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/workspace/teams/team_missing")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/workspace/teams/{team_id}/members — add member
# ---------------------------------------------------------------------------

def test_add_member_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_deny_all):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams/team_abc123/members", json={"userId": "user-2"})
        assert resp.status_code == 403


def test_add_member_happy_path():
    from src.auth.workspace.service import WorkspaceTeam, WorkspaceTeamMember

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="Alpha Team",
        description="",
        source="manual",
        members=[
            WorkspaceTeamMember(user_id="user-1", source="manual"),
            WorkspaceTeamMember(user_id="user-2", source="manual"),
        ],
        assets=[],
        is_shared=False,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-06-01T00:00:00.000Z",
    )

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.add_team_member", return_value=fake_team):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams/team_abc123/members", json={"userId": "user-2"})
        assert resp.status_code == 201
        body = resp.json()
        member_ids = [m["userId"] for m in body["members"]]
        assert "user-2" in member_ids


def test_add_member_404_for_nonexistent_team():
    from graphql import GraphQLError

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.add_team_member", side_effect=GraphQLError("team not found", extensions={"code": "NOT_FOUND"})):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams/team_missing/members", json={"userId": "user-2"})
        assert resp.status_code == 404


def test_add_member_validation_empty_user_id():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams/team_abc123/members", json={"userId": ""})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# DELETE /api/v1/workspace/teams/{team_id}/members/{user_id} — remove member
# ---------------------------------------------------------------------------

def test_remove_member_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_deny_all):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/workspace/teams/team_abc123/members/user-1")
        assert resp.status_code == 403


def test_remove_member_happy_path():
    from src.auth.workspace.service import WorkspaceTeam

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="Alpha Team",
        description="",
        source="manual",
        members=[],
        assets=[],
        is_shared=False,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-06-01T00:00:00.000Z",
    )

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.remove_team_member", return_value=fake_team):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/workspace/teams/team_abc123/members/user-1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["members"] == []


def test_remove_member_404_for_nonexistent_user():
    from graphql import GraphQLError

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.remove_team_member", side_effect=GraphQLError("user not found", extensions={"code": "NOT_FOUND"})):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/workspace/teams/team_abc123/members/user-missing")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Response shape — camelCase field names
# ---------------------------------------------------------------------------

def test_create_team_returns_403_when_feature_unavailable():
    from fastapi import HTTPException as _HTTPException

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch(
             "src.auth.workspace.teams_router.create_team",
             side_effect=_HTTPException(status_code=403, detail="feature unavailable: teams"),
         ):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "Locked Team"})
        assert resp.status_code == 403
        body = resp.json()
        assert "feature unavailable" in body.get("detail", "").lower()


def test_response_shape_is_camel_case():
    from src.auth.workspace.service import WorkspaceTeam, WorkspaceTeamMember, WorkspaceTeamAsset

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="Test",
        description="desc",
        source="manual",
        members=[WorkspaceTeamMember(user_id="u1", source="manual")],
        assets=[WorkspaceTeamAsset(asset_id="a1", type="repo", display_name="repo/name", external_ref="ref", source="manual")],
        is_shared=True,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-01-01T00:00:00.000Z",
    )

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.create_team", return_value=fake_team):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/workspace/teams", json={"name": "Test"})
        assert resp.status_code == 201
        body = resp.json()
        # Top-level camelCase
        assert "isShared" in body
        assert "createdAt" in body
        assert "updatedAt" in body
        # Members
        assert body["members"][0]["userId"] == "u1"
        # Assets
        assert body["assets"][0]["assetId"] == "a1"
        assert body["assets"][0]["displayName"] == "repo/name"
        assert body["assets"][0]["externalRef"] == "ref"


# ---------------------------------------------------------------------------
# PATCH partial update — omitting description preserves the existing value
# ---------------------------------------------------------------------------

def test_patch_name_only_preserves_description():
    """PATCH with only {name} must not reset description to ''."""
    from src.auth.workspace.service import WorkspaceTeam, TeamInput

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="New Name",
        description="Original description",
        source="manual",
        members=[],
        assets=[],
        is_shared=False,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-06-17T00:00:00.000Z",
    )

    captured: list[TeamInput] = []

    def _fake_update_team(*, team_id: str, input: TeamInput, info_context: dict) -> WorkspaceTeam:
        captured.append(input)
        return fake_team

    existing_teams = [{"id": "team_abc123", "name": "Old Name", "description": "Original description"}]

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.update_team", side_effect=_fake_update_team), \
         patch("src.auth.workspace.teams_router.list_teams", return_value=existing_teams):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/team_abc123", json={"name": "New Name"})
        assert resp.status_code == 200

    assert len(captured) == 1
    # The resolver must have received the preserved description, not ""
    assert captured[0].description == "Original description"
    assert captured[0].name == "New Name"


def test_patch_description_only_preserves_name():
    """PATCH with only {description} must not wipe the name."""
    from src.auth.workspace.service import WorkspaceTeam, TeamInput

    fake_team = WorkspaceTeam(
        id="team_abc123",
        name="Stable Name",
        description="New desc",
        source="manual",
        members=[],
        assets=[],
        is_shared=False,
        created_at="2026-01-01T00:00:00.000Z",
        updated_at="2026-06-17T00:00:00.000Z",
    )

    captured: list[TeamInput] = []

    def _fake_update_team(*, team_id: str, input: TeamInput, info_context: dict) -> WorkspaceTeam:
        captured.append(input)
        return fake_team

    existing_teams = [{"id": "team_abc123", "name": "Stable Name", "description": "Old desc"}]

    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.update_team", side_effect=_fake_update_team), \
         patch("src.auth.workspace.teams_router.list_teams", return_value=existing_teams):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/team_abc123", json={"description": "New desc"})
        assert resp.status_code == 200

    assert len(captured) == 1
    assert captured[0].name == "Stable Name"
    assert captured[0].description == "New desc"


def test_patch_unknown_team_returns_404_without_calling_update():
    """If the team_id isn't in list_teams, return 404 before calling the resolver."""
    with patch("src.authz.enforcement.dependencies.has_role_permission", side_effect=_allow_all), \
         patch("src.auth.workspace.teams_router.list_teams", return_value=[]):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/workspace/teams/nonexistent", json={"name": "X"})
        assert resp.status_code == 404
