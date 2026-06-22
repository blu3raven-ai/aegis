import pytest

from src.authz.teams import service as store


def _cleanup_all_teams():
    """Delete all teams from the DB so each test starts clean."""
    teams = store.list_teams()
    for t in teams:
        store.delete_team(t["id"])


def _cleanup_all_assets():
    """Wipe the assets table so external_ref upserts in tests stay deterministic."""
    from src.db.helpers import run_db
    from src.db.models import Asset

    async def _query(session):
        from sqlalchemy import delete
        await session.execute(delete(Asset))

    run_db(_query)


def _seed_default_roles():
    """Seed the default roles into the DB if they don't already exist."""
    from src.db.helpers import run_db
    from src.db.models import Role
    from src.db.seed import DEFAULT_ROLES

    async def _query(session):
        for role_data in DEFAULT_ROLES:
            existing = await session.get(Role, role_data["id"])
            if not existing:
                session.add(Role(
                    id=role_data["id"],
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                    protected=role_data.get("protected", False),
                ))

    run_db(_query)


def _make_asset(asset_type: str, external_ref: str, display_name: str) -> str:
    """Insert an Asset directly, returning its id. Lets tests focus on attach/detach
    without going through the manual-upload endpoint."""
    from src.db.helpers import run_db
    from src.assets.service import upsert_asset

    async def _query(session):
        return await upsert_asset(
            session,
            type=asset_type,  # type: ignore[arg-type]
            source="manual_upload",
            external_ref=external_ref,
            display_name=display_name,
        )

    return run_db(_query)


@pytest.fixture(autouse=True)
def clean_state():
    _seed_default_roles()
    _cleanup_all_teams()
    _cleanup_all_assets()
    yield
    _cleanup_all_teams()
    _cleanup_all_assets()


@pytest.fixture()
def client():
    from conftest import make_authed_client
    return make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)


# ── Validation tests ──────────────────────────────────────────────────────────


def test_normalize_repository_accepts_org_repo():
    assert store.normalize_repository(" aegis/api-gateway ") == {"org": "aegis", "repo": "api-gateway"}


@pytest.mark.parametrize("value", ["", "aegis", "aegis/", "/api", "aegis/api/extra"])
def test_normalize_repository_rejects_invalid_values(value):
    with pytest.raises(store.OrganisationValidationError):
        store.normalize_repository(value)


def test_normalize_container_image_accepts_ghcr_path():
    assert store.normalize_container_image(" ghcr.io/example-org/scanner ") == {
        "image": "ghcr.io/example-org/scanner"
    }


@pytest.mark.parametrize("value", ["", "aegis/api", "docker.io/aegis/api", "ghcr.io/aegis"])
def test_normalize_container_image_rejects_invalid_values(value):
    with pytest.raises(store.OrganisationValidationError):
        store.normalize_container_image(value)


# ── DB-backed service tests ──────────────────────────────────────────────────


def test_duplicate_team_names_rejected():
    store.create_team({"name": "Platform", "description": ""}, actor_user_id="usr_owner")

    with pytest.raises(store.OrganisationValidationError, match="Team already exists"):
        store.create_team({"name": "platform", "description": ""}, actor_user_id="usr_owner")


@pytest.mark.parametrize("payload", [{"name": 123, "description": ""}, {"description": ""}])
def test_create_team_rejects_non_string_names(payload):
    with pytest.raises(store.OrganisationValidationError, match="Team name is required"):
        store.create_team(payload, actor_user_id="usr_owner")


def test_create_team_sets_default_source():
    team = store.create_team({"name": "New Team", "description": ""})
    assert team["source"] == "manual"


def test_upsert_member_sets_default_source():
    team = store.create_team({"name": "New Team", "description": ""})
    updated_team = store.upsert_member(team["id"], "user_1")
    assert updated_team["members"][0]["userId"] == "user_1"
    assert updated_team["members"][0]["source"] == "manual"


def test_attach_asset_links_existing_asset_to_team():
    team = store.create_team({"name": "Platform", "description": ""})
    asset_id = _make_asset("repo", "github:aegis/api-gateway", "aegis/api-gateway")

    updated_team = store.attach_asset(team["id"], asset_id)

    assert len(updated_team["assets"]) == 1
    assert updated_team["assets"][0]["assetId"] == asset_id
    assert updated_team["assets"][0]["type"] == "repo"
    assert updated_team["assets"][0]["source"] == "manual"


def test_attach_asset_rejects_unknown_asset():
    team = store.create_team({"name": "Platform", "description": ""})

    with pytest.raises(store.OrganisationNotFoundError, match="Asset not found"):
        store.attach_asset(team["id"], "00000000-0000-0000-0000-000000000000")


def test_attach_asset_rejects_unknown_team():
    asset_id = _make_asset("repo", "github:aegis/api-gateway", "aegis/api-gateway")

    with pytest.raises(store.OrganisationNotFoundError, match="Team not found"):
        store.attach_asset("team_missing", asset_id)


def test_attach_asset_is_idempotent():
    team = store.create_team({"name": "Platform", "description": ""})
    asset_id = _make_asset("repo", "github:aegis/api-gateway", "aegis/api-gateway")

    store.attach_asset(team["id"], asset_id)
    updated_team = store.attach_asset(team["id"], asset_id)

    assert len(updated_team["assets"]) == 1


def test_detach_asset_removes_link():
    team = store.create_team({"name": "Platform", "description": ""})
    asset_id = _make_asset("repo", "github:aegis/api-gateway", "aegis/api-gateway")
    store.attach_asset(team["id"], asset_id)

    updated_team = store.detach_asset(team["id"], asset_id)

    assert updated_team["assets"] == []


def test_detach_asset_is_idempotent_when_not_attached():
    team = store.create_team({"name": "Platform", "description": ""})
    asset_id = _make_asset("repo", "github:aegis/api-gateway", "aegis/api-gateway")

    updated_team = store.detach_asset(team["id"], asset_id)

    assert updated_team["assets"] == []


# ── API endpoint tests ────────────────────────────────────────────────────────


def test_list_workspace_teams_requires_view_settings():
    from conftest import make_authed_client
    c = make_authed_client(role="security", user_id="usr_security", raise_server_exceptions=True)

    response = c.get("/api/v1/workspace/teams")

    assert response.status_code == 200
    assert response.json() == {"teams": []}


def test_create_team_requires_manage_organisations():
    from conftest import make_authed_client
    security_client = make_authed_client(role="security", user_id="usr_security", raise_server_exceptions=True)
    admin_client = make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)

    denied = security_client.post(
        "/api/v1/workspace/teams",
        json={"name": "Platform", "description": ""},
    )
    allowed = admin_client.post(
        "/api/v1/workspace/teams",
        json={"name": "Platform", "description": ""},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["team"]["name"] == "Platform"


def test_attach_and_detach_asset_via_endpoint(client):
    created = client.post(
        "/api/v1/workspace/teams",
        json={"name": "Platform", "description": ""},
    ).json()["team"]
    asset_id = _make_asset("repo", "github:aegis/api-gateway", "aegis/api-gateway")

    attach = client.post(
        f"/api/v1/workspace/teams/{created['id']}/assets",
        json={"assetId": asset_id},
    )
    assert attach.status_code == 200
    assert attach.json()["team"]["assets"][0]["assetId"] == asset_id

    detach = client.delete(
        f"/api/v1/workspace/teams/{created['id']}/assets/{asset_id}",
    )
    assert detach.status_code == 200
    assert detach.json()["team"]["assets"] == []


def test_attach_asset_returns_404_for_unknown_asset(client):
    team = client.post(
        "/api/v1/workspace/teams",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    response = client.post(
        f"/api/v1/workspace/teams/{team['id']}/assets",
        json={"assetId": "00000000-0000-0000-0000-000000000000"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found."


@pytest.mark.parametrize(
    ("method", "path", "json_body"),
    [
        ("patch", "/api/v1/workspace/teams/team_missing", {"name": "Updated", "description": ""}),
        ("delete", "/api/v1/workspace/teams/team_missing", None),
        ("post", "/api/v1/workspace/teams/team_missing/members", {"userId": "usr_jane"}),
        ("post", "/api/v1/workspace/teams/team_missing/assets", {"assetId": "00000000-0000-0000-0000-000000000000"}),
        ("delete", "/api/v1/workspace/teams/team_missing/assets/00000000-0000-0000-0000-000000000000", None),
    ],
)
def test_missing_team_mutations_return_404(client, method, path, json_body):
    response = client.request(method.upper(), path, json=json_body)

    assert response.status_code == 404
    assert response.json()["detail"] == "Team not found."


def test_delete_member_rejects_invalid_user_id(client):
    team = client.post(
        "/api/v1/workspace/teams",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    response = client.delete(
        f"/api/v1/workspace/teams/{team['id']}/members/%20",
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User is required."


def test_create_team_requires_workspace_admin_v2():
    from conftest import make_authed_client
    c = make_authed_client(role="security", user_id="usr_security", raise_server_exceptions=True)

    response = c.post(
        "/api/v1/workspace/teams",
        json={"name": "New Team", "description": ""},
    )
    assert response.status_code == 403


def test_delete_team_requires_workspace_admin():
    from conftest import make_authed_client
    team = store.create_team({"name": "To Delete", "description": ""})
    c = make_authed_client(role="security", user_id="usr_security_del", raise_server_exceptions=True)

    response = c.delete(f"/api/v1/workspace/teams/{team['id']}")
    assert response.status_code == 403


def test_list_workspace_teams_includes_sharing_status():
    from conftest import make_authed_client
    team1 = store.create_team({"name": "Team1", "description": ""})
    store.upsert_member(team1["id"], "usr_jane")

    team2 = store.create_team({"name": "Team2", "description": ""})

    c = make_authed_client(role="security", user_id="usr_jane", raise_server_exceptions=True)
    response = c.get("/api/v1/workspace/teams")

    assert response.status_code == 200
    teams = response.json()["teams"]
    t1 = next(t for t in teams if t["id"] == team1["id"])
    t2 = next(t for t in teams if t["id"] == team2["id"])

    assert t1["isShared"] is True
    assert t2["isShared"] is False
