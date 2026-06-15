import pytest

from src.settings import organisations_store as store


def _cleanup_all_teams():
    """Delete all teams from the DB so each test starts clean."""
    teams = store.list_teams()
    for t in teams:
        store.delete_team(t["id"])


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


@pytest.fixture(autouse=True)
def clean_teams_table():
    """Ensure a clean teams table and seeded roles for every test."""
    _seed_default_roles()
    _cleanup_all_teams()
    yield
    _cleanup_all_teams()


@pytest.fixture()
def client():
    from conftest import make_authed_client
    return make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)


def valid_team(**overrides):
    team = {
        "id": "team_platform",
        "name": "Platform",
        "description": "",
        "members": [{"userId": "usr_jane"}],
        "repositories": [{"org": "aegis", "repo": "api-gateway"}],
        "containerImages": [{"image": "ghcr.io/u9u-p/security/secret-scanner"}],
        "createdAt": "2026-04-20T00:00:00Z",
        "updatedAt": "2026-04-20T00:00:00Z",
    }
    team.update(overrides)
    return team


# ── Pure validation tests (no DB needed) ──────────────────────────────────────


def test_normalize_repository_accepts_org_repo():
    assert store.normalize_repository(" AEGIS/API-Gateway ") == {"org": "AEGIS", "repo": "API-Gateway"}


@pytest.mark.parametrize("value", ["", "aegis", "aegis/", "/api", "aegis/api/extra"])
def test_normalize_repository_rejects_invalid_values(value):
    with pytest.raises(store.OrganisationValidationError):
        store.normalize_repository(value)


def test_normalize_container_image_accepts_ghcr_path():
    assert store.normalize_container_image(" ghcr.io/u9u-p/security/secret-scanner ") == {
        "image": "ghcr.io/u9u-p/security/secret-scanner"
    }


@pytest.mark.parametrize("value", ["", "aegis/api", "docker.io/aegis/api", "ghcr.io/aegis"])
def test_normalize_container_image_rejects_invalid_values(value):
    with pytest.raises(store.OrganisationValidationError):
        store.normalize_container_image(value)


# ── DB-backed store tests ─────────────────────────────────────────────────────


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


def test_add_repository_sets_default_source():
    team = store.create_team({"name": "New Team", "description": ""})
    updated_team = store.add_repository(team["id"], "org/repo")
    assert updated_team["repositories"][0]["repo"] == "repo"
    assert updated_team["repositories"][0]["source"] == "manual"


def test_membership_grants_access_to_shared_repository():
    team = store.create_team({"name": "Platform", "description": ""})
    store.upsert_member(team["id"], "usr_jane")
    store.add_repository(team["id"], "aegis/api-gateway")

    from src.settings.team_access import user_has_repository_access
    teams = store.list_teams()
    assert user_has_repository_access(teams, "usr_jane", "aegis", "api-gateway") is True


def test_repository_lookup_is_case_insensitive():
    team = store.create_team({"name": "Platform", "description": ""})
    store.upsert_member(team["id"], "usr_jane")
    store.add_repository(team["id"], "AEGIS/API-Gateway")

    from src.settings.team_access import user_has_repository_access
    teams = store.list_teams()
    assert user_has_repository_access(teams, "usr_jane", "aegis", "api-gateway") is True


def test_unrelated_team_membership_does_not_grant_repository_access():
    team = store.create_team({"name": "Platform", "description": ""})
    store.upsert_member(team["id"], "usr_jane")
    store.add_repository(team["id"], "aegis/api-gateway")

    from src.settings.team_access import user_has_repository_access
    teams = store.list_teams()
    assert user_has_repository_access(teams, "usr_jane", "aegis", "mobile-app") is False




# ── API endpoint tests ────────────────────────────────────────────────────────


def test_list_organisations_requires_view_settings():
    from conftest import make_authed_client
    c = make_authed_client(role="security", user_id="usr_security", raise_server_exceptions=True)

    response = c.get("/api/v1/settings/organisations")

    assert response.status_code == 200
    assert response.json() == {"teams": []}


def test_create_team_requires_manage_organisations():
    from conftest import make_authed_client
    security_client = make_authed_client(role="security", user_id="usr_security", raise_server_exceptions=True)
    admin_client = make_authed_client(role="admin", user_id="usr_admin", raise_server_exceptions=True)

    denied = security_client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    )
    allowed = admin_client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["team"]["name"] == "Platform"


def test_add_member_and_repository_to_team(client):
    created = client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    member_response = client.post(
        f"/api/v1/settings/organisations/{created['id']}/members",
        json={"userId": "usr_jane"},
    )
    repo_response = client.post(
        f"/api/v1/settings/organisations/{created['id']}/repositories",
        json={"repository": "aegis/api-gateway"},
    )

    assert member_response.status_code == 200
    assert repo_response.status_code == 200
    assert member_response.json()["team"]["members"] == [{"userId": "usr_jane", "source": "manual"}]
    assert repo_response.json()["team"]["repositories"] == [{"org": "aegis", "repo": "api-gateway", "source": "manual"}]


@pytest.mark.parametrize(
    ("method", "path", "json_body", "params"),
    [
        ("patch", "/api/v1/settings/organisations/team_missing", {"name": "Updated", "description": ""}, None),
        ("delete", "/api/v1/settings/organisations/team_missing", None, None),
        ("post", "/api/v1/settings/organisations/team_missing/members", {"userId": "usr_jane"}, None),
        ("delete", "/api/v1/settings/organisations/team_missing/repositories/aegis/api-gateway", None, None),
        ("delete", "/api/v1/settings/organisations/team_missing/container-images", None, {"image": "ghcr.io/u9u-p/security/secret-scanner"}),
    ],
)
def test_missing_team_mutations_return_404(client, method, path, json_body, params):
    response = client.request(
        method.upper(),
        path,
        json=json_body,
        params=params,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Team not found."


def test_delete_repository_rejects_invalid_repository_input(client):
    team = client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    response = client.delete(
        f"/api/v1/settings/organisations/{team['id']}/repositories/aegis/api%20gateway",
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Repository must use org/repo format."


def test_delete_container_image_rejects_invalid_image_input(client):
    team = client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    response = client.delete(
        f"/api/v1/settings/organisations/{team['id']}/container-images",
        params={"image": "docker.io/aegis/api"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Container image must use ghcr.io/org/image format."


def test_delete_member_rejects_invalid_user_id(client):
    team = client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    response = client.delete(
        f"/api/v1/settings/organisations/{team['id']}/members/%20",
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User is required."


def test_delete_member_returns_500_on_store_error(client, monkeypatch):
    team = client.post(
        "/api/v1/settings/organisations",
        json={"name": "Platform", "description": ""},
    ).json()["team"]

    def fail_remove(*_args, **_kwargs):
        raise store.OrganisationStoreError("boom")

    monkeypatch.setattr("src.settings.organisations_router.remove_member", fail_remove)

    response = client.delete(
        f"/api/v1/settings/organisations/{team['id']}/members/usr_jane",
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "boom"


def test_repository_search_filters_results(client, monkeypatch):
    monkeypatch.setattr("src.settings.organisations_router.read_app_config", lambda: {"github": {"orgs": [{"name": "aegis"}]}})

    async def fake_fetch_repos(org, token):
        return [
            {"name": "api-gateway", "full_name": "aegis/api-gateway"},
            {"name": "mobile-app", "full_name": "aegis/mobile-app"},
        ]

    monkeypatch.setattr("src.settings.organisations_router.get_github_token_for_org", lambda org: "token")
    monkeypatch.setattr("src.settings.organisations_router.fetch_org_repos", fake_fetch_repos)

    response = client.get("/api/v1/settings/resources/repositories?org=aegis&q=api")

    assert response.status_code == 200
    assert response.json() == {"repositories": [{"org": "aegis", "repo": "api-gateway", "fullName": "aegis/api-gateway"}]}


def test_container_image_search_fails_softly(client, monkeypatch):
    monkeypatch.setattr("src.settings.organisations_router.read_app_config", lambda: {"github": {"orgs": [{"name": "aegis"}]}})
    monkeypatch.setattr("src.settings.organisations_router.get_github_token_for_org", lambda org: "")

    response = client.get("/api/v1/settings/resources/container-images?org=aegis&q=api")

    assert response.status_code == 200
    assert response.json()["images"] == []
    assert response.json()["error"] == "No GitHub token configured for aegis."


def test_repository_search_is_case_insensitive_and_caps_results(client, monkeypatch):
    monkeypatch.setattr("src.settings.organisations_router.read_app_config", lambda: {"github": {"orgs": [{"name": "aegis"}]}})

    async def fake_fetch_repos(org, token):
        return [{"name": f"api-{i}", "full_name": f"aegis/api-{i}"} for i in range(25)]

    monkeypatch.setattr("src.settings.organisations_router.get_github_token_for_org", lambda org: "token")
    monkeypatch.setattr("src.settings.organisations_router.fetch_org_repos", fake_fetch_repos)

    response = client.get("/api/v1/settings/resources/repositories?org=aegis&q=API")

    assert response.status_code == 200
    assert len(response.json()["repositories"]) == 25
    assert response.json()["repositories"][0] == {"org": "aegis", "repo": "api-0", "fullName": "aegis/api-0"}
    assert response.json()["repositories"][-1] == {"org": "aegis", "repo": "api-24", "fullName": "aegis/api-24"}


def test_create_team_requires_workspace_admin_v2():
    from conftest import make_authed_client
    c = make_authed_client(role="security", user_id="usr_security", raise_server_exceptions=True)

    response = c.post(
        "/api/v1/settings/organisations",
        json={"name": "New Team", "description": ""},
    )
    assert response.status_code == 403


def test_delete_team_requires_workspace_admin():
    from conftest import make_authed_client
    team = store.create_team({"name": "To Delete", "description": ""})
    c = make_authed_client(role="security", user_id="usr_security_del", raise_server_exceptions=True)

    response = c.delete(f"/api/v1/settings/organisations/{team['id']}")
    assert response.status_code == 403


def test_list_organisations_includes_sharing_status():
    from conftest import make_authed_client
    team1 = store.create_team({"name": "Team1", "description": ""})
    store.upsert_member(team1["id"], "usr_jane")

    team2 = store.create_team({"name": "Team2", "description": ""})

    # usr_jane has security role and is a member of team1
    c = make_authed_client(role="security", user_id="usr_jane", raise_server_exceptions=True)
    response = c.get("/api/v1/settings/organisations")

    assert response.status_code == 200
    teams = response.json()["teams"]
    t1 = next(t for t in teams if t["id"] == team1["id"])
    t2 = next(t for t in teams if t["id"] == team2["id"])

    assert t1["isShared"] is True
    assert t2["isShared"] is False
