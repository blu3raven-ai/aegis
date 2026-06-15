import pytest
from fastapi.testclient import TestClient
from src.main import app


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


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("RUNNER_ENCRYPTION_KEY", "a" * 64)
    monkeypatch.setenv("FASTAPI_ENV", "production")
    _seed_default_roles()
    # Unused by tests below, but kept for fixture compat. Tests create
    # role-specific clients directly via make_authed_client.
    from conftest import make_authed_client
    return make_authed_client(role="admin", user_id="dep-auth-admin")


def test_dependencies_refresh_requires_appropriate_role(monkeypatch):
    import src.dependencies.router as dependencies_api

    # Patch execute_dependencies_scan_once so the background thread exits immediately
    import src.shared.scan_orchestration as scan_orch
    monkeypatch.setattr(dependencies_api, "execute_dependencies_scan_once", lambda *a, **kw: None)
    monkeypatch.setattr(dependencies_api, "get_github_token_for_org", lambda org: "token")
    monkeypatch.setattr(dependencies_api, "get_dependencies_scanner_config", lambda: {"image": "test", "concurrency": "1"})
    monkeypatch.setattr(dependencies_api, "org_has_source_connections", lambda org, categories=None: True)
    monkeypatch.setattr(scan_orch, "org_has_source_connections", lambda org, categories=None: True)
    monkeypatch.setattr(scan_orch, "get_github_token_for_org", lambda org: "token")

    from conftest import make_authed_client
    _seed_default_roles()

    # Viewer role should be denied
    viewer_client = make_authed_client(role="viewer", user_id="dep-refresh-viewer")
    response = viewer_client.post("/api/v1/dependencies/runs?org=test-org")
    assert response.status_code == 403

    # Admin role should be ALLOWED (returns 202 Accepted)
    admin_client = make_authed_client(role="admin", user_id="dep-refresh-admin")
    response = admin_client.post("/api/v1/dependencies/runs?org=test-org")
    assert response.status_code == 202


def test_dependencies_cancel_requires_appropriate_role(monkeypatch):
    import src.dependencies.router as dependencies_api

    class FakeRuntime:
        def probe(self, org: str) -> dict:
            return {"active": True, "status": "running", "progress": 0}
        def cancel(self, org: str, cancel_fn=None) -> dict:
            return {"ok": True}

    monkeypatch.setattr(dependencies_api, "_dependencies_runtime", FakeRuntime())

    from conftest import make_authed_client
    _seed_default_roles()

    # Viewer role should be denied
    viewer_client = make_authed_client(role="viewer", user_id="dep-cancel-viewer")
    response = viewer_client.post("/api/v1/dependencies/runs/cancel?org=test-org")
    assert response.status_code == 403

    # Admin role should be ALLOWED
    admin_client = make_authed_client(role="admin", user_id="dep-cancel-admin")
    response = admin_client.post("/api/v1/dependencies/runs/cancel?org=test-org")
    assert response.status_code == 200


def test_viewer_with_repo_scope_cannot_refresh_cache(monkeypatch):
    from conftest import make_authed_client
    _seed_default_roles()

    # Viewer WITH scope should still be denied refresh (privileged action)
    viewer_client = make_authed_client(role="viewer", user_id="dep-scope-viewer")
    response = viewer_client.post("/api/v1/dependencies/runs?org=octo")
    assert response.status_code == 403
