import pytest
from fastapi.testclient import TestClient
from src.main import app
import time
import base64
import json
import hmac
import hashlib


def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def _make_jwt(sub: str, role: str, secret: str) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload = _b64url(json.dumps({"sub": sub, "role": role, "iat": now, "exp": now + 60}))
    if len(secret) == 64:
        key = bytes.fromhex(secret)
    else:
        key = secret.encode("utf-8")
    signature = _b64url(hmac.new(key, f"{header}.{payload}".encode("utf-8"), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"

def _auth_headers(role: str, secret: str = "a" * 64, sub: str | None = None) -> dict[str, str]:
    user_sub = sub if sub else f'usr_{role}'
    return {"Authorization": f"Bearer {_make_jwt(sub=user_sub, role=role, secret=secret)}"}


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
    monkeypatch.setenv("JWT_SHARED_SECRET", "a" * 64)
    monkeypatch.setenv("FASTAPI_ENV", "production")
    _seed_default_roles()
    return TestClient(app)


def test_dependencies_refresh_requires_appropriate_role(client, monkeypatch):
    import src.dependencies.router as dependencies_api

    # Patch execute_dependencies_scan_once so the background thread exits immediately
    import src.shared.scan_orchestration as scan_orch
    monkeypatch.setattr(dependencies_api, "execute_dependencies_scan_once", lambda *a, **kw: None)
    monkeypatch.setattr(dependencies_api, "get_github_token_for_org", lambda org: "token")
    monkeypatch.setattr(dependencies_api, "get_dependencies_scanner_config", lambda: {"image": "test", "concurrency": "1"})
    monkeypatch.setattr(dependencies_api, "org_has_source_connections", lambda org, categories=None: True)
    monkeypatch.setattr(scan_orch, "org_has_source_connections", lambda org, categories=None: True)
    monkeypatch.setattr(scan_orch, "get_github_token_for_org", lambda org: "token")

    # Viewer role should be denied
    response = client.post("/dependencies/api/runs?org=test-org", headers=_auth_headers("viewer"))
    assert response.status_code == 403

    # Admin role should be ALLOWED (returns 202 Accepted)
    response = client.post("/dependencies/api/runs?org=test-org", headers=_auth_headers("admin"))
    assert response.status_code == 202


def test_dependencies_cancel_requires_appropriate_role(client, monkeypatch):
    import src.dependencies.router as dependencies_api

    class FakeRuntime:
        def probe(self, org: str) -> dict:
            return {"active": True, "status": "running", "progress": 0}
        def cancel(self, org: str, cancel_fn=None) -> dict:
            return {"ok": True}

    monkeypatch.setattr(dependencies_api, "_dependencies_runtime", FakeRuntime())

    # Viewer role should be denied
    response = client.post("/dependencies/api/runs/cancel?org=test-org", headers=_auth_headers("viewer"))
    assert response.status_code == 403

    # Admin role should be ALLOWED
    response = client.post("/dependencies/api/runs/cancel?org=test-org", headers=_auth_headers("admin"))
    assert response.status_code == 200


def test_viewer_with_repo_scope_cannot_refresh_cache(client, monkeypatch):
    from src.settings import organisations_store as store

    # Viewer WITH scope should still be denied refresh (privileged action)
    response = client.post("/dependencies/api/runs?org=octo", headers=_auth_headers("viewer", sub="usr_viewer"))
    assert response.status_code == 403
