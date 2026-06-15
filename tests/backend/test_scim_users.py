import hashlib


_RAW = "test-scim-bearer-99"
_HASH = hashlib.sha256(_RAW.encode("utf-8")).hexdigest()


def _enable_scim():
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import ScimConfig

    async def _seed(session):
        row = (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one()
        row.enabled = True
        row.token_hash = _HASH
    run_db(_seed)


def _client():
    from fastapi.testclient import TestClient
    from src.main import app
    return TestClient(app), {"Authorization": f"Bearer {_RAW}"}


def test_post_user_creates(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    _enable_scim()
    client, auth = _client()
    resp = client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim-alice@example.com",
            "emails": [{"value": "scim-alice@example.com", "primary": True, "type": "work"}],
            "active": True,
        },
        headers=auth,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["userName"] == "scim-alice@example.com"
    assert body["active"] is True


def test_list_users_filters_by_username(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    _enable_scim()
    client, auth = _client()
    client.post(
        "/scim/v2/Users",
        json={"userName": "filter-target@example.com", "emails": [{"value": "filter-target@example.com"}], "active": True},
        headers=auth,
    )
    resp = client.get(
        '/scim/v2/Users?filter=userName eq "filter-target@example.com"',
        headers=auth,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] >= 1
    assert any(r["userName"] == "filter-target@example.com" for r in body["Resources"])


def test_delete_user_deprovisions(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    _enable_scim()
    client, auth = _client()
    create = client.post(
        "/scim/v2/Users",
        json={"userName": "to-delete@example.com", "emails": [{"value": "to-delete@example.com"}], "active": True},
        headers=auth,
    )
    user_id = create.json()["id"]
    resp = client.delete(f"/scim/v2/Users/{user_id}", headers=auth)
    assert resp.status_code in (204, 200)


def test_groups_returns_501(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    _enable_scim()
    client, auth = _client()
    resp = client.get("/scim/v2/Groups", headers=auth)
    assert resp.status_code == 501
