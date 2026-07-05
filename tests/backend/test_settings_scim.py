def test_get_scim_returns_defaults(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="scim-user-1")
    resp = client.get("/api/v1/settings/scim")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is False
    assert body["tokenSet"] is False
    assert body["scimEndpointUrl"].endswith("/scim/v2/")


def test_patch_scim_toggles_enabled(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="scim-user-2")
    resp = client.patch("/api/v1/settings/scim", json={"enabled": True})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


def test_patch_scim_requires_manage_settings(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="scim-user-3")
    resp = client.patch("/api/v1/settings/scim", json={"enabled": True})
    assert resp.status_code == 403


def test_post_token_generates_and_persists_hash(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import ScimConfig

    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="scim-user-4")
    resp = client.post("/api/v1/settings/scim/token")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["token"]) > 20

    async def _read(session):
        return (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one()
    row = run_db(_read)
    assert row.token_hash is not None
    assert row.token_hash != body["token"]
