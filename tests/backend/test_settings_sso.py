def test_get_sso_returns_disabled_defaults(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="sso-user-1")
    resp = client.get("/api/v1/settings/sso")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is False
    assert body["protocol"] is None
    assert body["samlSpPrivateKeySet"] is False
    assert body["oidcClientSecretSet"] is False
    assert body["samlAcsUrl"].endswith("/auth/sso/saml/acs")
    assert body["samlSpMetadataUrl"].endswith("/auth/sso/saml/metadata")
    assert body["oidcRedirectUri"].endswith("/auth/sso/oidc/callback")


def test_patch_sso_updates_metadata_url(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="sso-user-2")
    resp = client.patch("/api/v1/settings/sso", json={
        "protocol": "saml",
        "samlMetadataUrl": "https://idp.example.com/metadata",
        "enabled": True,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is True
    assert body["protocol"] == "saml"
    assert body["samlMetadataUrl"] == "https://idp.example.com/metadata"


def test_patch_sso_requires_manage_settings(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="sso-user-3")
    resp = client.patch("/api/v1/settings/sso", json={"enabled": True})
    assert resp.status_code == 403


def test_post_sp_keypair_generates_cert_and_key(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    from src.db.helpers import run_db
    from src.db.models import SsoConfig
    client = make_authed_client(role="admin", user_id="sso-user-4")
    resp = client.post("/api/v1/settings/sso/saml/sp-keypair")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "BEGIN CERTIFICATE" in body["certificate"]
    # Verify persistence via direct DB read to avoid the asyncpg cross-loop
    # flake that occurs when two TestClient requests run in a single isolated session.
    async def _q(session):
        return await session.get(SsoConfig, 1)
    row = run_db(_q)
    assert row.saml_sp_certificate == body["certificate"]
    assert row.saml_sp_private_key_enc is not None
