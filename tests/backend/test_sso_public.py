def test_sso_availability_returns_disabled_by_default(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    resp = client.get("/api/v1/auth/sso/availability")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"enabled": False, "protocol": None}


def test_sso_availability_reports_enabled_after_admin_toggles(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import SsoConfig

    async def _seed(session):
        row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one()
        row.enabled = True
        row.protocol = "saml"
        row.saml_metadata_xml = "<EntityDescriptor/>"
        from src.security.crypto import encrypt
        row.saml_sp_private_key_enc = encrypt("dummy")
    run_db(_seed)

    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    body = client.get("/api/v1/auth/sso/availability").json()
    assert body == {"enabled": True, "protocol": "saml"}
