def test_saml_login_redirects_when_unconfigured(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/auth/sso/saml/login")
    assert resp.status_code in (302, 303, 307)
    assert "/login?error=sso_disabled" in resp.headers["location"]


def test_saml_metadata_returns_404_when_unconfigured(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    resp = client.get("/auth/sso/saml/metadata")
    assert resp.status_code == 404


def test_saml_acs_rejects_when_unconfigured(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app, follow_redirects=False)
    resp = client.post("/auth/sso/saml/acs", data={"SAMLResponse": "x"})
    assert resp.status_code in (302, 303, 307)
    assert "/login?error=sso" in resp.headers["location"]
