def test_scim_disabled_returns_404(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    resp = client.get("/scim/v2/ServiceProviderConfig")
    assert resp.status_code == 404


def test_scim_missing_bearer_returns_401(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import ScimConfig

    async def _seed(session):
        row = (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one()
        row.enabled = True
        row.token_hash = "abc"
    run_db(_seed)

    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    resp = client.get("/scim/v2/ServiceProviderConfig")
    assert resp.status_code == 401


def test_scim_valid_bearer_passes(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    import hashlib
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import ScimConfig

    raw = "test-bearer-12345"
    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def _seed(session):
        row = (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one()
        row.enabled = True
        row.token_hash = hashed
    run_db(_seed)

    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app)
    resp = client.get(
        "/scim/v2/ServiceProviderConfig",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 200
