from __future__ import annotations

import base64


def _data_url(mime: str = "image/png", payload: bytes = b"x") -> str:
    return f"data:{mime};base64,{base64.b64encode(payload).decode('ascii')}"


def test_get_org_returns_null_branding_after_migration():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-1")
    resp = client.get("/api/v1/settings/org")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] is None
    assert body["logoDataUrl"] is None
    assert "updatedAt" in body
    for dropped in ("subtitle", "defaultTimezone", "securityContactEmail"):
        assert dropped not in body


def test_patch_org_empty_name_clears_to_null():
    from sqlalchemy import select

    from src.db.helpers import run_db
    from src.db.models import OrgSettings

    async def _seed(session):
        row = (await session.execute(select(OrgSettings).where(OrgSettings.id == 1))).scalar_one_or_none()
        if row is None:
            row = OrgSettings(id=1, name="Acme")
            session.add(row)
        else:
            row.name = "Acme"
    run_db(_seed)

    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-9")
    resp = client.patch("/api/v1/settings/org", json={"name": ""})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] is None


def test_patch_org_updates_name():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-2")
    resp = client.patch("/api/v1/settings/org", json={"name": "Acme Corp"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "Acme Corp"


def test_patch_org_requires_manage_organisations_permission():
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="org-user-3")
    resp = client.patch("/api/v1/settings/org", json={"name": "Hacked"})
    assert resp.status_code == 403


def test_post_org_logo_stores_data_url():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-4")
    url = _data_url()
    resp = client.post("/api/v1/settings/org/logo", json={"dataUrl": url})
    assert resp.status_code == 200, resp.text
    assert resp.json()["logoDataUrl"] == url


def test_post_org_logo_rejects_oversize():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-5")
    huge = "data:image/png;base64," + ("A" * (200 * 1024 + 1))
    resp = client.post("/api/v1/settings/org/logo", json={"dataUrl": huge})
    assert resp.status_code == 400


def test_post_org_logo_rejects_bad_mime():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-6")
    url = _data_url(mime="image/tiff")
    resp = client.post("/api/v1/settings/org/logo", json={"dataUrl": url})
    assert resp.status_code == 400


def test_delete_org_logo_clears_field():
    from datetime import datetime, timezone

    from src.db.helpers import run_db
    from src.db.models import OrgSettings
    from sqlalchemy import select

    async def _seed(session):
        row = (await session.execute(select(OrgSettings).where(OrgSettings.id == 1))).scalar_one_or_none()
        if row is None:
            row = OrgSettings(id=1, logo_data_url=_data_url(), updated_at=datetime.now(timezone.utc))
            session.add(row)
        else:
            row.logo_data_url = _data_url()
    run_db(_seed)

    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-7")
    resp = client.delete("/api/v1/settings/org/logo")
    assert resp.status_code == 200, resp.text
    assert resp.json()["logoDataUrl"] is None


def test_public_branding_reflects_org_edits():
    from conftest import make_authed_client
    from fastapi.testclient import TestClient
    from src.main import app

    authed = make_authed_client(role="admin", user_id="org-user-8")
    authed.patch("/api/v1/settings/org", json={"name": "Acme"})

    public = TestClient(app)
    body = public.get("/api/v1/branding").json()
    assert body["name"] == "Acme"
    assert "subtitle" not in body
