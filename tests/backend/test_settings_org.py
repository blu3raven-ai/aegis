from __future__ import annotations

import base64


def _data_url(mime: str = "image/png", payload: bytes = b"x") -> str:
    return f"data:{mime};base64,{base64.b64encode(payload).decode('ascii')}"


def _gql(client, operation_name: str, query: str, variables: dict | None = None) -> dict:
    payload: dict = {"operationName": operation_name, "query": query}
    if variables:
        payload["variables"] = variables
    resp = client.post("/api/v1/graphql", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


_ORG_FIELDS = "name logoDataUrl updatedAt"

_Q_ORG_BRANDING = f"query OrgBranding {{ orgBranding {{ {_ORG_FIELDS} }} }}"
_M_UPDATE_ORG_NAME = (
    f"mutation UpdateOrgName($name: String!) {{ updateOrgName(name: $name) {{ {_ORG_FIELDS} }} }}"
)
_M_SET_ORG_LOGO = (
    f"mutation SetOrgLogo($dataUrl: String!) {{ setOrgLogo(dataUrl: $dataUrl) {{ {_ORG_FIELDS} }} }}"
)
_M_CLEAR_ORG_LOGO = f"mutation ClearOrgLogo {{ clearOrgLogo {{ {_ORG_FIELDS} }} }}"


def test_get_org_returns_null_branding_after_migration():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-1")
    body = _gql(client, "OrgBranding", _Q_ORG_BRANDING)
    data = body["data"]["orgBranding"]
    assert data["name"] is None
    assert data["logoDataUrl"] is None
    assert "updatedAt" in data


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
    body = _gql(client, "UpdateOrgName", _M_UPDATE_ORG_NAME, {"name": ""})
    assert body["data"]["updateOrgName"]["name"] is None


def test_patch_org_updates_name():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-2")
    body = _gql(client, "UpdateOrgName", _M_UPDATE_ORG_NAME, {"name": "Acme Corp"})
    assert body["data"]["updateOrgName"]["name"] == "Acme Corp"


def test_patch_org_requires_manage_organisations_permission():
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="org-user-3")
    body = _gql(client, "UpdateOrgName", _M_UPDATE_ORG_NAME, {"name": "Hacked"})
    errors = body.get("errors", [])
    assert errors, "expected a permission error"
    assert errors[0]["extensions"]["code"] == "PERMISSION_DENIED"


def test_post_org_logo_stores_data_url():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-4")
    url = _data_url()
    body = _gql(client, "SetOrgLogo", _M_SET_ORG_LOGO, {"dataUrl": url})
    assert body["data"]["setOrgLogo"]["logoDataUrl"] == url


def test_post_org_logo_rejects_oversize():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-5")
    huge = "data:image/png;base64," + ("A" * (200 * 1024 + 1))
    body = _gql(client, "SetOrgLogo", _M_SET_ORG_LOGO, {"dataUrl": huge})
    errors = body.get("errors", [])
    assert errors, "expected a validation error"
    assert errors[0]["extensions"]["code"] == "VALIDATION_ERROR"


def test_post_org_logo_rejects_bad_mime():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="org-user-6")
    url = _data_url(mime="image/tiff")
    body = _gql(client, "SetOrgLogo", _M_SET_ORG_LOGO, {"dataUrl": url})
    errors = body.get("errors", [])
    assert errors, "expected a validation error"
    assert errors[0]["extensions"]["code"] == "VALIDATION_ERROR"


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
    body = _gql(client, "ClearOrgLogo", _M_CLEAR_ORG_LOGO)
    assert body["data"]["clearOrgLogo"]["logoDataUrl"] is None


def test_public_branding_reflects_org_edits():
    from fastapi.testclient import TestClient
    from conftest import make_authed_client
    from src.main import app

    authed = make_authed_client(role="admin", user_id="org-user-8")
    _gql(authed, "UpdateOrgName", _M_UPDATE_ORG_NAME, {"name": "Acme"})

    public = TestClient(app)
    body = public.post(
        "/api/v1/graphql",
        json={"operationName": "OrgBranding", "query": _Q_ORG_BRANDING},
    )
    assert body.status_code == 200, body.text
    data = body.json()["data"]["orgBranding"]
    assert data["name"] == "Acme"
