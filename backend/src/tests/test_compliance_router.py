from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.compliance.models import Framework  # noqa: E402
from src.compliance.router import router as compliance_router  # noqa: E402


_VIEWER_PERMS = {"view_findings"}


def _fw(framework_id: str = "soc2", label: str = "SOC 2") -> Framework:
    return Framework(id=framework_id, label=label, is_custom=False)


async def _resolve_known_framework(_session, framework_id):
    return _fw(framework_id, label=framework_id.upper())


async def _resolve_missing_framework(_session, _framework_id):
    return None


def _make_app(*, with_user: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)

    if with_user:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.user_sub = "test-user"
            request.state.user_org = "test-org"
            return await call_next(request)

    return app


async def _resolve_assets(_request):
    return ["asset-1", "asset-2"]


async def _resolve_no_assets(_request):
    return []


def test_get_summary_scopes_to_caller_assets():
    """The router must resolve viewer asset_ids and pass them to the service."""
    app = _make_app()
    captured: dict = {}

    async def _fake_summary(_session, framework, *, asset_ids):
        captured["framework"] = framework
        captured["asset_ids"] = asset_ids
        return []

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_known_framework),
        patch("src.compliance.router.get_framework_summary", side_effect=_fake_summary),
    ):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/soc2/summary")
    assert resp.status_code == 200, resp.text
    assert captured["framework"] == "soc2"
    assert captured["asset_ids"] == ["asset-1", "asset-2"]
    body = resp.json()
    assert body["framework"] == "soc2"
    assert body["controls"] == []


def test_get_summary_rejects_unknown_framework():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_missing_framework),
    ):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/madeup/summary")
    assert resp.status_code == 404


def test_get_summary_ignores_legacy_org_id_query_param():
    """Legacy ?org_id=... param must not influence scoping — it's silently dropped."""
    app = _make_app()
    captured: dict = {}

    async def _fake_summary(_session, framework, *, asset_ids):
        captured["asset_ids"] = asset_ids
        return []

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_known_framework),
        patch("src.compliance.router.get_framework_summary", side_effect=_fake_summary),
    ):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/soc2/summary?org_id=other-org")
    assert resp.status_code == 200
    assert captured["asset_ids"] == ["asset-1", "asset-2"]


def test_get_summary_requires_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/soc2/summary")
    assert resp.status_code == 403


def test_get_findings_by_control_scopes_to_caller_assets():
    app = _make_app()
    captured: dict = {}

    async def _fake_findings(_session, framework, control_id, *, asset_ids):
        captured["framework"] = framework
        captured["control_id"] = control_id
        captured["asset_ids"] = asset_ids
        return []

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_known_framework),
        patch("src.compliance.router.get_findings_for_control", side_effect=_fake_findings),
    ):
        resp = TestClient(app).get("/api/v1/compliance/controls/soc2/CC6.1/findings")
    assert resp.status_code == 200, resp.text
    assert captured["framework"] == "soc2"
    assert captured["control_id"] == "CC6.1"
    assert captured["asset_ids"] == ["asset-1", "asset-2"]


def test_get_findings_by_control_empty_assets_returns_empty():
    """Viewer with no team access (empty asset_ids) sees no findings — fail-closed."""
    app = _make_app()
    captured: dict = {}

    async def _fake_findings(_session, framework, control_id, *, asset_ids):
        captured["asset_ids"] = asset_ids
        return []

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_no_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_known_framework),
        patch("src.compliance.router.get_findings_for_control", side_effect=_fake_findings),
    ):
        resp = TestClient(app).get("/api/v1/compliance/controls/soc2/CC6.1/findings")
    assert resp.status_code == 200
    assert captured["asset_ids"] == []
    assert resp.json()["findings"] == []


def test_get_findings_by_control_requires_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/compliance/controls/soc2/CC6.1/findings")
    assert resp.status_code == 403
