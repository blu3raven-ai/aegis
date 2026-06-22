"""Tests for /api/v1/findings/reports/scheduled CRUD endpoints."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402
from src.reports.router import router as reports_router  # noqa: E402


_VIEWER_PERMS = {"view_findings"}


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(reports_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_email = "test@example.com"
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


def test_create_scheduled_report():
    app = _make_app()
    fake_result = {
        "id": 1, "name": "Weekly findings", "report_type": "findings", "format": "pdf",
        "schedule_type": "cron", "schedule_value": "0 9 * * 1",
        "filters": {"severity": ["critical"]}, "destination_ids": [],
        "created_by": "test@example.com", "enabled": True,
        "last_run_at": None, "last_run_status": None, "last_run_error": None,
        "created_at": "2026-06-14T00:00:00+00:00", "updated_at": "2026-06-14T00:00:00+00:00",
    }
    recorder = MagicMock()
    with (
        patch("src.reports.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=["a-1"])),
        patch("src.reports.router.create_schedule", return_value=fake_result),
        patch("src.reports.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).post("/api/v1/findings/reports/scheduled", json={
            "name": "Weekly findings",
            "report_type": "findings",
            "format": "pdf",
            "schedule_type": "cron",
            "schedule_value": "0 9 * * 1",
            "filters": {"severity": ["critical"]},
            "destination_ids": [],
            "enabled": True,
        })
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "Weekly findings"
    recorder.record.assert_called_once()
    kwargs = recorder.record.call_args.kwargs
    assert kwargs["action"] == "scheduled_report.created"


def test_create_scheduled_report_validation_error():
    app = _make_app()
    with (
        patch("src.reports.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=["a-1"])),
        patch("src.reports.router.create_schedule", side_effect=ValueError("posture reports do not support csv format")),
    ):
        r = TestClient(app).post("/api/v1/findings/reports/scheduled", json={
            "name": "Bad",
            "report_type": "posture",
            "format": "csv",
            "schedule_type": "simple",
            "schedule_value": "09:00",
        })
    assert r.status_code == 422
    assert "csv" in r.json()["detail"].lower()


def test_list_scheduled_reports():
    app = _make_app()
    fake_items = [
        {
            "id": 1, "name": "Daily posture", "report_type": "posture", "format": "json",
            "schedule_type": "simple", "schedule_value": "09:00", "filters": {},
            "destination_ids": [], "created_by": "u", "enabled": True,
            "last_run_at": None, "last_run_status": None, "last_run_error": None,
            "created_at": "2026-06-14T00:00:00+00:00", "updated_at": "2026-06-14T00:00:00+00:00",
        },
    ]
    with (
        patch("src.reports.router.list_schedules", return_value=fake_items),
    ):
        r = TestClient(app).get("/api/v1/findings/reports/scheduled")
    assert r.status_code == 200
    assert len(r.json()["items"]) == 1


def test_update_scheduled_report_404():
    from src.reports.scheduled import ScheduledReportNotFound

    app = _make_app()
    with (
        patch("src.reports.router.update_schedule", side_effect=ScheduledReportNotFound("999")),
    ):
        r = TestClient(app).patch("/api/v1/findings/reports/scheduled/999", json={"enabled": False})
    assert r.status_code == 404


def test_update_scheduled_report_empty_body():
    app = _make_app()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        r = TestClient(app).patch("/api/v1/findings/reports/scheduled/1", json={})
    assert r.status_code == 422


def test_delete_scheduled_report():
    app = _make_app()
    recorder = MagicMock()
    with (
        patch("src.reports.router.delete_schedule", return_value=True),
        patch("src.reports.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).delete("/api/v1/findings/reports/scheduled/1")
    assert r.status_code == 204
    recorder.record.assert_called_once()


def test_delete_scheduled_report_404():
    app = _make_app()
    with (
        patch("src.reports.router.delete_schedule", return_value=False),
    ):
        r = TestClient(app).delete("/api/v1/findings/reports/scheduled/999")
    assert r.status_code == 404


def test_create_requires_permission():
    app = _make_app(allow_view_findings=False)
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        r = TestClient(app).post("/api/v1/findings/reports/scheduled", json={
            "name": "x", "report_type": "findings", "format": "pdf",
            "schedule_type": "simple", "schedule_value": "09:00",
        })
    assert r.status_code == 403
