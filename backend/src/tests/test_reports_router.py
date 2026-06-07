from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.reports.router import router as reports_router  # noqa: E402


_VIEWER_PERMS = {"view_findings"}


def _make_app(*, with_user: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(reports_router)

    if with_user:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.user_sub = "test-user"
            request.state.user_org = "test-org"
            return await call_next(request)

    return app


def _fake_row(report_id: int = 1, **overrides) -> MagicMock:
    now = datetime(2026, 6, 4, 12, 0, tzinfo=timezone.utc)
    row = MagicMock()
    row.id = report_id
    row.org = "test-org"
    row.title = "Test report"
    row.report_type = "findings"
    row.format = "json"
    row.status = "completed"
    row.row_count = 3
    row.file_size_bytes = 256
    row.created_by = "tester@example.com"
    row.created_at = now
    row.expires_at = now
    row.filters = None
    row.error = None
    for k, v in overrides.items():
        setattr(row, k, v)
    return row


def test_create_findings_report_json():
    app = _make_app()
    fake = _fake_row(report_id=42, report_type="findings", format="json")
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.reports.router.generate_report", return_value=fake),
        patch("src.reports.router.get_download_url", return_value="https://minio.example/reports/42.json?sig=abc"),
    ):
        resp = TestClient(app).post("/api/v1/reports", json={
            "report_type": "findings",
            "format": "json",
        })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == 42
    assert body["report_type"] == "findings"
    assert body["format"] == "json"
    assert body["status"] == "completed"
    assert body["download_url"] == "https://minio.example/reports/42.json?sig=abc"


def test_create_report_no_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).post("/api/v1/reports", json={
            "report_type": "findings",
            "format": "json",
        })
    assert resp.status_code == 403


def test_list_reports_empty():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.reports.router.list_reports", return_value=([], 0)),
    ):
        resp = TestClient(app).get("/api/v1/reports")
    assert resp.status_code == 200
    body = resp.json()
    assert body["reports"] == []
    assert body["total"] == 0


def test_get_report_not_found():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.reports.router.get_report", return_value=None),
    ):
        resp = TestClient(app).get("/api/v1/reports/999")
    assert resp.status_code == 404


def test_delete_report():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.reports.router.delete_report", return_value=True),
    ):
        resp = TestClient(app).delete("/api/v1/reports/5")
    assert resp.status_code == 204


def test_create_posture_report_csv_rejected():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        resp = TestClient(app).post("/api/v1/reports", json={
            "report_type": "posture",
            "format": "csv",
        })
    assert resp.status_code == 422
    assert "JSON" in resp.json()["detail"]
