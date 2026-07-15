from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402
from src.reports.router import router as reports_router  # noqa: E402


_VIEWER_PERMS = {"view_findings"}


def _make_app(*, with_user: bool = True, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(reports_router)

    if with_user:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.user_sub = "test-user"
            request.state.user_org = "test-org"
            return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
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

    async def _fake_resolve(request):
        return ["asset-1"]

    with (
        patch("src.reports.router.resolve_asset_ids_from_request", side_effect=_fake_resolve),
        patch("src.reports.router.generate_report", return_value=fake),
        patch("src.reports.router.get_download_url", return_value="https://minio.example/reports/42.json?sig=abc"),
    ):
        resp = TestClient(app).post("/api/v1/findings/reports", json={
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
    app = _make_app(allow_view_findings=False)
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        resp = TestClient(app).post("/api/v1/findings/reports", json={
            "report_type": "findings",
            "format": "json",
        })
    assert resp.status_code == 403


async def _fake_resolve(request):
    return ["asset-1"]


def test_list_reports_empty():
    app = _make_app()
    with (
        patch("src.reports.router.resolve_asset_ids_from_request", side_effect=_fake_resolve),
        patch("src.reports.router.list_reports", return_value=([], 0)),
    ):
        resp = TestClient(app).get("/api/v1/findings/reports")
    assert resp.status_code == 200
    body = resp.json()
    assert body["reports"] == []
    assert body["total"] == 0


def test_list_reports_surfaces_download_url_and_error():
    """The history list must carry download_url (so completed reports stay
    downloadable after a reload) and error (so a failed report shows why)."""
    app = _make_app()
    completed = _fake_row(report_id=1, status="completed")
    failed = _fake_row(report_id=2, status="failed", error="MinIO upload failed")
    with (
        patch("src.reports.router.resolve_asset_ids_from_request", side_effect=_fake_resolve),
        patch("src.reports.router.list_reports", return_value=([completed, failed], 2)),
        # Signed URL only for the completed row; failed/keyless rows return None.
        patch("src.reports.router.get_download_url", side_effect=lambda r: "https://minio/1.json?sig=x" if r.status == "completed" else None),
    ):
        resp = TestClient(app).get("/api/v1/findings/reports")
    assert resp.status_code == 200
    rows = {r["id"]: r for r in resp.json()["reports"]}
    assert rows[1]["download_url"] == "https://minio/1.json?sig=x"
    assert rows[1]["error"] is None
    assert rows[2]["download_url"] is None
    assert rows[2]["error"] == "MinIO upload failed"


def test_get_report_not_found():
    app = _make_app()
    with (
        patch("src.reports.router.resolve_asset_ids_from_request", side_effect=_fake_resolve),
        patch("src.reports.router.get_report", return_value=None),
    ):
        resp = TestClient(app).get("/api/v1/findings/reports/999")
    assert resp.status_code == 404


def test_delete_report():
    app = _make_app()
    with (
        patch("src.reports.router.resolve_asset_ids_from_request", side_effect=_fake_resolve),
        patch("src.reports.router.delete_report", return_value=True),
    ):
        resp = TestClient(app).delete("/api/v1/findings/reports/5")
    assert resp.status_code == 204


def test_create_posture_report_csv_rejected():
    app = _make_app()
    resp = TestClient(app).post("/api/v1/findings/reports", json={
        "report_type": "posture",
        "format": "csv",
    })
    assert resp.status_code == 422
    assert "CSV" in resp.json()["detail"]
