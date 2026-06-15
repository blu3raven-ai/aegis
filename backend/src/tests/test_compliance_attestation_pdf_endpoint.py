from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.compliance.models import Framework  # noqa: E402
from src.compliance.router import router as compliance_router  # noqa: E402


_VIEWER_PERMS = {"view_findings"}


async def _resolve_known_framework(_session, framework_id):
    return Framework(id=framework_id, label="SOC 2", is_custom=False)


async def _resolve_missing_framework(_session, _framework_id):
    return None


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_org = "test-org"
        return await call_next(request)

    return app


async def _resolve_assets(_request):
    return ["asset-1"]


def _stub_payload():
    return {
        "framework": {"id": "soc2", "label": "SOC 2"},
        "summary": {
            "total_controls": 1,
            "met_controls": 1,
            "unmet_controls": 0,
            "partial_controls": 0,
            "critical_gaps": 0,
            "high_gaps": 0,
            "pass_pct": 100,
        },
        "controls": [
            {
                "control_id": "CC6.1",
                "title": "Logical access",
                "description": "Access ctrls",
                "status": "met",
                "findings": [],
            }
        ],
        "generated_at": "2026-06-14 23:30 UTC",
    }


def test_attestation_pdf_returns_pdf():
    app = _make_app()

    async def _fake_payload(_session, _fw, *, asset_ids):
        return _stub_payload()

    recorder = MagicMock()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_known_framework),
        patch("src.compliance.router.build_attestation_payload", side_effect=_fake_payload),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/soc2/attestation.pdf")

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.headers["content-disposition"].startswith('attachment; filename="soc2-attestation-')
    assert resp.headers["content-disposition"].endswith('.pdf"')
    assert resp.content[:4] == b"%PDF"
    recorder.record.assert_called_once()
    kwargs = recorder.record.call_args.kwargs
    assert kwargs["action"] == "compliance.attestation_exported"
    assert kwargs["resource_id"] == "soc2"
    assert kwargs["metadata"] == {"format": "pdf"}


def test_attestation_pdf_unknown_framework_404():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.compliance.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.compliance.router.get_framework", side_effect=_resolve_missing_framework),
    ):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/madeup/attestation.pdf")
    assert resp.status_code == 404


def test_attestation_pdf_requires_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/compliance/frameworks/soc2/attestation.pdf")
    assert resp.status_code == 403
