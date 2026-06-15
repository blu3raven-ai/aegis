"""Tests for the DB-backed framework registry."""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.compliance.router import router as compliance_router  # noqa: E402


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)
    return app


def test_list_frameworks_returns_db_rows():
    """GET /frameworks must return whatever the DB-backed list_frameworks yields."""
    rows = [
        {"id": "soc2", "label": "SOC 2"},
        {"id": "custom-x", "label": "Acme custom"},
    ]

    with patch("src.compliance.router.run_db", return_value=rows):
        resp = TestClient(_make_app()).get("/api/v1/compliance/frameworks")

    assert resp.status_code == 200, resp.text
    assert resp.json() == rows


def test_list_frameworks_router_delegates_to_service():
    """The router must pass src.compliance.service.list_frameworks to run_db."""
    captured: dict = {}

    def _fake_run_db(fn):
        captured["fn"] = fn
        return []

    with patch("src.compliance.router.run_db", side_effect=_fake_run_db):
        TestClient(_make_app()).get("/api/v1/compliance/frameworks")

    from src.compliance.router import list_frameworks
    assert captured["fn"] is list_frameworks
