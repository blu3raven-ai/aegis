"""Unit tests for enrichment admin endpoints.

Covers:
  POST /api/v1/enrichment/osv/refresh           (202, spawns bg thread)
  POST /api/v1/enrichment/osv/reconcile?mode=…  (202, spawns bg thread)
  POST /api/v1/enrichment/epss/refresh          (sync, bubbles fetch errors as 502)
  POST /api/v1/enrichment/advisory-sources/copy (sync, copies NVD+GHSA creds)

All endpoints are gated on MANAGE_SETTINGS.
"""
from __future__ import annotations

import contextlib
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.enrichment.router import router as enrichment_router  # noqa: E402


_ADMIN_PERMS = {"manage_settings"}


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(enrichment_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-1"
        request.state.user_role = "admin"
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


@pytest.fixture
def client():
    return TestClient(_make_app())


@pytest.fixture
def forbidden_client():
    return TestClient(_make_app(allow_manage_settings=False))


# ---- OSV refresh ----

def test_osv_refresh_endpoint_returns_202(client):
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.enrichment.router._spawn_osv_refresh") as spawn:
        resp = client.post("/api/v1/enrichment/osv/refresh")

    assert resp.status_code == 202
    assert spawn.called


def test_osv_refresh_endpoint_403_without_permission(forbidden_client):
    with patch("src.authz.enforcement.dependencies.has_role_permission",
               return_value=False):
        resp = forbidden_client.post("/api/v1/enrichment/osv/refresh")

    assert resp.status_code == 403


# ---- status ----

class _FakeResult:
    def __init__(self, scalar_one):
        self._scalar_one = scalar_one

    def scalar_one_or_none(self):
        return self._scalar_one


class _FakeSession:
    """Minimal async session: one execute() for the last-run row, then scalar()
    calls in the endpoint's order (osv count, epss count, epss fetched, kev
    count, kev ingested)."""

    def __init__(self, run, scalars):
        self._run = run
        self._scalars = list(scalars)

    async def execute(self, _stmt):
        return _FakeResult(self._run)

    async def scalar(self, _stmt):
        return self._scalars.pop(0)


def _fake_session_cm(run, scalars):
    @contextlib.asynccontextmanager
    async def _cm():
        yield _FakeSession(run, scalars)

    return _cm


def test_status_reports_feed_freshness_and_counts(client):
    run = SimpleNamespace(
        finished_at=datetime(2026, 7, 1, 2, 5, tzinfo=timezone.utc),
        started_at=datetime(2026, 7, 1, 2, 0, tzinfo=timezone.utc),
        error=None,
    )
    epss_fetched = datetime(2026, 7, 1, 3, 15, tzinfo=timezone.utc)
    kev_ingested = datetime(2026, 7, 1, 3, 0, tzinfo=timezone.utc)
    scalars = [84120, 250000, epss_fetched, 1300, kev_ingested]
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.enrichment.router.get_session", _fake_session_cm(run, scalars)):
        resp = client.get("/api/v1/enrichment/status")

    assert resp.status_code == 200
    body = resp.json()
    assert body["osv"]["advisories"] == 84120
    assert body["osv"]["lastRefreshedAt"] == "2026-07-01T02:05:00+00:00"
    assert body["osv"]["error"] is None
    assert body["epss"]["scores"] == 250000
    assert body["epss"]["lastRefreshedAt"] == "2026-07-01T03:15:00+00:00"
    assert body["kev"]["entries"] == 1300


def test_status_handles_never_refreshed_mirror(client):
    scalars = [0, 0, None, 0, None]
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.enrichment.router.get_session", _fake_session_cm(None, scalars)):
        resp = client.get("/api/v1/enrichment/status")

    assert resp.status_code == 200
    body = resp.json()
    assert body["osv"] == {"advisories": 0, "lastRefreshedAt": None, "startedAt": None, "error": None}
    assert body["epss"]["lastRefreshedAt"] is None
    assert body["kev"]["entries"] == 0


def test_status_403_without_permission(forbidden_client):
    with patch("src.authz.enforcement.dependencies.has_role_permission",
               return_value=False):
        resp = forbidden_client.get("/api/v1/enrichment/status")

    assert resp.status_code == 403


# ---- OSV reconcile ----

def test_osv_reconcile_endpoint_passes_mode_to_dispatcher(client):
    captured: dict = {}

    def fake_spawn(mode: str):
        captured["mode"] = mode

    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.enrichment.router._spawn_osv_reconcile", side_effect=fake_spawn):
        resp = client.post("/api/v1/enrichment/osv/reconcile?mode=full")

    assert resp.status_code == 202
    assert captured["mode"] == "full"


def test_osv_reconcile_endpoint_rejects_invalid_mode(client):
    if True:
        resp = client.post("/api/v1/enrichment/osv/reconcile?mode=nonsense")

    assert resp.status_code == 400


# ---- EPSS refresh ----

def test_epss_refresh_returns_result_on_success(client):
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.jobs.epss_refresh.refresh_epss_scores",
               return_value={"upserted": 42, "duration_ms": 1234}):
        resp = client.post("/api/v1/enrichment/epss/refresh")

    assert resp.status_code == 200
    assert resp.json() == {"upserted": 42, "duration_ms": 1234}


def test_epss_refresh_503_without_permission(forbidden_client):
    with patch("src.authz.enforcement.dependencies.has_role_permission",
               return_value=False):
        resp = forbidden_client.post("/api/v1/enrichment/epss/refresh")

    assert resp.status_code == 403


def test_epss_refresh_bubbles_fetch_errors_as_502(client):
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.jobs.epss_refresh.refresh_epss_scores",
               side_effect=RuntimeError("upstream feed unreachable")):
        resp = client.post("/api/v1/enrichment/epss/refresh")

    assert resp.status_code == 502
    assert "upstream feed unreachable" in resp.json()["detail"]


# ---- Advisory sources copy ----

def test_copy_advisory_sources_happy_path(client):
    cfg = {
        "tools": {
            "dependencies_scanning": {
                "nvdEnabled": True,
                "nvdApiKey": "nvd-key",
                "ghsaEnabled": True,
                "ghsaApiKey": "ghsa-key",
            },
            "container_scanning": {},
        }
    }
    written: dict = {}

    def fake_write(config, event_type=None):
        written["config"] = config
        written["event_type"] = event_type

    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.enrichment.router.read_app_config", return_value=cfg), \
         patch("src.enrichment.router.write_app_config", side_effect=fake_write):
        resp = client.post(
            "/api/v1/enrichment/advisory-sources/copy",
            json={"source": "dependencies_scanning", "target": "container_scanning"},
        )

    assert resp.status_code == 200
    target = written["config"]["tools"]["container_scanning"]
    assert target["nvdApiKey"] == "nvd-key"
    assert target["ghsaApiKey"] == "ghsa-key"
    assert written["event_type"] == "settings.advisory_sources_copied"


def test_copy_advisory_sources_rejects_same_source_target(client):
    if True:
        resp = client.post(
            "/api/v1/enrichment/advisory-sources/copy",
            json={"source": "dependencies_scanning", "target": "dependencies_scanning"},
        )

    assert resp.status_code == 400


def test_copy_advisory_sources_rejects_invalid_tool(client):
    if True:
        resp = client.post(
            "/api/v1/enrichment/advisory-sources/copy",
            json={"source": "invalid", "target": "container_scanning"},
        )

    assert resp.status_code == 400


def test_copy_advisory_sources_rejects_empty_source(client):
    cfg = {"tools": {"dependencies_scanning": {}, "container_scanning": {}}}
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.enrichment.router.read_app_config", return_value=cfg):
        resp = client.post(
            "/api/v1/enrichment/advisory-sources/copy",
            json={"source": "dependencies_scanning", "target": "container_scanning"},
        )

    assert resp.status_code == 400


def test_copy_advisory_sources_403_without_permission(forbidden_client):
    with patch("src.authz.enforcement.dependencies.has_role_permission",
               return_value=False):
        resp = forbidden_client.post(
            "/api/v1/enrichment/advisory-sources/copy",
            json={"source": "dependencies_scanning", "target": "container_scanning"},
        )

    assert resp.status_code == 403
