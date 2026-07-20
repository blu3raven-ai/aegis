"""Tests for the health endpoints — shape, status codes, probe reflection, and
the authenticated/unauthenticated split."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.health.probes import ProbeResult
from src.health.router import router as health_router


@pytest.fixture(autouse=True)
def _grant_manage_settings(monkeypatch):
    # /health now requires MANAGE_SETTINGS; grant it so the probe-shape tests can
    # reach the detail endpoint. The denial case re-patches this to False.
    monkeypatch.setattr(
        "src.authz.enforcement.dependencies.has_role_permission", lambda *a, **k: True
    )


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(health_router)
    return app


def _make_probe(name: str, status: str, error: str | None = None) -> ProbeResult:
    return ProbeResult(name=name, status=status, duration_ms=10, details={"test": True}, error=error)


PROBE_NAMES = ["postgres", "minio", "connected_runners", "recent_scans", "correlation_engine", "argus"]


class TestDeepHealthEndpoint:
    def test_returns_200_when_all_ok(self):
        all_ok = [_make_probe(n, "ok") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=all_ok)):
            with TestClient(app) as c:
                resp = c.get("/health")
        assert resp.status_code == 200

    def test_returns_200_even_when_probes_fail(self):
        mixed = [_make_probe(n, "fail", "something broke") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=mixed)):
            with TestClient(app) as c:
                resp = c.get("/health")
        assert resp.status_code == 200

    def test_overall_status_ok_when_all_ok_or_skipped(self):
        results = [_make_probe("postgres","ok"),_make_probe("minio","ok"),
                   _make_probe("connected_runners","skipped"),_make_probe("recent_scans","ok"),
                   _make_probe("correlation_engine","skipped"),_make_probe("argus","skipped")]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=results)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        assert data["status"] == "ok"

    def test_overall_status_degraded_when_some_degraded(self):
        results = [_make_probe("postgres","ok"),_make_probe("minio","ok"),
                   _make_probe("connected_runners","degraded"),_make_probe("recent_scans","degraded"),
                   _make_probe("correlation_engine","skipped"),_make_probe("argus","skipped")]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=results)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        assert data["status"] == "degraded"

    def test_overall_status_fail_when_any_critical_fails(self):
        results = [_make_probe("postgres","fail","connection refused"),
                   _make_probe("minio","ok"),_make_probe("connected_runners","skipped"),
                   _make_probe("recent_scans","ok"),_make_probe("correlation_engine","skipped"),
                   _make_probe("argus","skipped")]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=results)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        assert data["status"] == "fail"

    def test_fail_takes_precedence_over_degraded(self):
        results = [_make_probe("postgres","fail","timeout"),
                   _make_probe("minio","degraded"),_make_probe("connected_runners","skipped"),
                   _make_probe("recent_scans","skipped"),_make_probe("correlation_engine","skipped"),
                   _make_probe("argus","skipped")]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=results)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        assert data["status"] == "fail"

    def test_response_shape_contains_required_keys(self):
        all_ok = [_make_probe(n, "ok") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=all_ok)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        assert "status" in data
        assert "timestamp" in data
        assert "probes" in data
        assert isinstance(data["probes"], list)

    def test_response_contains_all_probes(self):
        all_ok = [_make_probe(n, "ok") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=all_ok)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        returned_names = {p["name"] for p in data["probes"]}
        assert returned_names == set(PROBE_NAMES)

    def test_each_probe_entry_has_required_fields(self):
        all_ok = [_make_probe(n, "ok") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=all_ok)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        for probe in data["probes"]:
            assert "name" in probe and "status" in probe and "duration_ms" in probe
            assert "details" in probe and "error" in probe

    def test_probe_error_is_reflected_in_response(self):
        results = [_make_probe(n, "ok") for n in PROBE_NAMES]
        results[1] = _make_probe("minio", "fail", "connection refused")
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=results)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        minio_probe = next(p for p in data["probes"] if p["name"] == "minio")
        assert minio_probe["status"] == "fail"
        assert minio_probe["error"] == "connection refused"

    def test_timestamp_is_iso_format(self):
        all_ok = [_make_probe(n, "ok") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=all_ok)):
            with TestClient(app) as c:
                data = c.get("/health").json()
        assert "T" in data["timestamp"]


class TestHealthzLeak:
    """The unauthenticated liveness probe must not expose internals."""

    def test_healthz_returns_status_only(self):
        # A failing probe carries a leaky error + details; /healthz must surface
        # none of it — only the overall status.
        results = [_make_probe(n, "ok") for n in PROBE_NAMES]
        results[0] = _make_probe("argus", "fail", "connection refused: 10.0.4.21:5432")
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=results)):
            with TestClient(app) as c:
                resp = c.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data.keys()) == {"status"}
        assert data["status"] == "fail"
        # No probe internals or error strings anywhere in the body.
        assert "probes" not in data
        assert "10.0.4.21" not in resp.text

    def test_health_detail_requires_manage_settings(self, monkeypatch):
        monkeypatch.setattr(
            "src.authz.enforcement.dependencies.has_role_permission", lambda *a, **k: False
        )
        all_ok = [_make_probe(n, "ok") for n in PROBE_NAMES]
        app = _make_app()
        with patch("src.health.router.run_all_probes", new=AsyncMock(return_value=all_ok)):
            with TestClient(app) as c:
                resp = c.get("/health")
        assert resp.status_code == 403
