"""Tests for the /health router — shape, status codes, env-var reflection."""
from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.health.router import router as health_router


def _make_app(**state_attrs) -> FastAPI:
    """Minimal FastAPI app that mounts only the health router."""
    app = FastAPI()
    app.include_router(health_router)
    for k, v in state_attrs.items():
        setattr(app.state, k, v)
    return app


@pytest.fixture()
def client(monkeypatch):
    """Default client — no env vars set beyond defaults."""
    monkeypatch.delenv("AEGIS_CORRELATION_ENABLED", raising=False)
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("JOB_QUEUE_BACKEND", raising=False)
    monkeypatch.delenv("RUNNER_DISPATCH_MODE", raising=False)
    app = _make_app()
    return TestClient(app)


class TestHealthCheck:
    def test_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_status_is_ok(self, client):
        data = resp = client.get("/health").json()
        assert data["status"] == "ok"

    def test_timestamp_present(self, client):
        data = client.get("/health").json()
        assert "timestamp" in data
        # ISO 8601 format — ends with +00:00 or Z
        ts = data["timestamp"]
        assert "T" in ts

    def test_components_shape(self, client):
        data = client.get("/health").json()
        components = data["components"]
        assert set(components.keys()) == {"correlation_engine", "argus", "queue_backend", "runner"}

    def test_defaults_correlation_dormant(self, client):
        data = client.get("/health").json()
        ce = data["components"]["correlation_engine"]
        assert ce["enabled"] is False
        assert ce["status"] == "dormant"

    def test_defaults_argus_disabled(self, client):
        data = client.get("/health").json()
        argus = data["components"]["argus"]
        assert argus["endpoint_configured"] is False
        assert argus["status"] == "disabled-fallback-heuristics"

    def test_defaults_queue_backend_file(self, client):
        data = client.get("/health").json()
        assert data["components"]["queue_backend"]["backend"] == "file"

    def test_defaults_runner_modes(self, client):
        data = client.get("/health").json()
        runner = data["components"]["runner"]
        assert runner["dispatch_mode"] == "poll"

    def test_correlation_enabled_via_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", "true")
        app = _make_app()
        with TestClient(app) as c:
            data = c.get("/health").json()
        ce = data["components"]["correlation_engine"]
        assert ce["enabled"] is True
        assert ce["status"] == "running"

    def test_argus_endpoint_configured(self, monkeypatch):
        monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
        app = _make_app()
        with TestClient(app) as c:
            data = c.get("/health").json()
        argus = data["components"]["argus"]
        assert argus["endpoint_configured"] is True
        assert argus["status"] == "connected"

    def test_queue_backend_env(self, monkeypatch):
        monkeypatch.setenv("JOB_QUEUE_BACKEND", "postgres")
        app = _make_app()
        with TestClient(app) as c:
            data = c.get("/health").json()
        assert data["components"]["queue_backend"]["backend"] == "postgres"

    def test_runner_modes_env(self, monkeypatch):
        monkeypatch.setenv("RUNNER_DISPATCH_MODE", "subscription")
        app = _make_app()
        with TestClient(app) as c:
            data = c.get("/health").json()
        runner = data["components"]["runner"]
        assert runner["dispatch_mode"] == "subscription"

    def test_live_engine_state_reflected(self, monkeypatch):
        """When app.state.correlation_engine is set, is_running drives status."""
        monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", "true")

        class _FakeEngine:
            is_running = True

        app = _make_app(correlation_engine=_FakeEngine())
        with TestClient(app) as c:
            data = c.get("/health").json()
        assert data["components"]["correlation_engine"]["status"] == "running"

    def test_stopped_engine_state_reflected(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", "true")

        class _FakeEngine:
            is_running = False

        app = _make_app(correlation_engine=_FakeEngine())
        with TestClient(app) as c:
            data = c.get("/health").json()
        assert data["components"]["correlation_engine"]["status"] == "stopped"


class TestReadinessCheck:
    def test_returns_200(self, client):
        assert client.get("/health/ready").status_code == 200

    def test_ready_true(self, client):
        assert client.get("/health/ready").json() == {"ready": True}


class TestLivenessCheck:
    def test_returns_200(self, client):
        assert client.get("/health/live").status_code == 200

    def test_alive_true(self, client):
        assert client.get("/health/live").json() == {"alive": True}
