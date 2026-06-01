"""Integration tests for POST /api/v1/decisions/go-no-go.

Patches the service entry point so we focus on HTTP concerns: request
parsing, validation status codes, and the response envelope.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from src.decisions.router import router as decisions_router  # noqa: E402


def _make_app() -> TestClient:
    app = FastAPI()
    app.include_router(decisions_router)

    @app.middleware("http")
    async def inject_state(request: Request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_role = "owner"
        return await call_next(request)

    return TestClient(app, raise_server_exceptions=True)


def _allow_response() -> dict:
    return {
        "decision": "allow",
        "blockers": [],
        "rationale": "No open findings at severity: critical.",
        "source": "backend",
    }


def _block_response() -> dict:
    return {
        "decision": "block",
        "blockers": [
            {
                "id": "1",
                "tool": "dependencies",
                "severity": "critical",
                "state": "open",
                "repo": "acme-org/api",
                "identity_key": "key-1",
                "title": "log4j RCE",
                "cve": "CVE-2021-44228",
            }
        ],
        "rationale": "1 open finding(s) at or above required severity (critical).",
        "source": "backend",
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_go_no_go_returns_200_allow_envelope():
    client = _make_app()
    with patch(
        "src.decisions.router._service.evaluate", new_callable=AsyncMock
    ) as svc:
        svc.return_value = _allow_response()
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={"org_id": "acme-org"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["blockers"] == []
    assert body["source"] == "backend"


def test_go_no_go_returns_200_block_envelope():
    client = _make_app()
    with patch(
        "src.decisions.router._service.evaluate", new_callable=AsyncMock
    ) as svc:
        svc.return_value = _block_response()
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={"org_id": "acme-org", "repo": "acme-org/api"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "block"
    assert len(body["blockers"]) == 1
    assert body["blockers"][0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


def test_repo_optional_defaults_to_none():
    client = _make_app()
    captured: dict = {}

    async def _capture(*, org_id, repo, policy, session):
        captured["org_id"] = org_id
        captured["repo"] = repo
        return _allow_response()

    with patch(
        "src.decisions.router._service.evaluate", side_effect=_capture
    ):
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={"org_id": "acme-org"},
        )
    assert resp.status_code == 200
    assert captured["org_id"] == "acme-org"
    assert captured["repo"] is None


def test_policy_block_on_pass_through():
    client = _make_app()
    captured: dict = {}

    async def _capture(*, org_id, repo, policy, session):
        captured["policy"] = policy
        return _allow_response()

    with patch(
        "src.decisions.router._service.evaluate", side_effect=_capture
    ):
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={
                "org_id": "acme-org",
                "policy": {"block_on": ["critical", "high"]},
            },
        )
    assert resp.status_code == 200
    assert captured["policy"].block_on == ("critical", "high")


# ---------------------------------------------------------------------------
# Validation — missing org_id → 422, bad policy → 400
# ---------------------------------------------------------------------------


def test_missing_org_id_returns_422():
    client = _make_app()
    resp = client.post("/api/v1/decisions/go-no-go", json={})
    assert resp.status_code == 422


def test_empty_org_id_returns_422():
    client = _make_app()
    resp = client.post("/api/v1/decisions/go-no-go", json={"org_id": ""})
    assert resp.status_code == 422


def test_bad_policy_shape_returns_400():
    client = _make_app()
    resp = client.post(
        "/api/v1/decisions/go-no-go",
        json={"org_id": "acme-org", "policy": {"block_on": ["bogus-severity"]}},
    )
    assert resp.status_code == 400
    assert "severity" in resp.json()["detail"].lower()


def test_bad_policy_type_returns_422():
    """policy must be an object — FastAPI rejects non-object before service runs."""
    client = _make_app()
    resp = client.post(
        "/api/v1/decisions/go-no-go",
        json={"org_id": "acme-org", "policy": "critical"},
    )
    assert resp.status_code == 422


def test_service_value_error_returns_400():
    client = _make_app()
    with patch(
        "src.decisions.router._service.evaluate", new_callable=AsyncMock
    ) as svc:
        svc.side_effect = ValueError("org_id is required")
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={"org_id": "acme-org"},
        )
    assert resp.status_code == 400
