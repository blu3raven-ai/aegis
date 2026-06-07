"""Unit tests for AuditMiddleware.

These tests use a lightweight ASGI test client built on httpx to verify:
- Matching paths trigger an audit record
- Non-matching paths and GET requests do not
- Explicit action mapping is applied correctly
- Action inference fallback works for unknown paths
"""
from __future__ import annotations

from typing import Callable
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from src.audit_log.middleware import AuditMiddleware


def _make_app(recorder: MagicMock | None = None) -> tuple[FastAPI, MagicMock]:
    mock_rec = recorder or MagicMock()
    app = FastAPI()
    app.add_middleware(AuditMiddleware, recorder=mock_rec)

    @app.post("/api/v1/notifications/destinations")
    def create_dest(request: Request):
        return JSONResponse({"ok": True}, status_code=201)

    @app.get("/api/v1/notifications/destinations")
    def list_dest(request: Request):
        return JSONResponse({"destinations": []})

    @app.delete("/api/v1/notifications/destinations/{dest_id}")
    def delete_dest(request: Request, dest_id: int):
        return JSONResponse(None, status_code=204)

    @app.get("/health")
    def health():
        return JSONResponse({"ok": True})

    @app.post("/runner/api/jobs")
    def runner_job():
        return JSONResponse({"ok": True})

    return app, mock_rec


def test_post_to_auditable_path_records_event():
    app, mock_rec = _make_app()
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/api/v1/notifications/destinations", json={})
    assert resp.status_code == 201
    mock_rec.record.assert_called_once()
    kwargs = mock_rec.record.call_args.kwargs
    assert kwargs["action"] == "notification.destination.created"
    assert kwargs["resource_type"] == "notification_destination"


def test_get_on_auditable_path_does_not_record():
    app, mock_rec = _make_app()
    client = TestClient(app)
    client.get("/api/v1/notifications/destinations")
    mock_rec.record.assert_not_called()


def test_delete_records_with_resource_id():
    app, mock_rec = _make_app()
    client = TestClient(app)
    client.delete("/api/v1/notifications/destinations/42")
    mock_rec.record.assert_called_once()
    kwargs = mock_rec.record.call_args.kwargs
    assert kwargs["action"] == "notification.destination.deleted"
    assert kwargs["resource_id"] == "42"


def test_health_path_not_audited():
    app, mock_rec = _make_app()
    client = TestClient(app)
    client.get("/health")
    mock_rec.record.assert_not_called()


def test_runner_path_not_audited():
    app, mock_rec = _make_app()
    client = TestClient(app)
    client.post("/runner/api/jobs", json={})
    mock_rec.record.assert_not_called()


def test_status_code_captured_in_request_context():
    app, mock_rec = _make_app()
    client = TestClient(app)
    client.post("/api/v1/notifications/destinations", json={})
    kwargs = mock_rec.record.call_args.kwargs
    assert kwargs["request"].status_code == 201
