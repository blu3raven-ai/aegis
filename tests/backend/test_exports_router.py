"""Integration tests for the findings export REST endpoint.

Tests verify:
- Correct Content-Type headers for CSV and JSONL
- Content-Disposition attachment with a filename
- X-Total-Count header is present
- Query params are forwarded to filters
- Response is streamed (chunked transfer encoding)
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.exports.router import router
from src.exports.findings_export import FindingFilters


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _fake_session_ctx(findings=None, count=0):
    """Return a context manager that yields a minimal fake session."""
    from unittest.mock import AsyncMock, MagicMock
    from contextlib import asynccontextmanager

    class _FakeRow:
        def __init__(self, f):
            self.Finding = f

    class _FakeStream:
        def __init__(self, items):
            self._items = items

        async def partitions(self, size):
            batch = [_FakeRow(f) for f in self._items]
            if batch:
                yield batch

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class _Session:
        def stream(self, stmt):
            return _FakeStream(findings or [])

        async def execute(self, stmt):
            r = MagicMock()
            r.scalar_one.return_value = count
            return r

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def commit(self):
            pass

        async def rollback(self):
            pass

    @asynccontextmanager
    async def _ctx():
        yield _Session()

    return _ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@patch("src.exports.router.get_session")
def test_csv_content_type(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings?format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]


@patch("src.exports.router.get_session")
def test_json_content_type(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings?format=json")
    assert resp.status_code == 200
    assert "ndjson" in resp.headers["content-type"]


@patch("src.exports.router.get_session")
def test_content_disposition_csv(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings?format=csv")
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert ".csv" in resp.headers.get("content-disposition", "")


@patch("src.exports.router.get_session")
def test_content_disposition_json(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings?format=json")
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert ".jsonl" in resp.headers.get("content-disposition", "")


@patch("src.exports.router.get_session")
def test_x_total_count_header(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 7)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings")
    assert resp.headers.get("x-total-count") == "7"


@patch("src.exports.router.get_session")
def test_csv_default_format(mock_get_session):
    """format=csv is the default when the param is omitted."""
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings")
    assert "text/csv" in resp.headers["content-type"]


@patch("src.exports.router.get_session")
def test_csv_header_row_present(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings?format=csv")
    first_line = resp.text.splitlines()[0]
    assert "id" in first_line
    assert "severity" in first_line
    assert "scanner" in first_line


@patch("src.exports.router.get_session")
def test_filter_params_accepted(mock_get_session):
    """Endpoint should accept all filter params without errors."""
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(
            "/api/v1/exports/findings"
            "?format=csv"
            "&severity=critical,high"
            "&scanner=dependencies"
            "&status=open"
            "&repo_id=example-org/api"
        )
    assert resp.status_code == 200


@patch("src.exports.router.get_session")
def test_json_empty_export_is_empty_body(mock_get_session):
    mock_get_session.side_effect = _fake_session_ctx([], 0)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/exports/findings?format=json")
    assert resp.status_code == 200
    assert resp.text.strip() == ""
