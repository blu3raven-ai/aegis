"""Tests for the KEV API router endpoint shapes.

Mounts only the KEV router on a minimal FastAPI app (no JWT middleware) so
tests are fast, isolated from auth, and free of DB dependencies.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.db.models import KevEntry
from src.kev.router import router as kev_router


def _make_app() -> FastAPI:
    """Minimal app — only the KEV router, no auth middleware."""
    app = FastAPI()
    app.include_router(kev_router)
    return app


def _make_entry(**kwargs) -> KevEntry:
    entry = KevEntry()
    entry.cve_id = kwargs.get("cve_id", "CVE-2024-12345")
    entry.vendor_project = kwargs.get("vendor_project", "Example Vendor")
    entry.product = kwargs.get("product", "Example Product")
    entry.vulnerability_name = kwargs.get("vulnerability_name", "Test RCE")
    entry.date_added = kwargs.get("date_added", date(2024, 1, 15))
    entry.short_description = kwargs.get("short_description", "A critical RCE.")
    entry.required_action = kwargs.get("required_action", "Apply patch.")
    entry.due_date = kwargs.get("due_date", date(2024, 2, 1))
    entry.known_ransomware_use = kwargs.get("known_ransomware_use", True)
    entry.notes = kwargs.get("notes", "")
    entry.cwes = kwargs.get("cwes", ["CWE-77"])
    entry.ingested_at = kwargs.get("ingested_at", datetime(2024, 1, 15, 12, 0, tzinfo=timezone.utc))
    return entry


@patch("src.kev.router._service")
def test_get_entry_found(mock_svc):
    mock_svc.get_entry.return_value = _make_entry()
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/kev/CVE-2024-12345")
    assert resp.status_code == 200
    data = resp.json()
    assert data["cve_id"] == "CVE-2024-12345"
    assert data["vendor_project"] == "Example Vendor"
    assert data["known_ransomware_use"] is True


@patch("src.kev.router._service")
def test_get_entry_not_found(mock_svc):
    mock_svc.get_entry.return_value = None
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/kev/CVE-9999-00000")
    assert resp.status_code == 404
    assert "not in the CISA KEV catalog" in resp.json()["detail"]


@patch("src.kev.router._service")
def test_list_recent(mock_svc):
    entries = [_make_entry(cve_id=f"CVE-2024-{i}") for i in range(3)]
    mock_svc.list_recent.return_value = entries
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/kev/recent?days=7")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 3
    assert len(data["entries"]) == 3


@patch("src.kev.router._service")
def test_exposure_summary(mock_svc):
    mock_svc.get_exposure_summary.return_value = {
        "open_findings_total": 100,
        "open_findings_in_kev": 5,
        "kev_overdue": 2,
        "kev_with_ransomware": 1,
        "top_kev_findings": [],
    }
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/kev/exposure-summary?org=example-org")
    assert resp.status_code == 200
    data = resp.json()
    assert data["open_findings_total"] == 100
    assert data["open_findings_in_kev"] == 5


@patch("src.kev.router._service")
def test_exposure_summary_missing_org(mock_svc):
    """org query parameter is required — 422 if missing."""
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/kev/exposure-summary")
    assert resp.status_code == 422


@patch("src.kev.router._service")
def test_entry_fields_serialized(mock_svc):
    """All expected fields appear in a GET /{cve_id} response."""
    mock_svc.get_entry.return_value = _make_entry()
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/kev/CVE-2024-12345")
    data = resp.json()
    for field in ("cve_id", "vendor_project", "product", "vulnerability_name",
                  "date_added", "due_date", "known_ransomware_use", "cwes", "ingested_at"):
        assert field in data, f"Missing field: {field}"
