"""Tests for BYO import → ScanRun envelope wiring (/api/v1/scans/import).

BYO findings arrive out-of-band, so each imported target gets a terminal
``completed`` ScanRun envelope (no runner dispatch) so the import shows up at
/scans/{id} and in the scan trail like a scanner-triggered run.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SOURCES, RUN_SCANS  # noqa: E402
from src.scans import byo_router as byo_module  # noqa: E402
from src.scans.byo_router import router as byo_router  # noqa: E402
from src.scans.service import record_byo_scan_run  # noqa: E402


class _FakeResult:
    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class _FakeSession:
    """Captures added ScanRun rows and serves scripted rowcounts for inserts."""

    def __init__(self, rowcounts: list[int] | None = None) -> None:
        self.added: list = []
        self.committed = False
        self._rowcounts = list(rowcounts) if rowcounts is not None else None
        self._exec_calls = 0

    async def execute(self, _stmt):
        rc = 1
        if self._rowcounts is not None and self._exec_calls < len(self._rowcounts):
            rc = self._rowcounts[self._exec_calls]
        self._exec_calls += 1
        return _FakeResult(rc)

    def add(self, row) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:  # pragma: no cover - defensive
        pass


def _make_app(fake: _FakeSession) -> FastAPI:
    app = FastAPI()
    app.include_router(byo_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    async def _override_db():
        yield fake

    app.dependency_overrides[byo_module._db] = _override_db
    app.dependency_overrides[Permission(RUN_SCANS, MANAGE_SOURCES)] = lambda: None
    return app


def test_record_byo_scan_run_builds_completed_envelope():
    """The helper adds one terminal, completed ScanRun row tagged source=byo."""
    fake = _FakeSession()
    scan_id = asyncio.run(record_byo_scan_run(
        fake,
        asset_id="asset-1",
        display_name="acme-org/repo-1",
        scanner="trivy",
        finding_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        user_id="u-1",
    ))

    assert scan_id.startswith("scan-")
    assert len(fake.added) == 1
    row = fake.added[0]
    assert row.id == scan_id
    assert row.tool == "byo_import"
    assert row.status == "completed"
    assert row.asset_id == "asset-1"
    # Instantaneous terminal envelope — born started+finished at the same instant.
    assert row.started_at is not None
    assert row.started_at == row.finished_at
    assert row.error is None
    assert row.metadata_json["source"] == "byo"
    assert row.metadata_json["scanner_types"] == ["trivy"]
    assert row.metadata_json["submitted_by"] == "u-1"
    assert row.metadata_json["repo_id"] == "acme-org/repo-1"
    assert row.progress["finding_counts"]["critical"] == 1


def test_byo_import_creates_one_envelope_per_target_with_per_asset_counts():
    """Import with 2 targets → 2 ScanRun envelopes; only new findings are tallied."""
    fake = _FakeSession(rowcounts=[1, 1, 1, 0])  # last finding is a dedup no-op

    payload = {
        "scanner": "trivy",
        "targets": [
            {"type": "repo", "source_type": "github", "owner": "acme-org", "name": "repo-1"},
            {"type": "image", "registry": "ghcr", "image": "acme-org/app", "tag": "v1"},
        ],
        "findings": [
            {"target_index": 0, "identity_key": "CVE-1", "tool": "trivy", "severity": "CRITICAL"},
            {"target_index": 0, "identity_key": "CVE-2", "tool": "trivy", "severity": "high"},
            {"target_index": 1, "identity_key": "CVE-3", "tool": "trivy", "severity": "medium"},
            {"target_index": 1, "identity_key": "CVE-3", "tool": "trivy", "severity": "low"},
        ],
    }

    with patch("src.scans.byo_router.upsert_asset",
               new=AsyncMock(side_effect=["asset-1", "asset-2"])), \
         patch("src.scans.byo_router.auto_grant_to_uploader", new=AsyncMock(return_value=None)), \
         patch("src.audit_log.recorder.get_recorder", return_value=MagicMock()):
        client = TestClient(_make_app(fake))
        resp = client.post("/api/v1/scans/import", json=payload)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["assets"] == ["asset-1", "asset-2"]
    assert body["findings_created"] == 3  # the duplicate low finding is not counted
    assert len(body["scan_runs"]) == 2
    assert fake.committed is True

    # One ScanRun envelope per target, in target order, with per-asset severity tallies.
    runs = fake.added
    assert len(runs) == 2
    assert [r.asset_id for r in runs] == ["asset-1", "asset-2"]
    assert all(r.tool == "byo_import" and r.status == "completed" for r in runs)
    assert runs[0].progress["finding_counts"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    # The deduped 'low' finding (rowcount 0) is excluded; only the new 'medium' counts.
    assert runs[1].progress["finding_counts"] == {"critical": 0, "high": 0, "medium": 1, "low": 0}
    assert runs[1].metadata_json["repo_id"] == "acme-org/app:v1"


def test_byo_import_invalid_target_index_returns_400():
    fake = _FakeSession()
    payload = {
        "scanner": "trivy",
        "targets": [
            {"type": "repo", "source_type": "github", "owner": "acme-org", "name": "repo-1"},
        ],
        "findings": [
            {"target_index": 5, "identity_key": "CVE-1", "tool": "trivy", "severity": "high"},
        ],
    }
    with patch("src.scans.byo_router.upsert_asset",
               new=AsyncMock(side_effect=["asset-1"])), \
         patch("src.scans.byo_router.auto_grant_to_uploader", new=AsyncMock(return_value=None)), \
         patch("src.audit_log.recorder.get_recorder", return_value=MagicMock()):
        client = TestClient(_make_app(fake))
        resp = client.post("/api/v1/scans/import", json=payload)

    assert resp.status_code == 400
    assert "invalid target_index" in resp.json()["detail"]
