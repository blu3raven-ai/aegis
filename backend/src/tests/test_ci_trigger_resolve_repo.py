"""CI trigger: resolve the source from the repo identity when no source_id is given.

Covers the auto-resolution path added so CI configs don't carry a source id:
- request validation (need source_id OR repo+source_type)
- invalid repo shape
- resolve an existing asset by external_ref
- auto-create for an unrestricted key
- reject auto-create for a source-scoped key
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.scans.ci_router import router as ci_router  # noqa: E402
from src.scans.service import ScanSubmission  # noqa: E402


def _make_app(state: dict) -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def _inject_state(request, call_next):
        for k, v in state.items():
            setattr(request.state, k, v)
        return await call_next(request)

    app.include_router(ci_router)
    return app


def _session_ctx(asset_obj):
    session = AsyncMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: asset_obj))
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


def _asset(asset_id: str):
    a = MagicMock()
    a.id = asset_id
    a.archived = False
    a.display_name = "acme-org/api"
    return a


def _submission(source_id: str) -> ScanSubmission:
    return ScanSubmission(
        scan_id=str(uuid.uuid4()),
        repo_id=source_id,
        commit_sha="abc12345",
        scanner_types=["dependencies_scanning"],
        status="queued",
        submitted_at=datetime(2026, 6, 21, tzinfo=timezone.utc),
        submitted_by="api_key:1",
    )


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets():
    from src.shared import rate_limit as rl
    with rl._lock:
        rl._buckets.clear()
    yield


_UNSCOPED = {"api_key_id": 1, "api_key_scopes": ["scan:trigger"], "api_key_allowed_source_ids": None}


def test_requires_source_id_or_repo():
    client = TestClient(_make_app(_UNSCOPED))
    resp = client.post("/api/v1/scans/ci", json={"commit_sha": "abc12345"})
    assert resp.status_code == 422  # pydantic validation


def test_invalid_repo_shape_400():
    client = TestClient(_make_app(_UNSCOPED))
    resp = client.post(
        "/api/v1/scans/ci",
        json={"repo": "no-slash", "source_type": "github", "commit_sha": "abc12345"},
    )
    assert resp.status_code == 400


def test_resolves_existing_asset_by_repo():
    src = str(uuid.uuid4())
    ctx = _session_ctx(_asset(src))
    with patch("src.scans.ci_router.get_session", return_value=ctx), \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
         patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(return_value=_submission(src))), \
         patch("src.scans.ci_router.cancel_older_queued_for_pr", new=AsyncMock(return_value=[])):
        client = TestClient(_make_app(_UNSCOPED))
        resp = client.post(
            "/api/v1/scans/ci",
            json={"repo": "acme-org/api", "source_type": "github", "commit_sha": "abc12345"},
        )
    assert resp.status_code == 202


def test_auto_creates_for_unscoped_key():
    new_id = str(uuid.uuid4())
    # First get_session (resolve) finds nothing; second (archived check) finds the created asset.
    contexts = [_session_ctx(None), _session_ctx(_asset(new_id))]
    with patch("src.scans.ci_router.get_session", side_effect=contexts), \
         patch("src.scans.ci_router.upsert_asset", new=AsyncMock(return_value=new_id)) as mock_upsert, \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
         patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(return_value=_submission(new_id))), \
         patch("src.scans.ci_router.cancel_older_queued_for_pr", new=AsyncMock(return_value=[])):
        client = TestClient(_make_app(_UNSCOPED))
        resp = client.post(
            "/api/v1/scans/ci",
            json={"repo": "acme-org/api", "source_type": "github", "commit_sha": "abc12345"},
        )
    assert resp.status_code == 202
    mock_upsert.assert_awaited_once()


def test_scoped_key_cannot_auto_create():
    state = {"api_key_id": 1, "api_key_scopes": ["scan:trigger"], "api_key_allowed_source_ids": [str(uuid.uuid4())]}
    with patch("src.scans.ci_router.get_session", return_value=_session_ctx(None)), \
         patch("src.scans.ci_router.upsert_asset", new=AsyncMock()) as mock_upsert:
        client = TestClient(_make_app(state))
        resp = client.post(
            "/api/v1/scans/ci",
            json={"repo": "acme-org/api", "source_type": "github", "commit_sha": "abc12345"},
        )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "source_not_in_scope"
    mock_upsert.assert_not_awaited()
