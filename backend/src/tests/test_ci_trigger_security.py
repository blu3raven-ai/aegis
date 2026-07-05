"""Security checks on the CI trigger endpoint.

Tests cover:
1. Scope enforcement — API key without scan:trigger is rejected 403 missing_scope.
2. Source allowlist — key scoped to src_a is blocked from src_b (403 source_not_in_scope).
3. Scope isolation — scan:trigger key fails view_findings check at the helper level.
4. Audit trail — successful trigger writes an AuditEvent row with correct fields.

Test 5 (PAT leakage via api_keys router) is omitted: the api_keys router requires
a real session cookie (authenticated browser session) which needs the full auth
middleware stack. The field-level check (token_hash not in API response) is better
covered by an e2e or router-level test that has session fixture support. No
existing test in this directory exercises the api_keys router directly, so there
is no safe precedent to adapt without introducing significant test-infrastructure
complexity beyond the scope of this task.
"""
from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.auth.credentials.auth import require_scope_and_source  # noqa: E402
from src.db.engine import DATABASE_URL  # noqa: E402
from src.db.models import Asset, AuditEvent, ScanRun  # noqa: E402
from src.scans.ci_router import router as ci_router  # noqa: E402



def _make_app(state: dict | None = None) -> FastAPI:
    app = FastAPI()
    if state is not None:
        @app.middleware("http")
        async def _inject_state(request, call_next):
            for k, v in state.items():
                setattr(request.state, k, v)
            return await call_next(request)
    app.include_router(ci_router)
    return app


def _fake_asset(asset_id: str, archived: bool = False) -> MagicMock:
    asset = MagicMock()
    asset.id = asset_id
    asset.archived = archived
    asset.display_name = "acme-org/api"
    return asset


def _mock_session_ctx(asset_obj):
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: asset_obj)
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    return mock_ctx


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets():
    from src.shared import rate_limit as rl
    with rl._lock:
        rl._buckets.clear()
    yield



def test_api_key_without_scope_blocked():
    """API key lacking scan:trigger scope returns 403 missing_scope."""
    state = {
        "api_key_id": 1,
        "api_key_scopes": ["view_findings"],
        "api_key_allowed_source_ids": None,
    }
    client = TestClient(_make_app(state))
    resp = client.post(
        "/api/v1/scans/ci",
        json={"source_id": str(uuid.uuid4()), "commit_sha": "abc12345"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["error"] == "missing_scope"
    assert body["detail"]["missing_scope"] == "scan:trigger"


def test_source_allowlist_blocks_other_sources():
    """allowed_source_ids enforced: source not in list → 403 source_not_in_scope."""
    src_a = str(uuid.uuid4())
    src_b = str(uuid.uuid4())
    state = {
        "api_key_id": 1,
        "api_key_scopes": ["scan:trigger"],
        "api_key_allowed_source_ids": [src_a],
    }

    # src_b is blocked at scope check — no DB lookup needed
    client = TestClient(_make_app(state))
    resp = client.post(
        "/api/v1/scans/ci",
        json={"source_id": src_b, "commit_sha": "abc12345"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["error"] == "source_not_in_scope"
    assert body["detail"]["source_id"] == src_b


def test_source_allowlist_permits_listed_source():
    """allowed_source_ids: source in list proceeds past scope check (mocked DB)."""
    src_a = str(uuid.uuid4())
    state = {
        "api_key_id": 1,
        "api_key_scopes": ["scan:trigger"],
        "api_key_allowed_source_ids": [src_a],
    }
    asset = _fake_asset(src_a)
    mock_ctx = _mock_session_ctx(asset)

    from src.scans.service import ScanSubmission
    from datetime import datetime, timezone
    submission = ScanSubmission(
        scan_id=str(uuid.uuid4()),
        repo_id=src_a,
        commit_sha="abc12345",
        scanner_types=["dependencies_scanning"],
        status="queued",
        submitted_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
        submitted_by="api_key:1",
    )

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
         patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(return_value=submission)), \
         patch("src.scans.ci_router.cancel_older_queued_for_pr", new=AsyncMock(return_value=[])):
        client = TestClient(_make_app(state))
        resp = client.post(
            "/api/v1/scans/ci",
            json={"source_id": src_a, "commit_sha": "abc12345"},
        )

    assert resp.status_code == 202


def test_scan_trigger_scope_does_not_grant_other_scopes():
    """A key with only scan:trigger fails the view_findings scope check."""
    class _K:
        scopes = ["scan:trigger"]
        allowed_source_ids = None

    err = require_scope_and_source(_K(), scope="view_findings", source_id="any")
    assert err is not None
    assert err["error"] == "missing_scope"
    assert err["missing_scope"] == "view_findings"


@pytest.mark.asyncio
async def test_audit_event_recorded_on_trigger(db_session, monkeypatch):
    """Successful trigger writes an AuditEvent row with action='scan.triggered'."""
    asset_id = str(uuid.uuid4())
    asset = Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        external_ref=f"github.com/acme-org/api-{asset_id[:8]}",
        display_name="acme-org/api",
    )
    db_session.add(asset)
    await db_session.commit()

    try:
        # Give service and router their own engines bound to the current event loop
        engine_a = create_async_engine(DATABASE_URL, echo=False)
        engine_b = create_async_engine(DATABASE_URL, echo=False)
        factory_a = async_sessionmaker(engine_a, class_=AsyncSession, expire_on_commit=False)
        factory_b = async_sessionmaker(engine_b, class_=AsyncSession, expire_on_commit=False)

        @asynccontextmanager
        async def _get_session_a():
            async with factory_a() as s:
                yield s

        @asynccontextmanager
        async def _get_session_b():
            async with factory_b() as s:
                yield s

        monkeypatch.setattr("src.scans.service.get_session", _get_session_a)
        monkeypatch.setattr("src.scans.ci_router.get_session", _get_session_b)
        monkeypatch.setattr("src.scans.service._dispatch_scanner_jobs", lambda *a, **k: None)

        state = {
            "api_key_id": 42,
            "api_key_scopes": ["scan:trigger"],
            "api_key_allowed_source_ids": None,
        }
        client = TestClient(_make_app(state))
        resp = client.post(
            "/api/v1/scans/ci",
            json={"source_id": asset_id, "commit_sha": "abc12345"},
        )
        assert resp.status_code == 202, resp.text
        scan_id = resp.json()["scan_id"]

        # Verify the audit event row
        result = await db_session.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "scan.triggered")
            .where(AuditEvent.resource_id == scan_id)
        )
        evt = result.scalar_one_or_none()
        assert evt is not None, "Expected AuditEvent row with action='scan.triggered'"
        assert evt.actor_user_id == "api_key:42"
        assert (evt.metadata_json or {}).get("triggered_by") == "ci"

    finally:
        scan_ids = (
            await db_session.execute(select(ScanRun.id).where(ScanRun.asset_id == asset_id))
        ).scalars().all()
        if scan_ids:
            await db_session.execute(
                delete(AuditEvent).where(AuditEvent.resource_id.in_(scan_ids))
            )
        await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()
        await engine_a.dispose()
        await engine_b.dispose()
