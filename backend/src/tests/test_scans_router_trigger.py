"""Tests for POST /api/v1/scans/ci.

Validation errors return 422 (FastAPI/pydantic default), not 400.
The plan describes "400 when commit_sha missing" — we accept 422 here since
FastAPI emits 422 Unprocessable Entity for body validation failures, which is
the correct HTTP semantics. Adding a custom exception handler to downgrade to
400 would be non-standard and is deliberately avoided.

DB-backed tests (dedup, force-push cancel) use a real testcontainer and seed
rows via the db_session fixture. They inject api_key state via middleware and
mock the asset lookup so the router never opens a second asyncpg connection in
the TestClient's sync thread — only the service functions interact with the DB,
and those are called directly via their own async context (within the
TestClient's anyio portal).
"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.db.models import ApiKey, Asset, ScanRun  # noqa: E402
from src.scans.ci_router import router as ci_router  # noqa: E402
from src.scans.service import ScanSubmission  # noqa: E402


_CI_URL = "/api/v1/scans/ci"


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


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _fake_asset(asset_id: str, archived: bool = False) -> MagicMock:
    asset = MagicMock()
    asset.id = asset_id
    asset.archived = archived
    asset.display_name = "acme-org/api"
    return asset


def _fake_submission(scan_id: str, source_id: str, commit_sha: str) -> ScanSubmission:
    return ScanSubmission(
        scan_id=scan_id,
        repo_id=source_id,
        commit_sha=commit_sha,
        scanner_types=["dependencies_scanning"],
        status="queued",
        submitted_at=datetime(2026, 6, 14, tzinfo=timezone.utc),
        submitted_by="api_key:1",
    )


_ANY_SOURCE = str(uuid.uuid4())

_DEFAULT_STATE = {
    "api_key_id": 1,
    "api_key_scopes": ["scan:trigger"],
    "api_key_allowed_source_ids": None,
}


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets():
    from src.shared import rate_limit as rl
    with rl._lock:
        rl._buckets.clear()
    yield


@pytest_asyncio.fixture
async def asset(db_session):
    """Seed a real Asset row for DB-backed tests; clean up on teardown."""
    asset_id = str(uuid.uuid4())
    row = Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        external_ref=f"github.com/acme-org/api-{asset_id[:8]}",
        display_name="acme-org/api",
    )
    db_session.add(row)
    await db_session.commit()
    yield row
    await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest_asyncio.fixture
async def api_key_row(db_session):
    """Seed a real ApiKey row; clean up on teardown."""
    raw_token = f"ak_test_{uuid.uuid4().hex}"
    row = ApiKey(
        name="test-ci-key",
        prefix=raw_token[:8],
        last_four=raw_token[-4:],
        token_hash=_token_hash(raw_token),
        scopes=["scan:trigger"],
        allowed_source_ids=None,
    )
    db_session.add(row)
    await db_session.commit()
    yield row, raw_token
    await db_session.execute(delete(ApiKey).where(ApiKey.id == row.id))
    await db_session.commit()


def test_401_when_no_api_key_state():
    """No api_key_id in request.state returns 401 (simulates non-API-key caller)."""
    client = TestClient(_make_app())
    resp = client.post(
        _CI_URL,
        json={"source_id": _ANY_SOURCE, "commit_sha": "abc12345"},
    )
    assert resp.status_code == 401


def test_422_when_commit_sha_missing():
    """Body without commit_sha returns 422 (FastAPI pydantic validation)."""
    client = TestClient(_make_app(_DEFAULT_STATE))
    resp = client.post(
        _CI_URL,
        json={"source_id": _ANY_SOURCE},
    )
    assert resp.status_code == 422


def test_422_when_source_id_missing():
    """Body without source_id returns 422."""
    client = TestClient(_make_app(_DEFAULT_STATE))
    resp = client.post(
        _CI_URL,
        json={"commit_sha": "abc12345"},
    )
    assert resp.status_code == 422


def test_403_when_api_key_lacks_scope():
    """API key missing scan:trigger scope returns 403."""
    state = {
        "api_key_id": 1,
        "api_key_scopes": ["view_findings"],
        "api_key_allowed_source_ids": None,
    }
    client = TestClient(_make_app(state))
    resp = client.post(
        _CI_URL,
        json={"source_id": _ANY_SOURCE, "commit_sha": "abc12345"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["error"] == "missing_scope"
    assert body["detail"]["missing_scope"] == "scan:trigger"


def test_404_when_source_not_found():
    """Valid API key, valid scope, but no matching asset → 404."""
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: None)
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx):
        client = TestClient(_make_app(_DEFAULT_STATE))
        resp = client.post(
            _CI_URL,
            json={"source_id": _ANY_SOURCE, "commit_sha": "abc12345"},
        )
    assert resp.status_code == 404


def test_409_when_asset_archived():
    """Asset.archived=True returns 409 with {error: source_disabled}."""
    source_id = str(uuid.uuid4())
    asset = _fake_asset(source_id, archived=True)

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: asset)
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx):
        client = TestClient(_make_app(_DEFAULT_STATE))
        resp = client.post(
            _CI_URL,
            json={"source_id": source_id, "commit_sha": "abc12345"},
        )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "source_disabled"


def test_202_happy_path():
    """Valid request returns 202 with scan_id, status, and status_url."""
    source_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    asset = _fake_asset(source_id)
    submission = _fake_submission(scan_id, source_id, "abc12345def67890")

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: asset)
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
         patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(return_value=submission)), \
         patch("src.scans.ci_router.cancel_older_queued_for_pr", new=AsyncMock(return_value=[])):
        client = TestClient(_make_app(_DEFAULT_STATE))
        resp = client.post(
            _CI_URL,
            json={"source_id": source_id, "commit_sha": "abc12345def67890", "branch": "main"},
        )

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "queued"
    assert body["status_url"] == f"/api/v1/scans/{scan_id}"
    assert not body.get("deduplicated")


def test_dedup_returns_existing_scan_without_new_submission():
    """When an in-flight scan exists, return it without calling submit_ci_scan."""
    source_id = str(uuid.uuid4())
    existing_scan_id = str(uuid.uuid4())
    asset = _fake_asset(source_id)

    inflight = MagicMock()
    inflight.id = existing_scan_id
    inflight.status = "queued"

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: asset)
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    mock_submit = AsyncMock()

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=inflight)), \
         patch("src.scans.ci_router.submit_ci_scan", new=mock_submit):
        client = TestClient(_make_app(_DEFAULT_STATE))
        resp = client.post(
            _CI_URL,
            json={"source_id": source_id, "commit_sha": "abc12345def67890"},
        )

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["scan_id"] == existing_scan_id
    assert body["deduplicated"] is True
    mock_submit.assert_not_called()


@pytest.mark.asyncio
async def test_db_dedup_returns_existing_scan(db_session, asset, api_key_row):
    """DB-backed dedup: second call with same commit_sha returns same scan_id."""
    key_row, _raw_token = api_key_row
    commit_sha = "dec01234" + "a" * 32
    scan_id_first = str(uuid.uuid4())

    existing = ScanRun(
        id=scan_id_first,
        tool="dependencies_scanning",
        asset_id=asset.id,
        status="queued",
        commit_sha=commit_sha,
        feedback_status="not_applicable",
    )
    db_session.add(existing)
    await db_session.commit()

    try:
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=lambda: _fake_asset(asset.id))
        )
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        state = {
            "api_key_id": key_row.id,
            "api_key_scopes": ["scan:trigger"],
            "api_key_allowed_source_ids": None,
        }

        with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
             patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=existing)), \
             patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock()) as mock_submit:
            client = TestClient(_make_app(state))
            resp = client.post(
                _CI_URL,
                json={"source_id": asset.id, "commit_sha": commit_sha},
            )

        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["scan_id"] == scan_id_first
        assert body["deduplicated"] is True
        mock_submit.assert_not_called()

    finally:
        await db_session.execute(delete(ScanRun).where(ScanRun.id == scan_id_first))
        await db_session.commit()


@pytest.mark.asyncio
async def test_db_force_push_cancels_older_pr_scan(db_session, asset, api_key_row):
    """Force-push: second call on same PR cancels the first queued scan."""
    key_row, _raw_token = api_key_row
    pr_number = 247
    old_scan_id = str(uuid.uuid4())
    new_scan_id = str(uuid.uuid4())

    old_scan = ScanRun(
        id=old_scan_id,
        tool="dependencies_scanning",
        asset_id=asset.id,
        status="queued",
        commit_sha="ab1111" + "a" * 34,
        pr_number=pr_number,
        feedback_status="pending",
    )
    db_session.add(old_scan)
    await db_session.commit()

    try:
        new_submission = _fake_submission(new_scan_id, asset.id, "bef222" + "b" * 34)
        new_submission.scan_id = new_scan_id
        new_submission_row = ScanRun(
            id=new_scan_id,
            tool="dependencies_scanning",
            asset_id=asset.id,
            status="queued",
            commit_sha="bef222" + "b" * 34,
            pr_number=pr_number,
            feedback_status="pending",
        )
        db_session.add(new_submission_row)
        await db_session.commit()

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=lambda: _fake_asset(asset.id))
        )
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        state = {
            "api_key_id": key_row.id,
            "api_key_scopes": ["scan:trigger"],
            "api_key_allowed_source_ids": None,
        }

        from contextlib import asynccontextmanager
        from src.db.engine import DATABASE_URL
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

        cancel_engine = create_async_engine(DATABASE_URL, echo=False)
        cancel_factory = async_sessionmaker(cancel_engine, class_=AsyncSession, expire_on_commit=False)

        @asynccontextmanager
        async def _real_get_session_for_cancel():
            async with cancel_factory() as s:
                yield s

        with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
             patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
             patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(return_value=new_submission)), \
             patch("src.scans.service.get_session", _real_get_session_for_cancel):
            client = TestClient(_make_app(state))
            resp = client.post(
                _CI_URL,
                json={"source_id": asset.id, "commit_sha": "bef222" + "b" * 34, "branch": "feat/pr", "pr_number": pr_number},
            )

        await cancel_engine.dispose()

        assert resp.status_code == 202, resp.text

        await db_session.refresh(old_scan)
        await db_session.refresh(new_submission_row)

        assert old_scan.status == "cancelled", f"expected cancelled, got {old_scan.status}"
        assert old_scan.cancelled_reason == "superseded"
        # finished_at must be stamped so the run sorts/paginates in the history feed.
        assert old_scan.finished_at is not None
        assert new_submission_row.status == "queued"

    finally:
        await db_session.execute(delete(ScanRun).where(ScanRun.id.in_([old_scan_id, new_scan_id])))
        await db_session.commit()


def test_rate_limit_blocks_second_request_within_window():
    """Second trigger within 10s for same source returns 429 with Retry-After."""
    source_id = str(uuid.uuid4())
    asset_obj = _fake_asset(source_id)
    submission = _fake_submission(str(uuid.uuid4()), source_id, "abc12345")

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: asset_obj)
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
         patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(return_value=submission)):
        client = TestClient(_make_app(_DEFAULT_STATE))
        r1 = client.post(
            _CI_URL,
            json={"source_id": source_id, "commit_sha": "abc12345"},
        )
        r2 = client.post(
            _CI_URL,
            json={"source_id": source_id, "commit_sha": "def67890"},
        )

    assert r1.status_code == 202
    assert r2.status_code == 429
    body = r2.json()
    assert body["detail"]["error"] == "rate_limited"
    assert isinstance(body["detail"]["retry_after_seconds"], int) and body["detail"]["retry_after_seconds"] > 0
    assert r2.headers.get("Retry-After")


def test_rate_limit_keyed_by_source_id():
    """Different source_id values share no counter."""
    source_a = str(uuid.uuid4())
    source_b = str(uuid.uuid4())
    submission_a = _fake_submission(str(uuid.uuid4()), source_a, "abc12345")
    submission_b = _fake_submission(str(uuid.uuid4()), source_b, "abc12345")

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: _fake_asset(source_a))
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("src.scans.ci_router.get_session", return_value=mock_ctx), \
         patch("src.scans.ci_router.find_inflight_scan", new=AsyncMock(return_value=None)), \
         patch("src.scans.ci_router.submit_ci_scan", new=AsyncMock(side_effect=[submission_a, submission_b])):
        client = TestClient(_make_app(_DEFAULT_STATE))
        r1 = client.post(
            _CI_URL,
            json={"source_id": source_a, "commit_sha": "abc12345"},
        )
        r2 = client.post(
            _CI_URL,
            json={"source_id": source_b, "commit_sha": "abc12345"},
        )

    assert r1.status_code == 202
    assert r2.status_code == 202
