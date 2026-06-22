"""End-to-end: CI trigger → scan completes → PR comment posted."""
from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.db.engine import DATABASE_URL  # noqa: E402
from src.db.models import Asset, ScanRun  # noqa: E402
from src.pr_feedback import poster as pr_poster  # noqa: E402
from src.scans.ci_router import router as ci_router  # noqa: E402


def _make_app(state: dict) -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def _inject_state(request, call_next):
        for k, v in state.items():
            setattr(request.state, k, v)
        return await call_next(request)

    app.include_router(ci_router)
    return app


def _make_session_patch(engine_url: str):
    """Build an async-cm callable to monkeypatch get_session against a fresh engine."""
    engine = create_async_engine(engine_url, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    @asynccontextmanager
    async def _patched_get_session():
        async with factory() as session:
            yield session

    return _patched_get_session, engine


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets():
    from src.shared import rate_limit as rl
    with rl._lock:
        rl._buckets.clear()
    yield


@pytest_asyncio.fixture
async def asset(db_session):
    asset_id = str(uuid.uuid4())
    row = Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github.com/acme-org/api-{asset_id[:8]}",
        display_name="acme-org/api",
    )
    db_session.add(row)
    await db_session.commit()
    yield row
    await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


class _FakeProvider:
    def __init__(self):
        self.posted = []

    def post_or_update_comment(self, *, repo, pr_number, body, marker, token):
        self.posted.append({"repo": repo, "pr_number": pr_number, "body": body, "marker": marker})


class _FakeSource:
    def __init__(self, sid):
        self.id = sid
        self.scm_type = "github"
        self.stored_pat = "ghp_fake"

    def base_sha_for_pr(self, _pr):
        return "base000"


@pytest.mark.asyncio
async def test_ci_trigger_to_comment_full_chain(db_session, asset, monkeypatch):
    # Patch the trigger router's service helpers to use a fresh-engine session
    # so the TestClient (sync thread, anyio portal) can write rows the test's
    # async db_session can read after the call.
    sess_for_service, eng_for_service = _make_session_patch(DATABASE_URL)
    monkeypatch.setattr("src.scans.service.get_session", sess_for_service)
    sess_for_router, eng_for_router = _make_session_patch(DATABASE_URL)
    monkeypatch.setattr("src.scans.ci_router.get_session", sess_for_router)

    state = {
        "api_key_id": 99,
        "api_key_scopes": ["scan:trigger"],
        "api_key_allowed_source_ids": None,
    }

    # ── 1. Trigger from "CI" — stub out the runner dispatch so no real jobs are created
    with patch("src.scans.service._dispatch_scanner_jobs", return_value=None):
        client = TestClient(_make_app(state))
        resp = client.post(
            "/api/v1/scans/ci",
            json={
                "source_id": asset.id,
                "commit_sha": "abc12345def67890",
                "branch": "feat/x",
                "pr_number": 247,
            },
        )
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]

    # ── 2. Simulate the runner finishing the scan
    await db_session.execute(
        update(ScanRun)
        .where(ScanRun.id == scan_id)
        .values(status="completed")
    )
    await db_session.commit()

    # ── 3. Stub poster adapters
    findings = [
        {"fingerprint": "x1", "severity": "high", "title": "SQLi"},
        {"fingerprint": "x2", "severity": "medium", "title": "XSS"},
    ]
    monkeypatch.setattr(pr_poster, "_list_findings_for_scan", lambda _sid: findings)
    monkeypatch.setattr(pr_poster, "_list_findings_for_base", lambda _src, _sha: [])
    monkeypatch.setattr(pr_poster, "_resolve_source", lambda sid: _FakeSource(sid))

    # Patch poster's get_session to share the test session for visibility
    sess_for_poster, eng_for_poster = _make_session_patch(DATABASE_URL)
    monkeypatch.setattr("src.pr_feedback.poster.get_session", sess_for_poster)

    # ── 4. Run the PR feedback poster once
    provider = _FakeProvider()
    result = await pr_poster.process_pending_once(
        provider=provider,
        aegis_url="https://aegis.example.com",
    )

    assert result["processed"] >= 1
    assert result["posted"] == 1

    # ── 5. Confirm the comment was rendered + posted
    assert len(provider.posted) == 1
    body = provider.posted[0]["body"]
    assert "2 new findings" in body
    # The render embeds the scan_id in the header marker inside the body
    assert scan_id in body

    # Verify the row's feedback_status flipped to 'posted'
    db_session.expire_all()
    row = (await db_session.execute(
        ScanRun.__table__.select().where(ScanRun.id == scan_id)
    )).first()
    assert dict(row._mapping)["feedback_status"] == "posted"
