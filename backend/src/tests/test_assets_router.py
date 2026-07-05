"""Smoke + behavior tests for the manual-upload and BYO-import routes.

These two endpoints both create assets and hand-off to the identity layer:
  - POST /api/v1/sources/manual   (sources router)
  - POST /api/v1/scans/import     (scans byo router)
"""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SOURCES, RUN_SCANS  # noqa: E402
from src.sources.router import _db as _sources_db, router as sources_router  # noqa: E402
from src.scans.byo_router import _db as _byo_db, router as scans_byo_router  # noqa: E402
from src.db.models import Asset, Finding, Grant, ScanRun, Team, TeamMember, User  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def _clean_router(db_session):
    yield
    # Delete FK-dependents (findings + scan_runs reference assets) before assets,
    # or the asset delete violates scan_runs_asset_id_fkey and leaves rows behind
    # that contaminate later asset-counting tests.
    await db_session.execute(delete(Finding))
    await db_session.execute(delete(ScanRun))
    await db_session.execute(delete(Grant))
    await db_session.execute(delete(TeamMember))
    await db_session.execute(delete(Team))
    await db_session.execute(delete(Asset))
    await db_session.execute(delete(User).where(User.id.like("router-test-%")))
    await db_session.commit()


def _make_app(user_id: str, db_session, *, allow_permissions: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(sources_router)
    app.include_router(scans_byo_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = user_id
        request.state.user_role = "viewer"
        return await call_next(request)

    async def _override_db():
        yield db_session

    app.dependency_overrides[_sources_db] = _override_db
    app.dependency_overrides[_byo_db] = _override_db
    if allow_permissions:
        # These tests cover upload/grant behavior, not the permission gate.
        # The gate itself is exercised in the dedicated _requires_* tests below.
        app.dependency_overrides[Permission(MANAGE_SOURCES)] = lambda: None
        app.dependency_overrides[Permission(RUN_SCANS, MANAGE_SOURCES)] = lambda: None
    return app


async def _seed_user_with_team(db_session) -> tuple[str, str]:
    user_id = f"router-test-{uuid4()}"
    db_session.add(User(id=user_id, username=user_id, email=f"{user_id}@example.com",
                        password_hash="", status="active"))
    team = Team(id=f"t-{uuid4()}", name="Test Team")
    db_session.add(team)
    await db_session.flush()
    db_session.add(TeamMember(team_id=team.id, user_id=user_id))
    await db_session.commit()
    return user_id, team.id


async def _seed_user_without_team(db_session) -> str:
    user_id = f"router-test-{uuid4()}"
    db_session.add(User(id=user_id, username=user_id, email=f"{user_id}@example.com",
                        password_hash="", status="active"))
    await db_session.commit()
    return user_id


@pytest.mark.asyncio
async def test_manual_repo_upload_creates_asset_and_grants_to_primary_team(db_session):
    user_id, team_id = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/sources/manual",
            json={"type": "repo", "source_type": "github", "owner": "acme", "name": "foo"},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["external_ref"] == "github:acme/foo"
    assert "asset_id" in body

    # The asset exists and is granted to the user's team
    asset = (await db_session.execute(select(Asset).where(Asset.external_ref == "github:acme/foo"))).scalar_one()
    assert asset.source == "manual_upload"
    grant = (await db_session.execute(
        select(Grant).where(Grant.asset_id == str(asset.id), Grant.subject_type == "team")
    )).scalar_one()
    assert grant.subject_id == team_id


@pytest.mark.asyncio
async def test_manual_image_upload_creates_asset(db_session):
    user_id, _ = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/sources/manual",
            json={"type": "image", "registry": "ghcr", "image": "acme/img", "tag": "v1.2.3"},
        )
    assert response.status_code == 200, response.text
    assert response.json()["external_ref"] == "ghcr:acme/img:v1.2.3"


@pytest.mark.asyncio
async def test_manual_upload_rejects_user_without_team(db_session):
    user_id = await _seed_user_without_team(db_session)
    app = _make_app(user_id, db_session)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/sources/manual",
            json={"type": "repo", "source_type": "github", "owner": "acme", "name": "foo"},
        )
    assert response.status_code == 400, response.text
    assert "team" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_byo_import_creates_one_asset_per_target_and_ingests_findings(db_session):
    user_id, team_id = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session)

    payload = {
        "scanner": "trivy",
        "targets": [
            {"type": "image", "registry": "ghcr", "image": "acme/img", "tag": "v1"},
            {"type": "image", "registry": "ghcr", "image": "acme/other", "tag": "v2"},
        ],
        "findings": [
            {"target_index": 0, "identity_key": "CVE-2025-0001", "tool": "container_scanning",
             "severity": "critical", "title": "vuln in img v1"},
            {"target_index": 1, "identity_key": "CVE-2025-0002", "tool": "container_scanning",
             "severity": "high", "title": "vuln in other v2"},
        ],
    }
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/scans/import", json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["assets"]) == 2
    assert body["findings_created"] == 2

    # Verify findings are linked to the right assets (this was the whole point)
    from sqlalchemy import select
    finding_rows = (await db_session.execute(
        select(Finding).where(Finding.tool == "container_scanning").order_by(Finding.identity_key)
    )).scalars().all()
    assert len(finding_rows) == 2
    asset_ids_returned = body["assets"]
    assert finding_rows[0].asset_id == asset_ids_returned[0]
    assert finding_rows[1].asset_id == asset_ids_returned[1]


@pytest.mark.asyncio
async def test_byo_import_rejects_unresolvable_target(db_session):
    user_id, _ = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session)

    payload = {
        "scanner": "trivy",
        "targets": [{"type": "image", "registry": "", "image": "", "tag": ""}],
        "findings": [],
    }
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/scans/import", json=payload)
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Permission-gate tests — lock in the new authorization requirements so a
# future change that drops the Depends(Permission(...)) is caught in CI.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manual_upload_requires_manage_sources(db_session):
    """Manual asset registration is a source-management operation."""
    user_id, _ = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session, allow_permissions=False)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/sources/manual",
            json={"type": "repo", "source_type": "github", "owner": "acme", "name": "foo"},
        )
    assert response.status_code == 403
    assert "manage_sources" in response.json()["detail"]


@pytest.mark.asyncio
async def test_byo_import_requires_run_scans_and_manage_sources(db_session):
    """BYO both ingests scan data (RUN_SCANS) and upserts assets (MANAGE_SOURCES).

    AND-semantics: a role with only one of the two cannot import. Locks in
    the least-privilege gate so a security-role user (run_scans but not
    manage_sources) gets 403 rather than silently widening their own scope.
    """
    user_id, _ = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session, allow_permissions=False)
    payload = {
        "scanner": "trivy",
        "targets": [{"type": "repo", "source_type": "github", "owner": "acme", "name": "foo"}],
        "findings": [],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/scans/import", json=payload)
    assert response.status_code == 403
    # The first failing permission in the AND-list wins; assert one of the
    # two appears in the detail so future re-ordering doesn't break the test.
    detail = response.json()["detail"]
    assert "run_scans" in detail or "manage_sources" in detail
