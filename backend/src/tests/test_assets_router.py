"""Smoke + behavior tests for /api/v1/assets/manual."""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from src.assets.router import _db, assets_router, scans_router  # noqa: E402
from src.db.models import Asset, Finding, Team, TeamAsset, TeamMember, User  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def _clean_router(db_session):
    yield
    await db_session.execute(delete(Finding).where(Finding.tool == "container_scanning"))
    await db_session.execute(delete(TeamAsset))
    await db_session.execute(delete(TeamMember))
    await db_session.execute(delete(Team))
    await db_session.execute(delete(Asset))
    await db_session.execute(delete(User).where(User.id.like("router-test-%")))
    await db_session.commit()


def _make_app(user_id: str, db_session) -> FastAPI:
    app = FastAPI()
    app.include_router(assets_router)
    app.include_router(scans_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = user_id
        request.state.user_role = "viewer"
        return await call_next(request)

    async def _override_db():
        yield db_session

    app.dependency_overrides[_db] = _override_db
    return app


async def _seed_user_with_team(db_session) -> tuple[str, str]:
    user_id = f"router-test-{uuid4()}"
    db_session.add(User(id=user_id, username=user_id, email=f"{user_id}@example.com",
                        password_hash="", role="viewer", status="active"))
    team = Team(id=f"t-{uuid4()}", name="Test Team")
    db_session.add(team)
    await db_session.flush()
    db_session.add(TeamMember(team_id=team.id, user_id=user_id))
    await db_session.commit()
    return user_id, team.id


async def _seed_user_without_team(db_session) -> str:
    user_id = f"router-test-{uuid4()}"
    db_session.add(User(id=user_id, username=user_id, email=f"{user_id}@example.com",
                        password_hash="", role="viewer", status="active"))
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
            "/api/v1/assets/manual",
            json={"type": "repo", "source_type": "github", "owner": "acme", "name": "foo"},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["external_ref"] == "github:acme/foo"
    assert "asset_id" in body

    # The asset exists and is granted to the user's team
    asset = (await db_session.execute(select(Asset).where(Asset.external_ref == "github:acme/foo"))).scalar_one()
    assert asset.source == "manual_upload"
    grant = (await db_session.execute(select(TeamAsset).where(TeamAsset.asset_id == asset.id))).scalar_one()
    assert grant.team_id == team_id


@pytest.mark.asyncio
async def test_manual_image_upload_creates_asset(db_session):
    user_id, _ = await _seed_user_with_team(db_session)
    app = _make_app(user_id, db_session)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/assets/manual",
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
            "/api/v1/assets/manual",
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
