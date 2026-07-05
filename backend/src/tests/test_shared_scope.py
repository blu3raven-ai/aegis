import pytest
import pytest_asyncio
from sqlalchemy import select, text

from src.db.models import Finding  # noqa: F401  (kept for apply_scope select() tests)
from src.db.models import Asset, Grant, Team, TeamMember
from src.authz.enforcement.scope import apply_scope, get_user_asset_ids


async def _clean_asset_graph(db_session):
    # These tests count *all* assets, so any rows left by upstream files skew the
    # results. TRUNCATE ... CASCADE clears assets + teams and every FK-dependent
    # table (findings, scan_runs, grants, sbom, posture, ...) in one FK-safe
    # statement — enumerating the 10 asset-referencing tables by hand is fragile,
    # and some use ondelete=RESTRICT so an ordered DELETE would block.
    await db_session.execute(text("TRUNCATE TABLE assets, teams RESTART IDENTITY CASCADE"))
    await db_session.commit()


@pytest_asyncio.fixture(autouse=True)
async def _clean_scope(db_session):
    await _clean_asset_graph(db_session)
    yield
    await _clean_asset_graph(db_session)


@pytest.mark.asyncio
async def test_get_user_asset_ids_returns_empty_for_no_team_member(db_session, seed_user):
    ctx = {"user_id": seed_user.id, "role": "viewer"}
    assert await get_user_asset_ids(db_session, ctx) == []


@pytest.mark.asyncio
async def test_get_user_asset_ids_returns_all_for_admin(db_session, seed_user):
    a = Asset(type="repo", source="source_connection", external_ref="github:acme/foo",
              display_name="acme/foo")
    db_session.add(a)
    await db_session.commit()
    ctx = {"user_id": seed_user.id, "role": "admin"}
    ids = await get_user_asset_ids(db_session, ctx)
    assert str(a.id) in ids


@pytest.mark.asyncio
async def test_get_user_asset_ids_returns_team_granted_only(db_session, seed_user):
    granted = Asset(type="repo", source="source_connection",
                    external_ref="github:acme/foo", display_name="acme/foo")
    other = Asset(type="repo", source="source_connection",
                  external_ref="github:acme/bar", display_name="acme/bar")
    team = Team(id="team-1", name="Team One")
    db_session.add_all([granted, other, team])
    await db_session.flush()
    db_session.add_all([
        TeamMember(team_id=team.id, user_id=seed_user.id),
        Grant(subject_type="team", subject_id=team.id, asset_id=granted.id),
    ])
    await db_session.commit()

    ctx = {"user_id": seed_user.id, "role": "viewer"}
    ids = await get_user_asset_ids(db_session, ctx)
    assert str(granted.id) in ids
    assert str(other.id) not in ids


def test_apply_scope_empty_yields_false_predicate():
    stmt = select(Finding)
    scoped = apply_scope(stmt, [])
    compiled = str(scoped.compile(compile_kwargs={"literal_binds": True}))
    assert "false" in compiled.lower()


def test_apply_scope_non_empty_yields_in_clause():
    stmt = select(Finding)
    scoped = apply_scope(stmt, ["abc", "def"])
    compiled = str(scoped.compile(compile_kwargs={"literal_binds": True}))
    assert "asset_id IN" in compiled or "asset_id in" in compiled
