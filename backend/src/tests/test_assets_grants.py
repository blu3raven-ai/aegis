import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, select

from src.assets.grants import auto_grant_to_uploader, primary_team_id_for_user
from src.db.models import Asset, Grant, Team, TeamMember


@pytest_asyncio.fixture(autouse=True)
async def _clean_grants(db_session):
    yield
    await db_session.execute(delete(Grant))
    await db_session.execute(delete(TeamMember))
    await db_session.execute(delete(Team))
    await db_session.execute(delete(Asset))
    await db_session.commit()


@pytest.mark.asyncio
async def test_primary_team_returns_oldest_membership(db_session, seed_user):
    now = datetime.now(timezone.utc)
    older = Team(id="t-old", name="Older")
    newer = Team(id="t-new", name="Newer")
    db_session.add_all([older, newer])
    await db_session.flush()
    db_session.add_all([
        TeamMember(team_id=newer.id, user_id=seed_user.id, added_at=now),
        TeamMember(team_id=older.id, user_id=seed_user.id, added_at=now - timedelta(days=7)),
    ])
    await db_session.commit()
    assert await primary_team_id_for_user(db_session, seed_user.id) == "t-old"


@pytest.mark.asyncio
async def test_primary_team_returns_none_when_no_membership(db_session, seed_user):
    assert await primary_team_id_for_user(db_session, seed_user.id) is None


@pytest.mark.asyncio
async def test_auto_grant_attaches_asset_to_primary_team(db_session, seed_user):
    team = Team(id="t-1", name="One")
    asset = Asset(type="repo", source="manual_upload",
                  external_ref="github:acme/foo", display_name="acme/foo")
    db_session.add_all([team, asset])
    await db_session.flush()
    db_session.add(TeamMember(team_id=team.id, user_id=seed_user.id))
    await db_session.commit()

    await auto_grant_to_uploader(db_session, asset_id=asset.id, user_id=seed_user.id)

    grant = (await db_session.execute(
        select(Grant).where(Grant.asset_id == str(asset.id), Grant.subject_type == "team")
    )).scalar_one()
    assert grant is not None
    assert grant.subject_id == "t-1"


@pytest.mark.asyncio
async def test_auto_grant_raises_when_user_has_no_team(db_session, seed_user):
    asset = Asset(type="repo", source="manual_upload",
                  external_ref="github:acme/foo", display_name="acme/foo")
    db_session.add(asset)
    await db_session.commit()
    with pytest.raises(ValueError, match="no team"):
        await auto_grant_to_uploader(db_session, asset_id=asset.id, user_id=seed_user.id)
