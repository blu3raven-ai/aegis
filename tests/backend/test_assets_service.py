import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.assets.service import upsert_asset
from src.db.models import Asset


@pytest_asyncio.fixture(autouse=True)
async def _clean_assets(db_session):
    yield
    await db_session.execute(delete(Asset))
    await db_session.commit()


@pytest.mark.asyncio
async def test_upsert_creates_new_asset_when_external_ref_unseen(db_session):
    asset_id = await upsert_asset(
        db_session,
        type="repo",
        source="source_connection",
        source_ref="conn-1",
        external_ref="github:acme/foo",
        display_name="acme/foo",
    )
    row = (await db_session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one()
    assert row.type == "repo"
    assert row.source == "source_connection"
    assert row.source_ref == "conn-1"
    assert row.external_ref == "github:acme/foo"
    assert row.display_name == "acme/foo"


@pytest.mark.asyncio
async def test_upsert_returns_existing_id_for_matching_external_ref(db_session):
    first = await upsert_asset(
        db_session, type="repo", source="source_connection", source_ref="conn-1",
        external_ref="github:acme/foo", display_name="acme/foo",
    )
    second = await upsert_asset(
        db_session, type="repo", source="manual_upload", source_ref=None,
        external_ref="github:acme/foo", display_name="acme/foo (renamed)",
        metadata={"note": "manual"},
    )
    assert first == second


@pytest.mark.asyncio
async def test_upsert_does_not_overwrite_source_or_source_ref_on_merge(db_session):
    asset_id = await upsert_asset(
        db_session, type="repo", source="source_connection", source_ref="conn-1",
        external_ref="github:acme/foo", display_name="acme/foo",
    )
    await upsert_asset(
        db_session, type="repo", source="manual_upload", source_ref=None,
        external_ref="github:acme/foo", display_name="acme/foo",
    )
    row = (await db_session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one()
    assert row.source == "source_connection"
    assert row.source_ref == "conn-1"


@pytest.mark.asyncio
async def test_upsert_merges_metadata_on_conflict(db_session):
    asset_id = await upsert_asset(
        db_session, type="repo", source="source_connection", source_ref="conn-1",
        external_ref="github:acme/foo", display_name="acme/foo",
        metadata={"discovered_at": "2026-06-01"},
    )
    await upsert_asset(
        db_session, type="repo", source="manual_upload", source_ref=None,
        external_ref="github:acme/foo", display_name="acme/foo",
        metadata={"manual_note": "added later"},
    )
    row = (await db_session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one()
    assert row.asset_metadata == {
        "discovered_at": "2026-06-01",
        "manual_note": "added later",
    }
