"""Saved views service tests — per-user scoping, default uniqueness, url_state validation."""
from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import SavedView
from src.saved_views.service import (
    KNOWN_SURFACES,
    MAX_URL_STATE_BYTES,
    SavedViewIn,
    create_view,
    delete_view,
    list_views,
    set_default,
    update_view,
)


def test_findings_is_a_known_surface():
    assert "findings" in KNOWN_SURFACES


@pytest_asyncio.fixture
async def user_ids(db_session):
    """Yield two unique per-test user ids; clean rows at teardown.

    The conftest db_session fixture commits across tests, so rows created
    here would otherwise leak into sibling tests via the (user_id, surface,
    name) unique constraint.
    """
    uid_a = f"u-{uuid4()}"
    uid_b = f"u-{uuid4()}"
    yield uid_a, uid_b
    await db_session.execute(
        delete(SavedView).where(SavedView.user_id.in_((uid_a, uid_b)))
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_create_view_persists_with_per_user_scope(db_session, user_ids):
    uid_a, _ = user_ids
    v = await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="KEV only", url_state={"kev": "true"}),
        session=db_session,
    )
    assert v.user_id == uid_a
    assert v.surface == "findings"
    assert v.name == "KEV only"
    assert v.url_state == {"kev": "true"}
    assert v.is_default is False


@pytest.mark.asyncio
async def test_create_rejects_unknown_surface(db_session, user_ids):
    uid_a, _ = user_ids
    with pytest.raises(ValueError):
        await create_view(
            user_id=uid_a,
            payload=SavedViewIn(surface="other", name="X", url_state={}),
            session=db_session,
        )


@pytest.mark.asyncio
async def test_create_rejects_empty_name(db_session, user_ids):
    uid_a, _ = user_ids
    with pytest.raises(ValueError):
        await create_view(
            user_id=uid_a,
            payload=SavedViewIn(surface="findings", name="", url_state={}),
            session=db_session,
        )


@pytest.mark.asyncio
async def test_list_views_scoped_to_user_and_surface(db_session, user_ids):
    uid_a, uid_b = user_ids
    await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="A", url_state={}),
        session=db_session,
    )
    await create_view(
        user_id=uid_b,
        payload=SavedViewIn(surface="findings", name="A", url_state={}),
        session=db_session,
    )
    rows = await list_views(user_id=uid_a, surface="findings", session=db_session)
    assert {r.user_id for r in rows} == {uid_a}


@pytest.mark.asyncio
async def test_set_default_clears_previous_default(db_session, user_ids):
    uid_a, _ = user_ids
    a = await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="A", url_state={}),
        session=db_session,
    )
    b = await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="B", url_state={}),
        session=db_session,
    )
    await set_default(user_id=uid_a, view_id=a.id, session=db_session)
    await set_default(user_id=uid_a, view_id=b.id, session=db_session)
    rows = await list_views(user_id=uid_a, surface="findings", session=db_session)
    defaults = [r for r in rows if r.is_default]
    assert len(defaults) == 1
    assert defaults[0].id == b.id


@pytest.mark.asyncio
async def test_update_name_only_does_not_touch_url_state(db_session, user_ids):
    uid_a, _ = user_ids
    v = await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="A", url_state={"kev": "true"}),
        session=db_session,
    )
    updated = await update_view(user_id=uid_a, view_id=v.id, name="B", session=db_session)
    assert updated.name == "B"
    assert updated.url_state == {"kev": "true"}


@pytest.mark.asyncio
async def test_delete_view_removes_it(db_session, user_ids):
    uid_a, _ = user_ids
    v = await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="A", url_state={}),
        session=db_session,
    )
    await delete_view(user_id=uid_a, view_id=v.id, session=db_session)
    rows = await list_views(user_id=uid_a, surface="findings", session=db_session)
    assert all(r.id != v.id for r in rows)


@pytest.mark.asyncio
async def test_delete_other_users_view_is_not_found(db_session, user_ids):
    uid_a, uid_b = user_ids
    v = await create_view(
        user_id=uid_a,
        payload=SavedViewIn(surface="findings", name="A", url_state={}),
        session=db_session,
    )
    with pytest.raises(LookupError):
        await delete_view(user_id=uid_b, view_id=v.id, session=db_session)


@pytest.mark.asyncio
async def test_url_state_too_large_rejected(db_session, user_ids):
    uid_a, _ = user_ids
    huge = {"k": "x" * (MAX_URL_STATE_BYTES + 100)}
    with pytest.raises(ValueError):
        await create_view(
            user_id=uid_a,
            payload=SavedViewIn(surface="findings", name="X", url_state=huge),
            session=db_session,
        )
