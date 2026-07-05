"""Transactional create_framework_with_controls — atomic, no orphans.

A failing control batch (duplicate id, missing title, bad id) must leave NOTHING
persisted, so a corrected resubmit is clean rather than 409-ing on a half-created
framework.
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.compliance import service as svc  # noqa: E402
from src.compliance.models import Framework, FrameworkControl  # noqa: E402


async def _framework_exists(session, fw_id: str) -> bool:
    return (await session.get(Framework, fw_id)) is not None


@pytest.mark.asyncio
async def test_create_with_controls_happy_path(db_session):
    fw_id = f"fw-{uuid.uuid4().hex[:8]}"
    try:
        fw = await svc.create_framework_with_controls(
            db_session, framework_id=fw_id, label="Test FW", description="d",
            controls=[
                {"control_id": "C1", "title": "One", "category": "Cat"},
                {"control_id": "C2", "title": "Two", "description": "two"},
            ],
            created_by_user_id="u1",
        )
        await db_session.commit()
        assert fw.id == fw_id and fw.is_custom is True
        ctrls = await svc.list_controls_for_framework(db_session, fw_id)
        assert {c.control_id for c in ctrls} == {"C1", "C2"}
    finally:
        await _cleanup(db_session, fw_id)


@pytest.mark.asyncio
async def test_duplicate_control_id_rolls_back_whole_framework(db_session):
    fw_id = f"fw-{uuid.uuid4().hex[:8]}"
    try:
        with pytest.raises(svc.ControlAlreadyExists):
            await svc.create_framework_with_controls(
                db_session, framework_id=fw_id, label="Test FW", description=None,
                controls=[
                    {"control_id": "DUP", "title": "a"},
                    {"control_id": "DUP", "title": "b"},
                ],
                created_by_user_id="u1",
            )
        await db_session.rollback()
        # Atomic: nothing persisted, so a clean retry is possible.
        assert not await _framework_exists(db_session, fw_id)
    finally:
        await _cleanup(db_session, fw_id)


@pytest.mark.asyncio
async def test_bad_control_id_does_not_create_framework(db_session):
    fw_id = f"fw-{uuid.uuid4().hex[:8]}"
    try:
        with pytest.raises(ValueError):
            await svc.create_framework_with_controls(
                db_session, framework_id=fw_id, label="Test FW", description=None,
                controls=[{"control_id": "", "title": "no id"}],  # invalid control id
                created_by_user_id="u1",
            )
        await db_session.rollback()
        assert not await _framework_exists(db_session, fw_id)
    finally:
        await _cleanup(db_session, fw_id)


async def _cleanup(session, fw_id: str) -> None:
    from sqlalchemy import delete
    await session.rollback()
    await session.execute(delete(FrameworkControl).where(FrameworkControl.framework == fw_id))
    await session.execute(delete(Framework).where(Framework.id == fw_id))
    await session.commit()
