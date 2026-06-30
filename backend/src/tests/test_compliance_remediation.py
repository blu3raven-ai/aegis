"""Control remediation overlay — owner + due date + overdue surfacing."""
from __future__ import annotations

import os
import uuid
from datetime import date, timedelta

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.compliance import service as svc  # noqa: E402
from src.compliance.models import ComplianceControlAssessment, Framework, FrameworkControl  # noqa: E402
from src.db.models import User  # noqa: E402


async def _seed(db_session) -> tuple[str, str]:
    fw_id = f"fw-{uuid.uuid4().hex[:8]}"
    user_id = f"u-{uuid.uuid4().hex[:8]}"
    db_session.add(Framework(id=fw_id, label="FW", is_custom=True))
    db_session.add(FrameworkControl(framework=fw_id, control_id="C1", title="One"))
    db_session.add(User(id=user_id, username="alice", email="a@x", status="active"))
    await db_session.commit()
    return fw_id, user_id


@pytest.mark.asyncio
async def test_owner_and_overdue_surface_in_summary(db_session):
    fw_id, user_id = await _seed(db_session)
    try:
        # A past due date on an un-attested (not-met-by-default... actually met
        # since no findings) control: make it non-met via a manual status so the
        # overdue logic has something to flag.
        await svc.upsert_control_assessment(
            db_session, fw_id, "C1",
            status="non_compliant", evidence_note=None, evidence_url=None,
            owner_user_id=user_id, due_date=(date.today() - timedelta(days=3)).isoformat(),
            user_id="admin",
        )
        await db_session.commit()
        summary = await svc.get_framework_summary(db_session, fw_id, asset_ids=[])
        c = next(x for x in summary if x.control_id == "C1")
        assert c.owner_user_id == user_id
        assert c.owner_label == "alice"  # resolved username
        assert c.overdue is True

        # A future due date is not overdue.
        await svc.upsert_control_assessment(
            db_session, fw_id, "C1",
            status="non_compliant", evidence_note=None, evidence_url=None,
            owner_user_id=user_id, due_date=(date.today() + timedelta(days=10)).isoformat(),
            user_id="admin",
        )
        await db_session.commit()
        c = next(x for x in await svc.get_framework_summary(db_session, fw_id, asset_ids=[]) if x.control_id == "C1")
        assert c.overdue is False

        # A met control is never overdue, even with a past due date.
        await svc.upsert_control_assessment(
            db_session, fw_id, "C1",
            status="compliant", evidence_note=None, evidence_url=None,
            owner_user_id=user_id, due_date=(date.today() - timedelta(days=3)).isoformat(),
            user_id="admin",
        )
        await db_session.commit()
        c = next(x for x in await svc.get_framework_summary(db_session, fw_id, asset_ids=[]) if x.control_id == "C1")
        assert c.overdue is False
    finally:
        await _cleanup(db_session, fw_id, user_id)


@pytest.mark.asyncio
async def test_invalid_owner_and_due_date_rejected(db_session):
    fw_id, user_id = await _seed(db_session)
    try:
        with pytest.raises(ValueError):
            await svc.upsert_control_assessment(
                db_session, fw_id, "C1", status="auto", evidence_note=None,
                evidence_url=None, owner_user_id="nobody", due_date=None, user_id="admin",
            )
        await db_session.rollback()
        with pytest.raises(ValueError):
            await svc.upsert_control_assessment(
                db_session, fw_id, "C1", status="auto", evidence_note=None,
                evidence_url=None, owner_user_id=None, due_date="not-a-date", user_id="admin",
            )
        await db_session.rollback()
    finally:
        await _cleanup(db_session, fw_id, user_id)


async def _cleanup(session, fw_id: str, user_id: str) -> None:
    from sqlalchemy import delete
    await session.rollback()
    await session.execute(delete(ComplianceControlAssessment).where(ComplianceControlAssessment.framework == fw_id))
    await session.execute(delete(FrameworkControl).where(FrameworkControl.framework == fw_id))
    await session.execute(delete(Framework).where(Framework.id == fw_id))
    await session.execute(delete(User).where(User.id == user_id))
    await session.commit()
