"""Suppressing an auto-mapping drops it from a control's status and counts.

A suppressed mapping is a false positive: kept for the audit trail but excluded
from finding counts / status. Also covers the BOLA scope gate and restore.
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.compliance import service as svc  # noqa: E402
from src.compliance.models import ComplianceControlMapping, Framework, FrameworkControl  # noqa: E402
from src.db.models import Asset, Finding  # noqa: E402


@pytest.mark.asyncio
async def test_suppress_excludes_mapping_from_status(db_session):
    db_session.add(Framework(id="soc2", label="SOC 2", is_custom=False))
    db_session.add(FrameworkControl(framework="soc2", control_id="CC6.8", title="Malware"))
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.flush()
    f = Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="high", title="Vuln",
    )
    db_session.add(f)
    await db_session.flush()
    m = ComplianceControlMapping(
        finding_id=f.id, framework="soc2", control_id="CC6.8", confidence=0.9, rationale="r",
    )
    db_session.add(m)
    await db_session.commit()

    try:
        # Baseline: the open high finding makes CC6.8 a gap.
        summary = await svc.get_framework_summary(db_session, "soc2", asset_ids=[asset_id])
        c = next(x for x in summary if x.control_id == "CC6.8")
        assert c.finding_count == 1
        assert svc._derive_control_status(c) == "unmet"

        # Suppress → drops from count + status, but the row survives.
        row = await svc.set_mapping_suppressed(
            db_session, m.id, suppressed=True, reason="False positive",
            user_id="analyst", asset_ids=[asset_id],
        )
        await db_session.commit()
        assert row is not None and row.suppressed is True
        summary = await svc.get_framework_summary(db_session, "soc2", asset_ids=[asset_id])
        c = next(x for x in summary if x.control_id == "CC6.8")
        assert c.finding_count == 0
        assert svc._derive_control_status(c) == "met"

        # Default findings list hides it; include_suppressed surfaces it.
        active = await svc.get_findings_for_control(db_session, "soc2", "CC6.8", asset_ids=[asset_id])
        assert active == []
        withsupp = await svc.get_findings_for_control(
            db_session, "soc2", "CC6.8", asset_ids=[asset_id], include_suppressed=True,
        )
        assert len(withsupp) == 1 and withsupp[0].suppressed is True

        # BOLA: a caller scoped elsewhere can't touch this mapping.
        assert await svc.set_mapping_suppressed(
            db_session, m.id, suppressed=False, reason=None,
            user_id="x", asset_ids=[str(uuid.uuid4())],
        ) is None

        # Restore → counts again.
        await svc.set_mapping_suppressed(
            db_session, m.id, suppressed=False, reason=None, user_id="analyst", asset_ids=[asset_id],
        )
        await db_session.commit()
        summary = await svc.get_framework_summary(db_session, "soc2", asset_ids=[asset_id])
        c = next(x for x in summary if x.control_id == "CC6.8")
        assert c.finding_count == 1
    finally:
        from sqlalchemy import delete
        await db_session.execute(delete(ComplianceControlMapping).where(ComplianceControlMapping.framework == "soc2"))
        await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.execute(delete(FrameworkControl).where(FrameworkControl.framework == "soc2"))
        await db_session.execute(delete(Framework).where(Framework.id == "soc2"))
        await db_session.commit()
