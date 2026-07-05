"""SOC 2 evidence ZIP bundle — structure + contents.

Builds the real ZIP (no WeasyPrint/MinIO) and asserts the manifest + three CSVs,
including that a mapped finding substantiates its control.
"""
from __future__ import annotations

import io
import os
import uuid
import zipfile

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.compliance.models import ComplianceControlMapping, Framework, FrameworkControl  # noqa: E402
from src.db.models import Asset, Finding  # noqa: E402
from src.reports import service as svc  # noqa: E402


@pytest.mark.asyncio
async def test_soc2_evidence_zip(db_session):
    # The bundled framework isn't seeded in the create_all test schema, so seed
    # a minimal SOC 2 + one control here.
    db_session.add(Framework(id="soc2", label="SOC 2", is_custom=False))
    db_session.add(FrameworkControl(framework="soc2", control_id="CC6.8", title="Detect malicious software"))
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.flush()
    f = Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="high", title="Vulnerable dep",
    )
    db_session.add(f)
    await db_session.flush()
    db_session.add(ComplianceControlMapping(
        finding_id=f.id, framework="soc2", control_id="CC6.8",
        confidence=0.9, rationale="Vulnerable component detected",
    ))
    await db_session.commit()

    try:
        blob = svc._serialize_soc2_evidence_zip(asset_ids=[asset_id], title="SOC 2 Evidence")
        zf = zipfile.ZipFile(io.BytesIO(blob))
        names = set(zf.namelist())
        assert names == {"MANIFEST.txt", "controls.csv", "mapped_findings.csv", "accepted_risks.csv"}

        controls = zf.read("controls.csv").decode()
        assert "CC6.8" in controls
        assert "control_id,title,category,status" in controls

        mapped = zf.read("mapped_findings.csv").decode()
        assert "CC6.8" in mapped
        assert "Vulnerable component detected" in mapped
    finally:
        from sqlalchemy import delete
        await db_session.execute(delete(ComplianceControlMapping).where(ComplianceControlMapping.framework == "soc2"))
        await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.execute(delete(FrameworkControl).where(FrameworkControl.framework == "soc2"))
        await db_session.execute(delete(Framework).where(Framework.id == "soc2"))
        await db_session.commit()
