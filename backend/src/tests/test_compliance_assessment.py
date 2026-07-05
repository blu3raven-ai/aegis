"""Manual control attestation overrides the finding-derived status.

A control with open critical findings derives 'unmet', but an analyst who marks
it 'compliant' (with evidence) flips the effective status to 'met' — the layer
auditors sign off on. Also covers clearing back to auto and bad-status rejection.
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.compliance import service as svc  # noqa: E402
from src.compliance.models import (  # noqa: E402
    ControlSummaryItem,
    Framework,
    FrameworkControl,
)


def _item(**kw) -> ControlSummaryItem:
    base = dict(
        framework="fw", control_id="C1", title="t", category=None,
        finding_count=0, highest_severity=None,
    )
    base.update(kw)
    return ControlSummaryItem(**base)


def test_manual_status_overrides_derived():
    # Derived would be 'unmet' (open critical), but an attestation wins.
    item = _item(finding_count=3, highest_severity="critical", manual_status="compliant")
    assert svc._derive_control_status(item) == "met"

    item = _item(finding_count=3, highest_severity="critical", manual_status="non_compliant")
    assert svc._derive_control_status(item) == "unmet"

    # not_applicable is not a gap.
    item = _item(finding_count=3, highest_severity="critical", manual_status="not_applicable")
    assert svc._derive_control_status(item) == "met"

    # No manual status → falls back to the finding-derived signal.
    item = _item(finding_count=3, highest_severity="critical")
    assert svc._derive_control_status(item) == "unmet"


@pytest.mark.asyncio
async def test_upsert_assessment_roundtrip(db_session):
    fw_id = f"fw-{uuid.uuid4().hex[:8]}"
    db_session.add(Framework(id=fw_id, label="Test FW", is_custom=True))
    db_session.add(FrameworkControl(framework=fw_id, control_id="C1", title="Control one"))
    await db_session.commit()

    try:
        # Set an attestation with evidence.
        row = await svc.upsert_control_assessment(
            db_session, fw_id, "C1",
            status="compliant", evidence_note="Reviewed Q2 ", evidence_url="https://e",
            user_id="u1",
        )
        await db_session.commit()
        assert row.status == "compliant"
        assert row.evidence_note == "Reviewed Q2"  # trimmed

        # It surfaces in the summary overlay (empty scope path still includes it).
        summary = await svc.get_framework_summary(db_session, fw_id, asset_ids=[])
        c1 = next(c for c in summary if c.control_id == "C1")
        assert c1.manual_status == "compliant"
        assert c1.evidence_note == "Reviewed Q2"
        assert c1.assessed_by == "u1"

        # Clearing with 'auto' drops the override but keeps the row/evidence.
        row = await svc.upsert_control_assessment(
            db_session, fw_id, "C1",
            status="auto", evidence_note="Reviewed Q2", evidence_url=None, user_id="u1",
        )
        await db_session.commit()
        assert row.status is None

        # Unknown control / framework / bad status all raise.
        with pytest.raises(svc.ControlNotFound):
            await svc.upsert_control_assessment(
                db_session, fw_id, "NOPE", status="compliant",
                evidence_note=None, evidence_url=None, user_id="u1",
            )
        with pytest.raises(ValueError):
            await svc.upsert_control_assessment(
                db_session, fw_id, "C1", status="bogus",
                evidence_note=None, evidence_url=None, user_id="u1",
            )
    finally:
        from sqlalchemy import delete
        from src.compliance.models import ComplianceControlAssessment
        await db_session.execute(delete(ComplianceControlAssessment).where(ComplianceControlAssessment.framework == fw_id))
        await db_session.execute(delete(FrameworkControl).where(FrameworkControl.framework == fw_id))
        await db_session.execute(delete(Framework).where(Framework.id == fw_id))
        await db_session.commit()
