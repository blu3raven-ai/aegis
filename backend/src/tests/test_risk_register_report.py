"""Quarterly risk register report — payload assembly + template render.

Validates the open-risk grouping and the accepted-risk (dismissed) log with its
decision rationale, without invoking WeasyPrint/MinIO.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.db.models import Asset, Decision, Finding  # noqa: E402
from src.reports import service as svc  # noqa: E402


@pytest.mark.asyncio
async def test_risk_register_payload_and_template(db_session):
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    old = datetime.now(timezone.utc) - timedelta(days=15)
    db_session.add(Finding(
        tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="critical", title="RCE", first_seen_at=old,
    ))
    dismissed_key = f"k-{uuid.uuid4()}"
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=dismissed_key, asset_id=asset_id,
        state="dismissed", severity="medium", title="Low-risk dep", first_seen_at=old,
    ))
    db_session.add(Decision(
        tool="dependencies_scanning", asset_id=asset_id, identity_key=dismissed_key,
        status="dismissed", reason="Not exploitable in our usage", decided_by="analyst",
    ))
    await db_session.commit()

    try:
        payload = svc._build_risk_register_payload(title="Q2 Risk", asset_ids=[asset_id])
        assert payload["open_count"] == 1
        assert "critical" in payload["open_by_severity"]
        assert payload["accepted_count"] == 1
        acc = payload["accepted"][0]
        assert acc["reason"] == "Not exploitable in our usage"
        assert acc["decided_by"] == "analyst"

        html = svc._get_jinja_env().get_template("report_risk_register.html.j2").render(**payload)
        assert "Open risk register" in html
        assert "Accepted risks" in html
        assert "Not exploitable in our usage" in html

        # CSV carries both open and accepted rows.
        csv_bytes = svc._serialize_risk_register_csv(asset_ids=[asset_id])
        text = csv_bytes.decode()
        assert "severity,state,title,source,age_days,reason" in text
        assert "Not exploitable in our usage" in text
    finally:
        from sqlalchemy import delete
        await db_session.execute(delete(Decision).where(Decision.asset_id == asset_id))
        await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()
