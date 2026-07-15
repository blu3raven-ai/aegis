"""Executive summary report — payload assembly, sparkline, template render.

Covers the data layer and the Jinja template (which validates the payload
contract) without invoking WeasyPrint/MinIO, so it runs in plain CI.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.db.models import Asset, Finding  # noqa: E402
from src.reports import service as svc  # noqa: E402


def test_sparkline_points():
    assert svc._sparkline_points([]) == ""
    # Single point sits on the mid-line across the full width.
    assert svc._sparkline_points([5], width=480, height=44) == "0,22.0 480,22.0"
    pts = svc._sparkline_points([0, 10], width=100, height=40)
    # Min maps to the baseline (y=height), max to the top (y=0).
    assert pts == "0.0,40.0 100.0,0.0"


@pytest.mark.asyncio
async def test_executive_payload_and_template(db_session):
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    old = datetime.now(timezone.utc) - timedelta(days=20)
    db_session.add(Finding(
        tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="critical", title="RCE in handler", first_seen_at=old,
    ))
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="high", title="Vulnerable dep", first_seen_at=old,
    ))
    await db_session.commit()

    try:
        payload = svc._build_executive_pdf_payload(title="Exec review", asset_ids=[asset_id])

        assert payload["title"] == "Exec review"
        assert payload["period_label"] == "Last 30 days"
        assert payload["counts"]["total"] >= 2
        assert payload["counts"]["critical"] >= 1
        # The two seeded findings surface as urgent, critical first.
        assert payload["top_findings"]
        assert payload["top_findings"][0]["severity"] == "critical"
        assert "trend_sparkline" in payload

        # Rendering the template validates the payload contract end-to-end
        # (every referenced key exists) without needing WeasyPrint.
        html = svc._get_jinja_env().get_template("report_executive.html.j2").render(**payload)
        assert "Exec review" in html
        assert "Most urgent open findings" in html
        assert "RCE in handler" in html
    finally:
        from sqlalchemy import delete
        await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()
