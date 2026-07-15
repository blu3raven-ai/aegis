"""Tests for compute_risk_score (pure) and recompute_finding_risk_scores (DB)."""
from __future__ import annotations

from datetime import date
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import EpssScore, Finding, KevEntry
from src.findings.risk_score import (
    compute_risk_score,
    recompute_finding_risk_scores,
)


@pytest.mark.parametrize(
    "severity,expected_base",
    [
        ("critical", 80),
        ("high", 60),
        ("medium", 35),
        ("low", 15),
        ("CRITICAL", 80),
    ],
)
def test_compute_risk_score_severity_baselines(severity, expected_base):
    assert compute_risk_score(severity) == expected_base


def test_compute_risk_score_returns_none_when_severity_missing():
    assert compute_risk_score(None) is None
    assert compute_risk_score("") is None
    assert compute_risk_score("informational") is None


def test_compute_risk_score_kev_adds_fifteen():
    assert compute_risk_score("medium", kev_listed=True) == 35 + 15


def test_compute_risk_score_epss_scales_to_twenty():
    # EPSS percentile 1.0 → +20, 0.5 → +10, 0.25 → +5
    assert compute_risk_score("low", epss_percentile=1.0) == 15 + 20
    assert compute_risk_score("low", epss_percentile=0.5) == 15 + 10
    assert compute_risk_score("low", epss_percentile=0.25) == 15 + 5


def test_compute_risk_score_clamps_to_one_hundred():
    # critical (80) + KEV (15) + max EPSS (20) = 115 → clamped to 100
    assert compute_risk_score("critical", kev_listed=True, epss_percentile=1.0) == 100


def test_compute_risk_score_clamps_epss_out_of_range():
    assert compute_risk_score("low", epss_percentile=-0.5) == 15
    assert compute_risk_score("low", epss_percentile=2.0) == 35




@pytest_asyncio.fixture
async def rescore_fixture(db_session):
    """Seed two findings, a KEV entry, and an EPSS row. Clean up at teardown."""
    cve_kev = f"CVE-1999-{uuid4().hex[:4].upper()}"
    cve_epss = f"CVE-2000-{uuid4().hex[:4].upper()}"

    kev = KevEntry(cve_id=cve_kev, date_added=date(2026, 1, 1))
    epss = EpssScore(cve=cve_epss, score=0.5, percentile=0.9, scored_date=date(2026, 1, 1))
    f_critical = Finding(
        tool="dependencies_scanning", identity_key=f"k1-{uuid4()}",
        state="open", severity="critical", cve_id=cve_kev, detail={},
    )
    f_low_epss = Finding(
        tool="dependencies_scanning", identity_key=f"k2-{uuid4()}",
        state="open", severity="low", cve_id=cve_epss, detail={},
    )
    f_unknown = Finding(
        tool="dependencies_scanning", identity_key=f"k3-{uuid4()}",
        state="open", severity=None, cve_id=None, detail={},
    )
    db_session.add_all([kev, epss, f_critical, f_low_epss, f_unknown])
    await db_session.commit()
    yield f_critical, f_low_epss, f_unknown
    await db_session.execute(
        delete(Finding).where(Finding.id.in_((f_critical.id, f_low_epss.id, f_unknown.id)))
    )
    await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == cve_kev))
    await db_session.execute(delete(EpssScore).where(EpssScore.cve == cve_epss))
    await db_session.commit()


@pytest.mark.asyncio
async def test_recompute_sets_kev_finding_to_critical_plus_kev(db_session, rescore_fixture):
    f_critical, _, _ = rescore_fixture
    updated = await recompute_finding_risk_scores(db_session)
    assert updated >= 2  # both severity-known findings touched
    await db_session.commit()
    row = (await db_session.execute(
        select(Finding.risk_score).where(Finding.id == f_critical.id)
    )).scalar_one()
    assert row == 95  # 80 base + 15 KEV


@pytest.mark.asyncio
async def test_recompute_sets_low_finding_with_epss(db_session, rescore_fixture):
    _, f_low_epss, _ = rescore_fixture
    await recompute_finding_risk_scores(db_session)
    await db_session.commit()
    row = (await db_session.execute(
        select(Finding.risk_score).where(Finding.id == f_low_epss.id)
    )).scalar_one()
    # 15 (low) + round(20 * 0.9) = 15 + 18 = 33
    assert row == 33


@pytest.mark.asyncio
async def test_recompute_leaves_unknown_severity_alone(db_session, rescore_fixture):
    _, _, f_unknown = rescore_fixture
    await recompute_finding_risk_scores(db_session)
    await db_session.commit()
    row = (await db_session.execute(
        select(Finding.risk_score).where(Finding.id == f_unknown.id)
    )).scalar_one()
    assert row is None


@pytest.mark.asyncio
async def test_recompute_scoped_by_asset_ids(db_session, rescore_fixture):
    """Empty asset_ids list means nothing is rescored (fail-closed scope)."""
    f_critical, _, _ = rescore_fixture
    foreign = Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid4()}",
        state="open", severity="high", detail={},
    )
    db_session.add(foreign)
    await db_session.commit()
    try:
        updated = await recompute_finding_risk_scores(db_session, asset_ids=[])
        assert updated == 0
        await db_session.commit()
        row = (await db_session.execute(
            select(Finding.risk_score).where(Finding.id == foreign.id)
        )).scalar_one()
        assert row is None
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == foreign.id))
        await db_session.commit()
