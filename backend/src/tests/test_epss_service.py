"""Tests for the EPSS service layer.

upsert_scores / get_score / top_findings_by_* run against a real DB session.
The fetcher (HTTP path) is exercised separately — here we focus on the
service contract: empty inputs, missing rows, scope enforcement, and the
fail-closed behaviour when org_id is supplied without asset_ids.
"""
from __future__ import annotations

from datetime import date
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Asset, EpssScore, Finding
from src.epss.service import EpssService


@pytest.fixture
def svc() -> EpssService:
    return EpssService()




def test_upsert_scores_empty_iterable_returns_zero_and_skips_db(svc):
    # No rows in → no DB hit, zero new. Cheap fast-path is important for the
    # daily refresh job when the feed is unchanged.
    assert svc.upsert_scores([]) == 0


@pytest_asyncio.fixture
async def epss_cleanup(db_session):
    """Track CVE IDs inserted by a test so we can purge them at teardown."""
    inserted: list[str] = []
    yield inserted
    if inserted:
        await db_session.execute(delete(EpssScore).where(EpssScore.cve.in_(inserted)))
        await db_session.commit()


def test_upsert_scores_inserts_new_rows_and_returns_count(svc, epss_cleanup):
    cve_a = f"CVE-9999-{uuid4().hex[:6].upper()}"
    cve_b = f"CVE-9999-{uuid4().hex[:6].upper()}"
    epss_cleanup.extend([cve_a, cve_b])

    n = svc.upsert_scores([
        {"cve": cve_a, "score": 0.5, "percentile": 0.7, "scored_date": date(2026, 1, 1)},
        {"cve": cve_b, "score": 0.9, "percentile": 0.99, "scored_date": date(2026, 1, 1)},
    ])
    assert n == 2


def test_upsert_scores_second_call_does_not_recount_existing_rows(svc, epss_cleanup):
    cve = f"CVE-9999-{uuid4().hex[:6].upper()}"
    epss_cleanup.append(cve)
    row = {"cve": cve, "score": 0.1, "percentile": 0.2, "scored_date": date(2026, 1, 1)}

    assert svc.upsert_scores([row]) == 1
    # Same row again — only the score/percentile update should fire, count
    # of net-new rows should be 0.
    row_v2 = {**row, "score": 0.55}
    assert svc.upsert_scores([row_v2]) == 0

    fetched = svc.get_score(cve)
    assert fetched is not None
    assert fetched.score == pytest.approx(0.55)




def test_get_score_missing_cve_returns_none(svc):
    assert svc.get_score(f"CVE-0000-{uuid4().hex[:6].upper()}") is None


def test_get_score_uppercases_cve_lookup(svc, epss_cleanup):
    cve = f"CVE-9999-{uuid4().hex[:6].upper()}"
    epss_cleanup.append(cve)
    svc.upsert_scores([
        {"cve": cve, "score": 0.42, "percentile": 0.84, "scored_date": date(2026, 1, 1)},
    ])

    out = svc.get_score(cve.lower())
    assert out is not None
    assert out.cve == cve




def test_top_findings_by_epss_requires_org_or_asset_ids(svc):
    with pytest.raises(ValueError, match="org_id or asset_ids"):
        svc.top_findings_by_epss(org_id=None, asset_ids=None)


def test_top_findings_by_epss_empty_asset_ids_returns_empty_list(svc):
    # Empty scope short-circuits — never hits the DB. Important so a caller
    # that resolved 0 assets doesn't accidentally trigger an unbounded query.
    assert svc.top_findings_by_epss(asset_ids=[]) == []


def test_top_findings_by_epss_org_only_is_fail_closed(svc):
    # Post-Plan-D the org-only path returns no rows by design; locks that.
    assert svc.top_findings_by_epss(org_id="any-org") == []




@pytest_asyncio.fixture
async def epss_top_fixture(db_session):
    """Seed one asset, one open Finding with a typed cve_id, and a matching
    EpssScore so the JOIN succeeds end-to-end."""
    cve = f"CVE-9999-{uuid4().hex[:6].upper()}"
    asset = Asset(
        type="repo",
        source="source_connection",
        external_ref=f"github:acme/{uuid4().hex[:6]}",
        display_name=f"acme/{uuid4().hex[:6]}",
    )
    db_session.add(asset)
    await db_session.flush()
    finding = Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid4()}",
        state="open",
        severity="critical",
        title="log4j",
        cve_id=cve,
        detail={},
        asset_id=str(asset.id),
    )
    score = EpssScore(cve=cve, score=0.95, percentile=0.99, scored_date=date(2026, 1, 1))
    db_session.add_all([finding, score])
    await db_session.commit()

    yield {"cve": cve, "asset_id": str(asset.id), "finding_id": finding.id}

    await db_session.execute(delete(Finding).where(Finding.id == finding.id))
    await db_session.execute(delete(EpssScore).where(EpssScore.cve == cve))
    await db_session.execute(delete(Asset).where(Asset.id == asset.id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_top_findings_by_asset_ids_returns_expected_shape(svc, epss_top_fixture):
    rows = svc.top_findings_by_asset_ids([epss_top_fixture["asset_id"]], limit=5)
    assert len(rows) >= 1
    match = next(r for r in rows if r["cve"] == epss_top_fixture["cve"])
    assert match["epss_score"] == pytest.approx(0.95)
    assert match["epss_percentile"] == pytest.approx(0.99)
    assert match["severity"] == "critical"
    assert match["scored_date"] == "2026-01-01"


@pytest.mark.asyncio
async def test_top_findings_by_epss_with_asset_scope_returns_rows(svc, epss_top_fixture):
    rows = svc.top_findings_by_epss(
        org_id=None, limit=5, asset_ids=[epss_top_fixture["asset_id"]],
    )
    cves = {r["cve"] for r in rows}
    assert epss_top_fixture["cve"] in cves


@pytest.mark.asyncio
async def test_top_findings_by_epss_unrelated_asset_id_yields_empty(
    svc, epss_top_fixture,
):
    # asset_id is a UUID column — use a fresh UUID that no Finding references.
    rows = svc.top_findings_by_epss(
        org_id=None, asset_ids=[str(uuid4())], limit=5,
    )
    assert rows == []


@pytest.mark.asyncio
async def test_top_findings_by_epss_skips_non_open_findings(
    db_session, svc, epss_top_fixture,
):
    # Closed/fixed/dismissed findings must not surface in the EPSS top list
    # — the prioritisation surface is for actionable, currently-open work only.
    closed = Finding(
        tool="dependencies_scanning",
        identity_key=f"closed-{uuid4()}",
        state="fixed",  # not "open" → excluded
        severity="critical",
        title="historical",
        cve_id=epss_top_fixture["cve"],
        detail={},
        asset_id=epss_top_fixture["asset_id"],
    )
    db_session.add(closed)
    await db_session.commit()
    try:
        rows = svc.top_findings_by_asset_ids([epss_top_fixture["asset_id"]], limit=5)
        ids = {r["finding_id"] for r in rows}
        assert closed.id not in ids
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == closed.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_top_findings_join_falls_back_to_identity_key_contains(
    db_session, svc,
):
    # cve_id was added later; older Finding rows have it NULL but encode the
    # CVE in identity_key. The OR-join `Finding.cve_id == EpssScore.cve OR
    # Finding.identity_key.contains(EpssScore.cve)` must still match them so
    # the historical backlog stays prioritisable.
    cve = f"CVE-9999-{uuid4().hex[:6].upper()}"
    asset = Asset(
        type="repo", source="source_connection",
        external_ref=f"github:acme-{uuid4().hex[:6]}/legacy",
        display_name="acme/legacy",
    )
    db_session.add(asset)
    await db_session.flush()
    finding = Finding(
        tool="dependencies_scanning",
        identity_key=f"pkg|legacy|{cve}|x.y.z",  # cve embedded in identity_key
        state="open", severity="high",
        cve_id=None,  # the column was never backfilled for this row
        title="legacy", detail={},
        asset_id=str(asset.id),
    )
    score = EpssScore(cve=cve, score=0.75, percentile=0.9, scored_date=date(2026, 1, 1))
    db_session.add_all([finding, score])
    await db_session.commit()
    try:
        rows = svc.top_findings_by_asset_ids([str(asset.id)], limit=5)
        match = next((r for r in rows if r["cve"] == cve), None)
        assert match is not None
        assert match["finding_id"] == finding.id
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == finding.id))
        await db_session.execute(delete(EpssScore).where(EpssScore.cve == cve))
        await db_session.execute(delete(Asset).where(Asset.id == asset.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_top_findings_orders_by_epss_score_descending(db_session, svc):
    # Highest-EPSS finding must come first — that's the entire point of the
    # surface. Two findings with different scores → assert ordering.
    cve_low = f"CVE-9999-{uuid4().hex[:6].upper()}"
    cve_high = f"CVE-9999-{uuid4().hex[:6].upper()}"
    asset = Asset(
        type="repo", source="source_connection",
        external_ref=f"github:acme-{uuid4().hex[:6]}/svc",
        display_name="acme/svc",
    )
    db_session.add(asset)
    await db_session.flush()
    f_low = Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid4()}", state="open", severity="medium",
        cve_id=cve_low, title="low-epss", detail={},
        asset_id=str(asset.id),
    )
    f_high = Finding(
        tool="dependencies_scanning",
        identity_key=f"k-{uuid4()}", state="open", severity="medium",
        cve_id=cve_high, title="high-epss", detail={},
        asset_id=str(asset.id),
    )
    s_low = EpssScore(cve=cve_low, score=0.05, percentile=0.10, scored_date=date(2026, 1, 1))
    s_high = EpssScore(cve=cve_high, score=0.92, percentile=0.99, scored_date=date(2026, 1, 1))
    db_session.add_all([f_low, f_high, s_low, s_high])
    await db_session.commit()
    try:
        rows = svc.top_findings_by_asset_ids([str(asset.id)], limit=10)
        scoped = [r for r in rows if r["cve"] in {cve_low, cve_high}]
        assert len(scoped) == 2
        # High EPSS comes first (DESC ordering)
        assert scoped[0]["cve"] == cve_high
        assert scoped[1]["cve"] == cve_low
    finally:
        await db_session.execute(
            delete(Finding).where(Finding.id.in_([f_low.id, f_high.id]))
        )
        await db_session.execute(
            delete(EpssScore).where(EpssScore.cve.in_([cve_low, cve_high]))
        )
        await db_session.execute(delete(Asset).where(Asset.id == asset.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_top_findings_limit_caps_returned_rows(db_session, svc):
    # Limit must be honoured server-side so a malformed caller can't pull
    # the entire findings table into memory. Three matched rows + limit=2
    # must return exactly 2.
    asset = Asset(
        type="repo", source="source_connection",
        external_ref=f"github:acme-{uuid4().hex[:6]}/cap",
        display_name="acme/cap",
    )
    db_session.add(asset)
    await db_session.flush()

    cves = [f"CVE-9999-{uuid4().hex[:6].upper()}" for _ in range(3)]
    findings = [
        Finding(
            tool="dependencies_scanning",
            identity_key=f"k-{uuid4()}",
            state="open", severity="high",
            cve_id=c, title=f"f-{i}", detail={},
            asset_id=str(asset.id),
        )
        for i, c in enumerate(cves)
    ]
    scores = [
        EpssScore(cve=c, score=0.5 + i * 0.05, percentile=0.5, scored_date=date(2026, 1, 1))
        for i, c in enumerate(cves)
    ]
    db_session.add_all(findings + scores)
    await db_session.commit()
    try:
        rows = svc.top_findings_by_asset_ids([str(asset.id)], limit=2)
        scoped = [r for r in rows if r["cve"] in set(cves)]
        assert len(scoped) == 2
    finally:
        await db_session.execute(
            delete(Finding).where(Finding.id.in_([f.id for f in findings]))
        )
        await db_session.execute(delete(EpssScore).where(EpssScore.cve.in_(cves)))
        await db_session.execute(delete(Asset).where(Asset.id == asset.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_top_findings_by_asset_ids_empty_list_returns_empty(
    db_session, svc, epss_top_fixture,
):
    # `top_findings_by_asset_ids` doesn't have the same short-circuit guard
    # as `top_findings_by_epss`, so an empty list must still safely yield
    # no rows (the WHERE asset_id IN () is empty-set safe in Postgres).
    rows = svc.top_findings_by_asset_ids([], limit=5)
    assert rows == []


def test_upsert_scores_idempotent_across_batches(svc, epss_cleanup):
    # The daily refresh job replays the same feed; running upsert twice on
    # the same batch must yield 1 net-new insert on the first call and 0 on
    # the second — proving the ON CONFLICT path is observed, not bypassed.
    cve_a = f"CVE-9999-{uuid4().hex[:6].upper()}"
    cve_b = f"CVE-9999-{uuid4().hex[:6].upper()}"
    epss_cleanup.extend([cve_a, cve_b])
    batch = [
        {"cve": cve_a, "score": 0.1, "percentile": 0.2, "scored_date": date(2026, 1, 1)},
        {"cve": cve_b, "score": 0.3, "percentile": 0.4, "scored_date": date(2026, 1, 1)},
    ]
    assert svc.upsert_scores(batch) == 2
    assert svc.upsert_scores(batch) == 0


def test_upsert_scores_mixed_batch_reports_only_new_rows(svc, epss_cleanup):
    # A real refresh combines existing and brand-new CVEs in one batch. Only
    # the brand-new ones should be reported as net-new inserts.
    cve_old = f"CVE-9999-{uuid4().hex[:6].upper()}"
    cve_new = f"CVE-9999-{uuid4().hex[:6].upper()}"
    epss_cleanup.extend([cve_old, cve_new])

    svc.upsert_scores([
        {"cve": cve_old, "score": 0.1, "percentile": 0.2, "scored_date": date(2026, 1, 1)},
    ])

    n = svc.upsert_scores([
        # cve_old already exists — not counted
        {"cve": cve_old, "score": 0.2, "percentile": 0.3, "scored_date": date(2026, 1, 2)},
        # cve_new is fresh — counted
        {"cve": cve_new, "score": 0.5, "percentile": 0.6, "scored_date": date(2026, 1, 2)},
    ])
    assert n == 1


def test_upsert_scores_overwrites_score_percentile_and_scored_date(svc, epss_cleanup):
    # The point of the daily refresh is to keep score/percentile/scored_date
    # fresh. Verify each of those columns is actually updated on conflict.
    cve = f"CVE-9999-{uuid4().hex[:6].upper()}"
    epss_cleanup.append(cve)
    svc.upsert_scores([
        {"cve": cve, "score": 0.1, "percentile": 0.2, "scored_date": date(2026, 1, 1)},
    ])
    svc.upsert_scores([
        {"cve": cve, "score": 0.9, "percentile": 0.99, "scored_date": date(2026, 6, 15)},
    ])
    fetched = svc.get_score(cve)
    assert fetched is not None
    assert fetched.score == pytest.approx(0.9)
    assert fetched.percentile == pytest.approx(0.99)
    assert fetched.scored_date == date(2026, 6, 15)
