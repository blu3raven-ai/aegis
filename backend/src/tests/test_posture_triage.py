"""Tests for posture triage resolvers: scanner breakdown, risk contributions,
exploitability summary, and SLA posture."""
from __future__ import annotations

import os
import uuid
from datetime import date

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete, select  # noqa: E402

from src.db.models import (  # noqa: E402
    Asset, EpssScore, Finding, FindingSlaStatus, Grant, KevEntry,
    SbomComponent, Team,
)
from src.db.models import PostureSnapshot  # noqa: E402
from src.posture.resolvers import (  # noqa: E402
    exploitability_summary, risk_contributions, scanner_breakdown, sla_posture,
)
from src.posture.service import get_posture_by_team, get_posture_trend  # noqa: E402


def _uuid() -> str:
    return str(uuid.uuid4())


async def _seed(db_session):
    """Two repos, open findings across tools/severities, with SBOM ecosystem
    mapping, KEV/EPSS scores, SLA breach statuses, and team grants."""
    a, b = _uuid(), _uuid()
    team_id = _uuid()

    db_session.add_all([
        Asset(id=a, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}",
              display_name="acme-org/api"),
        Asset(id=b, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}",
              display_name="acme-org/web"),
        Team(id=team_id, name="platform"),
    ])
    await db_session.flush()

    # Grant team both assets so the team dimension resolves them.
    db_session.add_all([
        Grant(subject_type="team", subject_id=team_id, asset_id=a),
        Grant(subject_type="team", subject_id=team_id, asset_id=b),
    ])
    await db_session.flush()

    # SBOM component ecosystem mapping (package_name -> ecosystem).
    db_session.add_all([
        SbomComponent(asset_id=a, purl="pkg:npm/express@4.18.2",
                      name="express", version="4.18.2", ecosystem="npm",
                      source_tool="syft"),
        SbomComponent(asset_id=b, purl="pkg:maven/log4j@2.14.1",
                      name="log4j", version="2.14.1", ecosystem="maven",
                      source_tool="syft"),
    ])
    await db_session.flush()

    # Findings across tools/severities. CVE-bearing findings get cve_id +
    # package_name for ecosystem / exploitability resolution.
    db_session.add_all([
        # deps: critical (KEV + high-EPSS), on asset a, npm/express
        Finding(tool="dependencies", asset_id=a, identity_key="f1",
                state="open", severity="critical", cve_id="CVE-KEV-1",
                package_name="express", archived=False),
        # deps: high, on asset b, maven/log4j
        Finding(tool="dependencies", asset_id=b, identity_key="f2",
                state="open", severity="high", cve_id="CVE-EPSS-HI",
                package_name="log4j", archived=False),
        # code_scanning: medium on asset a
        Finding(tool="code_scanning", asset_id=a, identity_key="f3",
                state="open", severity="medium", archived=False),
        # code_scanning: low on asset b
        Finding(tool="code_scanning", asset_id=b, identity_key="f4",
                state="open", severity="low", archived=False),
        # A dismissed (non-open) finding — must be excluded everywhere.
        Finding(tool="dependencies", asset_id=a, identity_key="f5",
                state="dismissed", severity="critical", archived=False),
        # An archived open finding — must be excluded.
        Finding(tool="dependencies", asset_id=a, identity_key="f6",
                state="open", severity="critical", archived=True),
    ])
    await db_session.flush()

    # KEV + EPSS enrichment tables.
    db_session.add_all([
        KevEntry(cve_id="CVE-KEV-1"),
        EpssScore(cve="CVE-EPSS-HI", score=0.95, percentile=0.97,
                   scored_date=date(2026, 6, 30)),
        # Low-percentile EPSS entry that must NOT count as high-EPSS.
        EpssScore(cve="CVE-LO", score=0.01, percentile=0.10,
                  scored_date=date(2026, 6, 30)),
    ])
    await db_session.flush()

    # SLA breach statuses: f1 (critical) + f2 (high) breached; f3/f4 not.
    findings = await db_session.execute(
        select(Finding.id, Finding.identity_key)
    )
    fids = {fk: fid for fid, fk in findings.all()}
    db_session.add_all([
        FindingSlaStatus(finding_id=fids["f1"], breached=True, breach_age_days=15),
        FindingSlaStatus(finding_id=fids["f2"], breached=True, breach_age_days=40),
        FindingSlaStatus(finding_id=fids["f3"], breached=False, breach_age_days=None),
        FindingSlaStatus(finding_id=fids["f4"], breached=False, breach_age_days=None),
    ])
    await db_session.commit()

    return a, b, team_id


async def _cleanup(db_session, *asset_ids):
    aids = [aid for aid in asset_ids if aid]
    if aids:
        await db_session.execute(
            delete(FindingSlaStatus).where(
                FindingSlaStatus.finding_id.in_(
                    select(Finding.id).where(Finding.asset_id.in_(aids))
                )
            )
        )
        await db_session.execute(delete(Finding).where(Finding.asset_id.in_(aids)))
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id.in_(aids)))
        await db_session.execute(delete(Grant).where(Grant.asset_id.in_(aids)))
        await db_session.execute(delete(Asset).where(Asset.id.in_(aids)))
    # Enrichment rows have stable CVEs — clear by explicit values.
    await db_session.execute(
        delete(KevEntry).where(KevEntry.cve_id == "CVE-KEV-1")
    )
    await db_session.execute(
        delete(EpssScore).where(EpssScore.cve.in_(["CVE-EPSS-HI", "CVE-LO"]))
    )
    # Teams without grants left over.
    await db_session.execute(delete(Team).where(Team.id.notin_(
        select(Grant.subject_id).where(Grant.subject_type == "team")
    )))
    await db_session.commit()


@pytest.mark.asyncio
async def test_scanner_breakdown_aggregates(db_session):
    a, b, _ = await _seed(db_session)
    try:
        items = scanner_breakdown(info_context={"asset_ids": [a, b]})
        by_tool = {it.scanner: it for it in items}

        deps = by_tool["dependencies"]
        # Only the two open non-archived deps findings (f1 crit, f2 high).
        assert deps.critical == 1
        assert deps.high == 1
        assert deps.medium == 0
        assert deps.low == 0
        assert deps.total == 2
        # critical=1, high=1 -> raw 10+5=15 (weighted volume, no clamp).
        assert deps.risk_score == 15
        # f1 + f2 are breached.
        assert deps.sla_breached == 2

        code = by_tool["code_scanning"]
        assert code.critical == 0
        assert code.medium == 1
        assert code.low == 1
        assert code.total == 2
        # medium=1, low=1 -> 2+1=3.
        assert code.risk_score == 3
        assert code.sla_breached == 0
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_scanner_breakdown_empty_scope(db_session):
    """Empty asset_ids is fail-closed (empty list, never an error)."""
    assert scanner_breakdown(info_context={"asset_ids": []}) == []


@pytest.mark.asyncio
async def test_scanner_breakdown_sorted_by_risk_not_count(db_session):
    """The riskiest scanner leads the list, not the one with the most findings.

    A volume sort would put the many-low-severity scanner first; a risk sort
    puts the few-critical scanner first. Guards against an ORDER BY COUNT(*)
    regression that buries the scanner an analyst most needs to act on.
    """
    a = _uuid()
    db_session.add(Asset(
        id=a, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/sort",
    ))
    await db_session.flush()
    # secret_scanning: 5 low findings (count=5, risk=5).
    # code_scanning: 1 critical finding (count=1, risk=10) — fewer, riskier.
    db_session.add_all([
        Finding(tool="secret_scanning", asset_id=a,
                identity_key=f"s-{i}-{uuid.uuid4()}", state="open", severity="low",
                archived=False)
        for i in range(5)
    ])
    db_session.add(Finding(
        tool="code_scanning", asset_id=a, identity_key=f"c-{uuid.uuid4()}",
        state="open", severity="critical", archived=False,
    ))
    await db_session.commit()
    try:
        items = scanner_breakdown(info_context={"asset_ids": [a]})
        by_tool = {it.scanner: it for it in items}
        # Both present with the expected counts/risk.
        assert by_tool["code_scanning"].total == 1
        assert by_tool["code_scanning"].risk_score == 10
        assert by_tool["secret_scanning"].total == 5
        assert by_tool["secret_scanning"].risk_score == 5
        # Risk sort: code_scanning (risk 10) must lead, despite having 1/5th
        # the findings of secret_scanning.
        assert items[0].scanner == "code_scanning"
        assert items[1].scanner == "secret_scanning"
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_risk_contributions_scanner(db_session):
    a, b, _ = await _seed(db_session)
    try:
        items = risk_contributions(dimension="scanner", info_context={"asset_ids": [a, b]})
        by_tool = {it.label: it for it in items}
        # deps raw=15, code raw=3; total org = 18.
        deps = by_tool["dependencies"]
        assert deps.risk_score == 15
        assert deps.count == 2
        assert deps.percentage == round(15 / 18 * 100)  # 83
        code = by_tool["code_scanning"]
        assert code.risk_score == 3
        assert code.count == 2
        assert code.percentage == round(3 / 18 * 100)  # 17
        # Sorted by risk_score desc.
        assert items[0].risk_score >= items[-1].risk_score
        assert all(it.dimension == "scanner" for it in items)
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_risk_contributions_severity_unclamped(db_session):
    """Severity dimension uses UNCLAMPED weighted counts so the four tier rows
    sum to the raw org weighted total."""
    a, b, _ = await _seed(db_session)
    try:
        items = risk_contributions(dimension="severity", info_context={"asset_ids": [a, b]})
        by_tier = {it.label: it for it in items}
        # critical: f1 only (f5 dismissed, f6 archived excluded) -> 1*10=10
        assert by_tier["critical"].risk_score == 10
        assert by_tier["critical"].count == 1
        # high: f2 -> 1*5=5
        assert by_tier["high"].risk_score == 5
        assert by_tier["high"].count == 1
        # medium: f3 -> 1*2=2
        assert by_tier["medium"].risk_score == 2
        assert by_tier["medium"].count == 1
        # low: f4 -> 1*1=1
        assert by_tier["low"].risk_score == 1
        assert by_tier["low"].count == 1
        # Sum = 18, unclamped (no 100 cap applied).
        assert sum(it.risk_score for it in items) == 18
        assert all(it.dimension == "severity" for it in items)
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_risk_contributions_repo(db_session):
    a, b, _ = await _seed(db_session)
    try:
        items = risk_contributions(dimension="repo", info_context={"asset_ids": [a, b]})
        by_repo = {it.label: it for it in items}
        # asset a: f1 crit (10) + f3 med (2) = 12.
        api = by_repo["acme-org/api"]
        assert api.risk_score == 12
        assert api.count == 2
        # asset b: f2 high (5) + f4 low (1) = 6.
        web = by_repo["acme-org/web"]
        assert web.risk_score == 6
        assert web.count == 2
        assert all(it.dimension == "repo" for it in items)
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_risk_contributions_team(db_session):
    a, b, _ = await _seed(db_session)
    try:
        items = risk_contributions(dimension="team", info_context={"asset_ids": [a, b]})
        assert len(items) == 1
        team = items[0]
        assert team.label == "platform"
        # Both assets granted -> all 4 open findings -> raw 10+5+2+1=18.
        assert team.risk_score == 18
        assert team.count == 4
        assert team.dimension == "team"
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_risk_contributions_ecosystem(db_session):
    a, b, _ = await _seed(db_session)
    try:
        items = risk_contributions(dimension="ecosystem", info_context={"asset_ids": [a, b]})
        by_eco = {it.label: it for it in items}
        # express (npm, asset a) -> f1 critical -> 10.
        npm = by_eco["npm"]
        assert npm.risk_score == 10
        assert npm.count == 1
        # log4j (maven, asset b) -> f2 high -> 5.
        maven = by_eco["maven"]
        assert maven.risk_score == 5
        assert maven.count == 1
        assert all(it.dimension == "ecosystem" for it in items)
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_risk_contributions_invalid_dimension(db_session):
    """Invalid dimension raises BAD_INPUT (GraphQL error)."""
    from src.graphql.resolver_utils import raise_bad_input
    with pytest.raises(Exception):
        risk_contributions(dimension="bogus", info_context={"asset_ids": []})
    # Confirm the guard fn is the one raising for unknown dimensions.
    try:
        risk_contributions(dimension="bogus", info_context={"asset_ids": ["x"]})
    except Exception as exc:
        assert "Invalid dimension" in str(exc)


@pytest.mark.asyncio
async def test_risk_contributions_empty_scope(db_session):
    for dim in ("scanner", "repo", "team", "severity", "ecosystem"):
        assert risk_contributions(dimension=dim, info_context={"asset_ids": []}) == []


@pytest.mark.asyncio
async def test_exploitability_summary(db_session):
    a, b, _ = await _seed(db_session)
    try:
        summary = exploitability_summary(info_context={"asset_ids": [a, b]})
        # CVE-KEV-1 is in kev_entries and open in scope.
        assert summary.kev_count == 1
        # CVE-EPSS-HI has percentile 0.97 >= 0.9.
        assert summary.high_epss_count == 1
        # epss_top delegated to EpssService; the high-EPSS finding surfaces.
        assert summary.epss_top is not None
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_exploitability_summary_empty_scope(db_session):
    summary = exploitability_summary(info_context={"asset_ids": []})
    assert summary.kev_count == 0
    assert summary.high_epss_count == 0
    assert summary.epss_top == []


@pytest.mark.asyncio
async def test_sla_posture(db_session):
    a, b, _ = await _seed(db_session)
    try:
        summary = sla_posture(info_context={"asset_ids": [a, b]})
        # f1 (critical) + f2 (high) breached.
        assert summary.total_breached == 2
        assert summary.critical_breached == 1
        assert summary.high_breached == 1
        assert summary.medium_breached == 0
        assert summary.low_breached == 0
        # max breach age = 40 (f2).
        assert summary.max_breach_age_days == 40
        # by_scanner: dependencies has 2 breached.
        by_tool = {r.scanner: r for r in summary.by_scanner}
        assert by_tool["dependencies"].breached == 2
        assert "code_scanning" not in by_tool
        # Sorted by breached desc.
        assert summary.by_scanner[0].breached >= summary.by_scanner[-1].breached
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_sla_posture_empty_scope(db_session):
    summary = sla_posture(info_context={"asset_ids": []})
    assert summary.total_breached == 0
    assert summary.max_breach_age_days == 0
    assert summary.by_scanner == []


@pytest.mark.asyncio
async def test_risk_contributions_ecosystem_collapses_versions(db_session):
    """A package with multiple versions in the SBOM must count its finding once.

    SbomComponent is unique on (asset_id, purl), so a bare join on name would
    multiply a finding's row by the version count. The ecosystem dimension must
    collapse versions (DISTINCT asset_id, name, ecosystem) — mirroring
    sbom_ecosystem_analytics — or production multi-version SBOMs inflate counts.
    """
    a = _uuid()
    db_session.add(Asset(
        id=a, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/multi",
    ))
    await db_session.flush()
    # Three versions of the same package name in one asset's SBOM.
    db_session.add_all([
        SbomComponent(asset_id=a, purl="pkg:npm/express@4.18.0",
                      name="express", version="4.18.0", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=a, purl="pkg:npm/express@4.18.2",
                      name="express", version="4.18.2", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=a, purl="pkg:npm/express@5.0.0",
                      name="express", version="5.0.0", ecosystem="npm", source_tool="syft"),
    ])
    await db_session.flush()
    # One critical finding on express.
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}",
        asset_id=a, state="open", severity="critical",
        package_name="express", cve_id="CVE-EXPR",
    ))
    await db_session.commit()
    try:
        items = risk_contributions(dimension="ecosystem", info_context={"asset_ids": [a]})
        by_eco = {it.label: it for it in items}
        npm = by_eco["npm"]
        # Must be 1 — not 3 (the version count).
        assert npm.count == 1, f"expected 1, got {npm.count} (version multiplicity not collapsed)"
        assert npm.risk_score == 10  # one critical -> raw 10
    finally:
        await _cleanup(db_session, a)


@pytest.mark.asyncio
async def test_resolvers_exclude_out_of_scope_assets(db_session):
    """All 4 triage resolvers exclude findings from assets not in asset_ids.

    Empty-scope tests only hit the early-return guard, not the SQL WHERE. This
    test seeds an out-of-scope asset (c) with a critical finding, KEV entry, and
    SLA breach, then asserts none appear when only [a, b] are scoped.
    """
    a, b, _ = await _seed(db_session)
    c = _uuid()
    cve_oos = "CVE-OOS-BOLA-1"

    db_session.add(Asset(
        id=c, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}",
        display_name="acme-org/oos",
    ))
    await db_session.flush()

    db_session.add(Finding(
        tool="code_scanning", asset_id=c, identity_key=f"oos-{uuid.uuid4()}",
        state="open", severity="critical", cve_id=cve_oos, archived=False,
    ))
    await db_session.flush()

    db_session.add(KevEntry(cve_id=cve_oos))
    oos_fid = (await db_session.execute(
        select(Finding.id).where(Finding.cve_id == cve_oos)
    )).scalar_one()
    db_session.add(FindingSlaStatus(finding_id=oos_fid, breached=True, breach_age_days=99))
    await db_session.commit()

    try:
        # scanner_breakdown: code_scanning for [a,b] = medium+low; c's critical excluded.
        items = scanner_breakdown(info_context={"asset_ids": [a, b]})
        by_tool = {it.scanner: it for it in items}
        code = by_tool["code_scanning"]
        assert code.critical == 0, f"c's critical leaked: critical={code.critical}"
        assert code.total == 2

        # risk_contributions: org risk for [a,b] = 18; c's 10 must not inflate it.
        rc = risk_contributions(dimension="scanner", info_context={"asset_ids": [a, b]})
        assert sum(it.risk_score for it in rc) == 18

        # exploitability_summary: kev_count=1 (CVE-KEV-1 only), c's KEV excluded.
        expl = exploitability_summary(info_context={"asset_ids": [a, b]})
        assert expl.kev_count == 1, f"c's KEV leaked: kev_count={expl.kev_count}"

        # sla_posture: total_breached=2 (f1+f2 only), c's breach excluded.
        sla = sla_posture(info_context={"asset_ids": [a, b]})
        assert sla.total_breached == 2, f"c's SLA breach leaked: total_breached={sla.total_breached}"
    finally:
        await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == cve_oos))
        await db_session.execute(
            delete(FindingSlaStatus).where(
                FindingSlaStatus.finding_id.in_(
                    select(Finding.id).where(Finding.asset_id == c)
                )
            )
        )
        await db_session.execute(delete(Finding).where(Finding.asset_id == c))
        await db_session.execute(delete(Asset).where(Asset.id == c))
        await db_session.commit()
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_posture_trend_risk_score_from_summed_totals_not_avg(db_session):
    """get_posture_trend must derive risk_score from summed severity totals.

    avg(per-asset gauge) diverges from posture_risk_gauge(summed totals): the
    gauge is concave, so summing then gauging is not the same as gauging then
    averaging. This test catches an avg-of-per-asset regression.
    """
    a1, a2 = _uuid(), _uuid()
    today = date.today()
    db_session.add(Asset(id=a1, type="repo", source="source_connection",
                         external_ref=f"github:acme-org/{uuid.uuid4().hex}",
                         display_name="acme-org/trend-a"))
    db_session.add(Asset(id=a2, type="repo", source="source_connection",
                         external_ref=f"github:acme-org/{uuid.uuid4().hex}",
                         display_name="acme-org/trend-b"))
    await db_session.flush()

    # Each asset: 5 criticals, band-weighted raw 50 (no KEV → Track ×1).
    # The trend sums risk_weight (50+50=100) then gauges once: gauge(100)=39.
    # Averaging per-asset gauges (gauge(50)=22 each) would give 22 ← the bug.
    for asset_id in (a1, a2):
        db_session.add(PostureSnapshot(
            asset_id=asset_id,
            snapshot_date=today,
            severity_critical=5,
            severity_high=0,
            severity_medium=0,
            severity_low=0,
            risk_weight=50,  # exploitability-weighted raw the nightly stores
            risk_score=22,   # pre-stored per-asset gauge (ignored; trend re-gauges the summed raw)
        ))
    await db_session.commit()

    try:
        points = get_posture_trend(asset_ids=[a1, a2], days=3)
        today_str = today.strftime("%Y-%m-%d")
        pt = next((p for p in points if p["date"] == today_str), None)
        assert pt is not None, "expected a trend point for today"
        assert pt["critical"] == 10, f"expected 10 total criticals, got {pt['critical']}"
        # gauge(10 summed criticals, raw 100) == 39; averaging per-asset gauges
        # (each 5 criticals → gauge 22) would give 22.
        assert pt["risk_score"] == 39, (
            f"expected 39 (gauge of summed totals), got {pt['risk_score']} — "
            "avg(per-asset gauge) regression"
        )
    finally:
        from sqlalchemy import delete
        await db_session.execute(
            delete(PostureSnapshot).where(PostureSnapshot.asset_id.in_([a1, a2]))
        )
        await _cleanup(db_session, a1)
        await _cleanup(db_session, a2)


@pytest.mark.asyncio
async def test_posture_by_team_applies_kev_weighting(db_session):
    """A team holding a KEV-listed critical must outrank a team holding an
    otherwise-identical critical without KEV — the team path must resolve KEV so
    the risk gauge applies the "act" band, matching the org hero."""
    a_kev, a_plain = _uuid(), _uuid()
    t_kev, t_plain = _uuid(), _uuid()
    db_session.add_all([
        Asset(id=a_kev, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}",
              display_name="acme-org/kev"),
        Asset(id=a_plain, type="repo", source="source_connection",
              external_ref=f"github:acme-org/{uuid.uuid4().hex}",
              display_name="acme-org/plain"),
        Team(id=t_kev, name="kev-team"),
        Team(id=t_plain, name="plain-team"),
    ])
    await db_session.flush()
    db_session.add_all([
        Grant(subject_type="team", subject_id=t_kev, asset_id=a_kev),
        Grant(subject_type="team", subject_id=t_plain, asset_id=a_plain),
    ])
    await db_session.flush()
    db_session.add_all([
        Finding(tool="dependencies", asset_id=a_kev, identity_key=f"k-{uuid.uuid4()}",
                state="open", severity="critical", cve_id="CVE-TEAMKEV", archived=False),
        Finding(tool="dependencies", asset_id=a_plain, identity_key=f"p-{uuid.uuid4()}",
                state="open", severity="critical", cve_id="CVE-TEAMPLAIN", archived=False),
    ])
    await db_session.flush()
    db_session.add(KevEntry(cve_id="CVE-TEAMKEV"))
    await db_session.commit()
    try:
        teams = get_posture_by_team(asset_ids=[a_kev, a_plain])
        by_name = {t["team_name"]: t for t in teams}
        kev_score = by_name["kev-team"]["risk_score"]["score"]
        plain_score = by_name["plain-team"]["risk_score"]["score"]
        # Same single-critical shape; KEV pushes the finding into the "act" band
        # (2.5x) so its gauge must be strictly higher. Without the fix both teams
        # score identically (KEV defaulted to False).
        assert kev_score > plain_score, (
            f"KEV team ({kev_score}) must outrank non-KEV team ({plain_score})"
        )
    finally:
        await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == "CVE-TEAMKEV"))
        await _cleanup(db_session, a_kev, a_plain)


@pytest.mark.asyncio
async def test_risk_contributions_ecosystem_no_cross_ecosystem_double_count(db_session):
    """A package name mapping to >1 ecosystem for an asset must count its
    finding once, not once per ecosystem — the SBOM subquery collapses to one
    row per (asset_id, name)."""
    a = _uuid()
    db_session.add(Asset(
        id=a, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/multi-eco",
    ))
    await db_session.flush()
    # Same package name recorded under two ecosystems in one asset's SBOM.
    db_session.add_all([
        SbomComponent(asset_id=a, purl="pkg:npm/shared@1.0.0",
                      name="shared", version="1.0.0", ecosystem="npm", source_tool="syft"),
        SbomComponent(asset_id=a, purl="pkg:pypi/shared@1.0.0",
                      name="shared", version="1.0.0", ecosystem="pypi", source_tool="syft"),
    ])
    await db_session.flush()
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}",
        asset_id=a, state="open", severity="critical",
        package_name="shared", cve_id="CVE-MULTI", archived=False,
    ))
    await db_session.commit()
    try:
        items = risk_contributions(dimension="ecosystem", info_context={"asset_ids": [a]})
        total_count = sum(it.count for it in items)
        total_risk = sum(it.risk_score for it in items)
        assert total_count == 1, (
            f"finding counted {total_count}x across ecosystems (cross-ecosystem fan-out)"
        )
        assert total_risk == 10, f"one critical -> raw 10, got {total_risk}"
    finally:
        await _cleanup(db_session, a)
