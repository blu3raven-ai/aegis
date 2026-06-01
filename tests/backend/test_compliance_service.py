"""Integration tests for the compliance service layer."""
from __future__ import annotations

from datetime import datetime, timezone

from src.compliance.models import ComplianceControlMapping, FrameworkControl
from src.compliance.service import (
    get_controls_for_finding,
    get_findings_for_control,
    get_framework_summary,
    list_controls_for_framework,
    list_frameworks,
)
from src.db.helpers import run_db
from src.db.models import Finding


def _now():
    return datetime.now(timezone.utc)


def _seed_control(framework: str, control_id: str, title: str) -> None:
    async def _run(session):
        from sqlalchemy import select
        res = await session.execute(
            select(FrameworkControl).where(
                FrameworkControl.framework == framework,
                FrameworkControl.control_id == control_id,
            )
        )
        if not res.scalars().first():
            session.add(FrameworkControl(
                framework=framework, control_id=control_id, title=title,
                description="svc test", category="Service Tests",
            ))
    run_db(_run)


def _seed_finding(tool="secrets", org="example-org", severity="critical", state="open", suffix="") -> int:
    now = _now()
    async def _run(session):
        f = Finding(
            tool=tool, org=org, repo="svc-test-repo",
            identity_key=f"svc-key-{org}-{tool}-{severity}-{state}-{suffix}",
            state=state, severity=severity, detail={},
            first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now,
        )
        session.add(f)
        await session.flush()
        return f.id
    return run_db(_run)


def _seed_mapping(finding_id, framework, control_id, confidence=0.9, chain_id=None) -> None:
    async def _run(session):
        session.add(ComplianceControlMapping(
            finding_id=finding_id, chain_id=chain_id,
            framework=framework, control_id=control_id,
            confidence=confidence, rationale="svc test rationale", created_at=_now(),
        ))
    run_db(_run)


# list_frameworks

def test_list_frameworks_returns_all_three():
    async def _run(_session):
        return await list_frameworks()
    result = run_db(_run)
    assert {f["id"] for f in result} == {"soc2", "iso27001", "pci-dss"}


def test_list_frameworks_has_labels():
    async def _run(_session):
        return await list_frameworks()
    result = run_db(_run)
    for item in result:
        assert item["label"]


# list_controls_for_framework

def test_list_controls_for_soc2_contains_seeded():
    _seed_control("soc2", "CC_SVC1", "SVC1")
    async def _run(session):
        return await list_controls_for_framework(session, "soc2")
    controls = run_db(_run)
    assert "CC_SVC1" in [c.control_id for c in controls]


def test_list_controls_wrong_framework_returns_empty():
    async def _run(session):
        return await list_controls_for_framework(session, "nonexistent")
    assert run_db(_run) == []


# get_controls_for_finding

def test_get_controls_for_finding_returns_mappings():
    _seed_control("soc2", "CC6_SVC_A", "Access SVC")
    fid = _seed_finding(tool="secrets", org="svc-access-org", suffix="acc")
    _seed_mapping(fid, "soc2", "CC6_SVC_A", confidence=0.95)
    async def _run(session):
        return await get_controls_for_finding(session, fid)
    results = run_db(_run)
    assert len(results) >= 1
    r = results[0]
    assert r["framework"] == "soc2"
    assert r["confidence"] == 0.95
    assert "title" in r


def test_get_controls_for_finding_unknown_id_returns_empty():
    async def _run(session):
        return await get_controls_for_finding(session, 999_999_999)
    assert run_db(_run) == []


# get_findings_for_control

def test_get_findings_for_control_returns_correct_org():
    _seed_control("iso27001", "A8_SVC_FW", "A8 SVC")
    fid_in = _seed_finding(tool="dependencies", org="svc-org-in", severity="high", suffix="in")
    fid_out = _seed_finding(tool="dependencies", org="svc-org-out", severity="high", suffix="out")
    _seed_mapping(fid_in, "iso27001", "A8_SVC_FW")
    _seed_mapping(fid_out, "iso27001", "A8_SVC_FW")
    async def _run(session):
        return await get_findings_for_control(session, "iso27001", "A8_SVC_FW", "svc-org-in")
    results = run_db(_run)
    assert len(results) == 1
    assert results[0].org == "svc-org-in"


def test_get_findings_for_control_excludes_fixed():
    _seed_control("soc2", "CC6_SVC_FX", "Fixed SVC")
    fid_open = _seed_finding(org="svc-fx-org", state="open", suffix="open-fx")
    fid_fixed = _seed_finding(org="svc-fx-org", state="fixed", suffix="fixed-fx")
    _seed_mapping(fid_open, "soc2", "CC6_SVC_FX")
    _seed_mapping(fid_fixed, "soc2", "CC6_SVC_FX")
    async def _run(session):
        return await get_findings_for_control(session, "soc2", "CC6_SVC_FX", "svc-fx-org")
    results = run_db(_run)
    assert len(results) == 1
    assert results[0].state == "open"


# get_framework_summary

def test_get_framework_summary_counts():
    _seed_control("pci-dss", "6_3_SVC_SUM", "PCI SVC Sum")
    fid1 = _seed_finding(tool="dependencies", org="svc-sum-org", severity="critical", suffix="s1")
    fid2 = _seed_finding(tool="containers", org="svc-sum-org", severity="high", suffix="s2")
    _seed_mapping(fid1, "pci-dss", "6_3_SVC_SUM")
    _seed_mapping(fid2, "pci-dss", "6_3_SVC_SUM")
    async def _run(session):
        return await get_framework_summary(session, "pci-dss", "svc-sum-org")
    items = run_db(_run)
    matches = [i for i in items if i.control_id == "6_3_SVC_SUM"]
    assert len(matches) == 1
    assert matches[0].finding_count == 2
    assert matches[0].highest_severity == "critical"


def test_get_framework_summary_zero_for_org_with_no_findings():
    _seed_control("soc2", "CC7_SVC_NF", "No Finding SVC")
    async def _run(session):
        return await get_framework_summary(session, "soc2", "svc-nf-org")
    items = run_db(_run)
    for item in items:
        if item.control_id == "CC7_SVC_NF":
            assert item.finding_count == 0
            break


def test_get_framework_summary_highest_severity():
    _seed_control("iso27001", "A8_SVC_SEV", "Sev SVC")
    fid_c = _seed_finding(org="svc-sev-org", severity="critical", suffix="sev-c")
    fid_m = _seed_finding(org="svc-sev-org", severity="medium", suffix="sev-m")
    _seed_mapping(fid_c, "iso27001", "A8_SVC_SEV")
    _seed_mapping(fid_m, "iso27001", "A8_SVC_SEV")
    async def _run(session):
        return await get_framework_summary(session, "iso27001", "svc-sev-org")
    items = run_db(_run)
    matches = [i for i in items if i.control_id == "A8_SVC_SEV"]
    assert matches[0].highest_severity == "critical"
