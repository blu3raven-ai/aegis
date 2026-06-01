"""Integration tests for the compliance REST endpoints."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.compliance.models import ComplianceControlMapping, FrameworkControl
from src.compliance.router import router as compliance_router
from src.db.helpers import run_db
from src.db.models import Finding


def _now():
    return datetime.now(timezone.utc)


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)

    @app.middleware("http")
    async def _inject_auth(request: Request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_role = "owner"
        request.state.user_role_id = None
        return await call_next(request)

    return app


@pytest.fixture(scope="module")
def client():
    return TestClient(_make_app(), raise_server_exceptions=True)


def _seed_control(framework, control_id, title):
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
                description="rtr test", category="Router Tests",
            ))
    run_db(_run)


def _seed_finding_and_mapping(org, tool, severity, framework, control_id, suffix="") -> int:
    async def _run(session):
        now = _now()
        f = Finding(
            tool=tool, org=org, repo="rtr-repo",
            identity_key=f"rtr-{org}-{tool}-{framework}-{control_id}-{suffix}",
            state="open", severity=severity, detail={},
            first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now,
        )
        session.add(f)
        await session.flush()
        session.add(ComplianceControlMapping(
            finding_id=f.id, chain_id=None,
            framework=framework, control_id=control_id,
            confidence=0.9, rationale="rtr rationale", created_at=now,
        ))
        return f.id
    return run_db(_run)


# GET /api/v1/compliance/frameworks

def test_list_frameworks_200(client):
    resp = client.get("/api/v1/compliance/frameworks")
    assert resp.status_code == 200
    ids = {f["id"] for f in resp.json()}
    assert ids == {"soc2", "iso27001", "pci-dss"}


def test_list_frameworks_has_labels(client):
    for f in client.get("/api/v1/compliance/frameworks").json():
        assert f["label"]


# GET /api/v1/compliance/frameworks/{framework}/controls

def test_get_controls_unknown_framework_404(client):
    assert client.get("/api/v1/compliance/frameworks/unknown-fw/controls").status_code == 404


def test_get_controls_soc2_returns_list(client):
    _seed_control("soc2", "CC6_RTR1", "RTR1")
    resp = client.get("/api/v1/compliance/frameworks/soc2/controls")
    assert resp.status_code == 200
    assert "CC6_RTR1" in [c["control_id"] for c in resp.json()]


def test_get_controls_iso27001_shape(client):
    _seed_control("iso27001", "A8_RTR1", "ISO RTR1")
    resp = client.get("/api/v1/compliance/frameworks/iso27001/controls")
    assert resp.status_code == 200
    for ctrl in resp.json():
        assert "control_id" in ctrl and "title" in ctrl and "framework" in ctrl


def test_get_controls_pci_returns_list(client):
    _seed_control("pci-dss", "6_RTR_L", "PCI List")
    assert isinstance(client.get("/api/v1/compliance/frameworks/pci-dss/controls").json(), list)


# GET /api/v1/compliance/frameworks/{framework}/summary

def test_get_summary_unknown_framework_404(client):
    assert client.get("/api/v1/compliance/frameworks/unknown/summary?org_id=x").status_code == 404


def test_get_summary_returns_controls_list(client):
    _seed_control("pci-dss", "6_RTR_SUM", "PCI Sum")
    _seed_finding_and_mapping("rtr-sum-org", "dependencies", "critical", "pci-dss", "6_RTR_SUM")
    resp = client.get("/api/v1/compliance/frameworks/pci-dss/summary?org_id=rtr-sum-org")
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "pci-dss"
    matches = [c for c in data["controls"] if c["control_id"] == "6_RTR_SUM"]
    assert len(matches) == 1
    assert matches[0]["finding_count"] >= 1


def test_get_summary_has_label(client):
    resp = client.get("/api/v1/compliance/frameworks/soc2/summary?org_id=x")
    assert resp.json()["label"] == "SOC 2"


def test_get_summary_org_with_no_findings_returns_zeros(client):
    for ctrl in client.get("/api/v1/compliance/frameworks/soc2/summary?org_id=empty-rtr-org").json()["controls"]:
        assert ctrl["finding_count"] == 0


# GET /api/v1/compliance/controls/{framework}/{control_id}/findings

def test_get_findings_by_control_unknown_framework_404(client):
    assert client.get("/api/v1/compliance/controls/bad-fw/CC6.1/findings?org_id=x").status_code == 404


def test_get_findings_by_control_returns_findings(client):
    _seed_control("soc2", "CC6_RTR_FND", "FND")
    fid = _seed_finding_and_mapping("rtr-find-org", "secrets", "critical", "soc2", "CC6_RTR_FND")
    resp = client.get("/api/v1/compliance/controls/soc2/CC6_RTR_FND/findings?org_id=rtr-find-org")
    assert resp.status_code == 200
    assert fid in [f["id"] for f in resp.json()["findings"]]


def test_get_findings_by_control_shape(client):
    _seed_control("pci-dss", "6_RTR_SHP", "Shape")
    _seed_finding_and_mapping("rtr-shp-org", "dependencies", "high", "pci-dss", "6_RTR_SHP")
    resp = client.get("/api/v1/compliance/controls/pci-dss/6_RTR_SHP/findings?org_id=rtr-shp-org")
    for f in resp.json()["findings"]:
        assert all(k in f for k in ("id", "tool", "severity", "confidence", "rationale"))


def test_get_findings_by_control_empty_for_wrong_org(client):
    _seed_control("iso27001", "A8_RTR_ORG", "Org Iso")
    _seed_finding_and_mapping("rtr-org-a", "containers", "high", "iso27001", "A8_RTR_ORG")
    resp = client.get("/api/v1/compliance/controls/iso27001/A8_RTR_ORG/findings?org_id=rtr-org-b")
    assert resp.json()["findings"] == []


# GET /api/v1/compliance/findings/{finding_id}/controls

def test_get_controls_for_finding_returns_data(client):
    _seed_control("iso27001", "A9_RTR_C", "A9 RTR")
    fid = _seed_finding_and_mapping("rtr-ctrl-org", "secrets", "high", "iso27001", "A9_RTR_C")
    resp = client.get(f"/api/v1/compliance/findings/{fid}/controls")
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding_id"] == fid
    assert any(c["control_id"] == "A9_RTR_C" for c in data["controls"])


def test_get_controls_for_finding_no_mappings_empty(client):
    async def _seed(session):
        now = _now()
        f = Finding(
            tool="sast", org="rtr-nm-org", repo=None,
            identity_key="rtr-no-mapping-key-unique",
            state="open", severity="low", detail={},
            first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now,
        )
        session.add(f)
        await session.flush()
        return f.id
    fid = run_db(_seed)
    resp = client.get(f"/api/v1/compliance/findings/{fid}/controls")
    assert resp.json()["controls"] == []


def test_get_controls_for_finding_includes_title(client):
    _seed_control("soc2", "CC6_RTR_T", "Title Control")
    fid = _seed_finding_and_mapping("rtr-t-org", "iac", "medium", "soc2", "CC6_RTR_T")
    resp = client.get(f"/api/v1/compliance/findings/{fid}/controls")
    ctrl = next(c for c in resp.json()["controls"] if c["control_id"] == "CC6_RTR_T")
    assert ctrl["title"] == "Title Control"
    assert "confidence" in ctrl
