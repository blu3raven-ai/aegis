"""Tests for CorrelationState — read-only lookups against testcontainers Postgres."""
from __future__ import annotations

import pytest

from src.correlation.state import CorrelationState, max_severity
from src.db.helpers import run_db
from src.db.models import Finding, SbomComponent, Chain, ChainEdge
from sqlalchemy import delete, insert


ORG = "acme-org"
REPO = "acme-org/test-repo"


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(ChainEdge))
        await session.execute(delete(Chain))
        await session.execute(delete(Finding).where(Finding.org == ORG))
        await session.execute(delete(SbomComponent).where(SbomComponent.org == ORG))
    run_db(_del)
    yield


def _insert_finding(**kwargs) -> int:
    defaults = {
        "tool": "dependencies",
        "org": ORG,
        "repo": REPO,
        "identity_key": "test-key",
        "state": "open",
        "severity": "high",
        "detail": {},
    }
    defaults.update(kwargs)

    async def _ins(session):
        f = Finding(**defaults)
        from src.shared.finding_queryable_fields import extract_queryable_fields
        qf = extract_queryable_fields(f.detail or {})
        f.cve_id = qf["cve_id"]
        f.file_path = qf["file_path"]
        f.title = qf["title"]
        f.rule_name = qf["rule_name"]
        f.package_name = qf["package_name"]
        session.add(f)
        await session.flush()
        return f.id
    return run_db(_ins)


# ── max_severity ──────────────────────────────────────────────────────────────


def test_max_severity_picks_highest():
    assert max_severity("medium", "critical", "low") == "critical"


def test_max_severity_single_value():
    assert max_severity("high") == "high"


def test_max_severity_none_values():
    assert max_severity(None, "medium", None) == "medium"


def test_max_severity_all_none():
    assert max_severity(None, None) == "unknown"


# ── lookup_findings ───────────────────────────────────────────────────────────


def test_lookup_findings_by_org():
    _insert_finding(identity_key="f1", org=ORG)
    state = CorrelationState()
    findings = state.lookup_findings(org_id=ORG)
    assert any(f["identity_key"] == "f1" for f in findings)


def test_lookup_findings_by_scanner_type():
    _insert_finding(identity_key="dep-1", tool="dependencies_scanning")
    _insert_finding(identity_key="sast-1", tool="code_scanning")
    state = CorrelationState()
    findings = state.lookup_findings(org_id=ORG, scanner_type="code_scanning")
    assert all(f["tool"] == "code_scanning" for f in findings)
    assert any(f["identity_key"] == "sast-1" for f in findings)


def test_lookup_findings_by_status():
    _insert_finding(identity_key="open-1", state="open")
    _insert_finding(identity_key="fixed-1", state="fixed")
    state = CorrelationState()
    findings = state.lookup_findings(org_id=ORG, status="open")
    assert all(f["state"] == "open" for f in findings)
    assert any(f["identity_key"] == "open-1" for f in findings)


def test_lookup_findings_by_status_list():
    _insert_finding(identity_key="open-2", state="open")
    _insert_finding(identity_key="def-2", state="deferred")
    _insert_finding(identity_key="fixed-2", state="fixed")
    state = CorrelationState()
    findings = state.lookup_findings(org_id=ORG, status=["open", "deferred"])
    states = {f["state"] for f in findings}
    assert "fixed" not in states
    assert "open" in states
    assert "deferred" in states


def test_lookup_findings_by_file_path():
    _insert_finding(identity_key="file-f1", detail={"file_path": "src/app.py"})
    _insert_finding(identity_key="file-f2", detail={"file_path": "src/other.py"})
    state = CorrelationState()
    findings = state.lookup_findings(org_id=ORG, file_path="src/app.py")
    assert len(findings) >= 1
    assert any(f["identity_key"] == "file-f1" for f in findings)


def test_lookup_open_findings_excludes_fixed():
    _insert_finding(identity_key="o3", state="open")
    _insert_finding(identity_key="f3", state="fixed")
    state = CorrelationState()
    findings = state.lookup_open_findings(org_id=ORG)
    assert not any(f["state"] == "fixed" for f in findings)


# ── lookup_sboms_containing ───────────────────────────────────────────────────


def _insert_sbom_component(org, repo, name, version, purl="pkg:npm/test@1.0.0"):
    async def _ins(session):
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        stmt = pg_insert(SbomComponent).values(
            org=org, repo=repo, purl=purl, name=name, version=version,
            ecosystem="npm",
        ).on_conflict_do_nothing(constraint="uq_sbom_components_org_repo_purl")
        await session.execute(stmt)
    run_db(_ins)


def test_lookup_sboms_containing_match():
    _insert_sbom_component(ORG, "test-repo", "lodash", "4.17.21",
                           purl="pkg:npm/lodash@4.17.21")
    state = CorrelationState()
    matches = state.lookup_sboms_containing("lodash")
    assert any(m["name"] == "lodash" for m in matches)


def test_lookup_sboms_containing_with_version():
    _insert_sbom_component(ORG, "test-repo", "lodash", "4.17.21",
                           purl="pkg:npm/lodash@4.17.21")
    _insert_sbom_component(ORG, "other-repo", "lodash", "3.0.0",
                           purl="pkg:npm/lodash@3.0.0")
    state = CorrelationState()
    matches = state.lookup_sboms_containing("lodash", version="4.17.21")
    assert all(m["version"] == "4.17.21" for m in matches)


def test_lookup_sboms_containing_miss():
    state = CorrelationState()
    matches = state.lookup_sboms_containing("nonexistent-pkg-xyz")
    assert matches == []


# ── lookup_chains_by_finding ──────────────────────────────────────────────────


def _insert_chain(org_id=ORG, chain_type="reachable_cve", severity="high") -> str:
    from src.correlation.chain_graph_store import ChainGraphStore
    store = ChainGraphStore()
    return store.create_chain(org_id=org_id, chain_type=chain_type, severity=severity)


def _insert_edge(chain_id, src, tgt):
    from src.correlation.chain_graph_store import ChainGraphStore
    ChainGraphStore().add_edge(
        chain_id=chain_id,
        source_finding_id=src,
        target_finding_id=tgt,
        edge_type="taint",
        confidence=0.9,
        provenance_rule="test",
    )


def test_lookup_chains_by_finding_found():
    chain_id = _insert_chain()
    _insert_edge(chain_id, 100, 101)
    state = CorrelationState()
    chains = state.lookup_chains_by_finding(100)
    assert any(c["id"] == chain_id for c in chains)


def test_lookup_chains_by_finding_not_found():
    state = CorrelationState()
    chains = state.lookup_chains_by_finding(99999)
    assert chains == []


# ── get_setting ───────────────────────────────────────────────────────────────


def test_get_setting_returns_env_var(monkeypatch):
    monkeypatch.setenv("AEGIS_CORRELATION_EPSS_THRESHOLD", "0.5")
    state = CorrelationState()
    assert state.get_setting("epss_threshold", 0.7) == "0.5"


def test_get_setting_returns_default_when_missing(monkeypatch):
    monkeypatch.delenv("AEGIS_CORRELATION_MY_KEY", raising=False)
    state = CorrelationState()
    assert state.get_setting("my_key", "fallback") == "fallback"
