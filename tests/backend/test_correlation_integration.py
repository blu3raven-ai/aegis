"""Integration test: engine + rules + chain store end-to-end.

Uses real testcontainers Postgres (shared session fixture) and a real
Redis container for the event bus and idempotency keys.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import redis as redis_lib
from testcontainers.redis import RedisContainer

from src.argus.connector import NullArgusConnector
from src.correlation.chain_graph_store import ChainGraphStore
from src.correlation.emit_interface import EmitInterface
from src.correlation.engine import CorrelationEngine
from src.correlation.rules import (
    register_builtin_rules,
    IntelMatchRule,
    EpssEscalationRule,
    LifecycleRule,
)
from src.correlation.state import CorrelationState
from src.correlation.rule import RuleContext
from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge, Finding, SbomComponent
from sqlalchemy import delete, select


ORG = "acme-org"
REPO = "acme-org/integ-test-repo"


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest.fixture
def redis_client(redis_container):
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    client = redis_lib.Redis(host=host, port=int(port))
    client.flushdb()
    return client


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(ChainEdge))
        await session.execute(delete(Chain))
        await session.execute(delete(Finding).where(Finding.org == ORG))
        await session.execute(delete(SbomComponent).where(SbomComponent.org == ORG))
    run_db(_del)
    yield


def _stream_cfg(container) -> dict:
    host = container.get_container_host_ip()
    port = container.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}", "stream_prefix": "integ.test.", "max_len": 100}


def _redis_cfg(container) -> dict:
    host = container.get_container_host_ip()
    port = container.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}"}


def _insert_sbom(name, version, repo=REPO):
    async def _ins(session):
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        purl = f"pkg:npm/{name}@{version}"
        stmt = pg_insert(SbomComponent).values(
            org=ORG, repo=repo, purl=purl, name=name, version=version, ecosystem="npm",
        ).on_conflict_do_nothing(constraint="uq_sbom_components_org_repo_purl")
        await session.execute(stmt)
    run_db(_ins)


def _insert_finding_db(**kwargs) -> int:
    defaults = {
        "tool": "dependencies", "org": ORG, "repo": REPO,
        "identity_key": "default-key", "state": "open", "severity": "medium", "detail": {},
    }
    defaults.update(kwargs)
    async def _ins(session):
        f = Finding(**defaults)
        session.add(f)
        await session.flush()
        return f.id
    return run_db(_ins)


def _make_ctx(redis_client) -> RuleContext:
    store = ChainGraphStore()
    return RuleContext(
        state=CorrelationState(),
        argus=NullArgusConnector(),
        emit=EmitInterface(redis_client=redis_client, chain_store=store),
    )


# ── Rule 1: Intel match ───────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_intel_match_creates_finding_for_sbom_match(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    _insert_sbom("lodash", "4.17.21")
    ctx = _make_ctx(redis_client)
    rule = IntelMatchRule()
    rule.evaluate({
        "_stream_id": "1-0",
        "event_id": "integ-evt-001",
        "event_type": "intel.cve_published",
        "org_id": ORG,
        "source_component": "argus",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "cve_id": "CVE-2024-INTEG",
            "affected_package": "lodash",
            "affected_version": "4.17.21",
            "severity": "high",
            "epss_score": 0.1,
        },
    }, ctx)

    async def _check(session):
        result = await session.execute(
            select(Finding).where(Finding.org == ORG, Finding.tool == "correlation")
        )
        return result.scalars().all()

    findings = run_db(_check)
    assert len(findings) == 1
    assert findings[0].detail.get("cve_id") == "CVE-2024-INTEG"
    assert findings[0].severity == "high"


# ── Rule 4: Lifecycle ─────────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_lifecycle_rule_closes_finding_on_file_delete(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    fid = _insert_finding_db(
        identity_key="lc-integ-1",
        tool="code_scanning",
        detail={"file_path": "src/vuln.py"},
    )
    ctx = _make_ctx(redis_client)
    rule = LifecycleRule()
    rule.evaluate({
        "_stream_id": "1-0",
        "event_id": "integ-lc-001",
        "event_type": "code.push",
        "org_id": ORG,
        "source_component": "git_sync",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "repo_id": REPO,
            "after_sha": "deadbeef",
            "deleted_files": ["src/vuln.py"],
        },
    }, ctx)

    async def _check(session):
        result = await session.execute(select(Finding).where(Finding.id == fid))
        return result.scalars().first()

    row = run_db(_check)
    assert row.state == "fixed"


# ── Rule 5: EPSS escalation ───────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_epss_escalation_bumps_finding_severity(mock_pub, redis_client):
    mock_pub.return_value.__class__ = type("P", (), {"publish": lambda s, e: None})()

    fid = _insert_finding_db(
        identity_key="epss-integ-1",
        tool="dependencies",
        severity="medium",
        detail={"cve_id": "CVE-2024-EPSS"},
    )
    ctx = _make_ctx(redis_client)
    rule = EpssEscalationRule()
    rule.evaluate({
        "_stream_id": "1-0",
        "event_id": "integ-epss-001",
        "event_type": "intel.epss_changed",
        "org_id": ORG,
        "source_component": "argus",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "cve_id": "CVE-2024-EPSS",
            "new_epss": 0.9,
            "old_epss": 0.2,
        },
    }, ctx)

    async def _check(session):
        result = await session.execute(select(Finding).where(Finding.id == fid))
        return result.scalars().first()

    row = run_db(_check)
    assert row.severity == "critical"


# ── engine: register_builtin_rules ────────────────────────────────────────────


def test_register_builtin_rules_registers_all_nine(redis_container):
    # Phase 11 adds 4 temporal rules; total is now 13.
    engine = CorrelationEngine(
        stream_config=_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )
    register_builtin_rules(engine)
    assert len(engine._rules) == 13
    expected = {
        "intel_match", "reachable_cve", "secret_to_resource", "lifecycle",
        "epss_escalation", "public_exposure_data_handling", "cross_repo_cve_cluster",
        "container_base_image_propagation", "credential_reuse_chain",
        "attribution_rollup", "severity_velocity", "mttr_tracking", "anomaly_detection",
    }
    assert set(engine._rules.keys()) == expected


def test_engine_dispatch_routes_to_registered_rules(redis_container):
    from src.correlation.rules.intel_match import IntelMatchRule as _IML

    call_log: list = []

    class SpyIntelMatchRule(_IML):
        name = "intel_match"

        def evaluate(self, event, ctx):
            call_log.append(event["event_id"])

    engine = CorrelationEngine(
        stream_config=_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )
    engine.register_rule(SpyIntelMatchRule())

    engine.dispatch_event({
        "_stream_id": "1-0",
        "event_id": "dispatch-integ-001",
        "event_type": "intel.cve_published",
        "org_id": ORG,
        "source_component": "test",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {},
    })

    assert "dispatch-integ-001" in call_log


# ── chain graph store round-trip ──────────────────────────────────────────────


def test_chain_and_edges_round_trip():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=1,
        target_finding_id=2,
        edge_type="taint_reaches_vulnerable_dep",
        confidence=0.9,
        provenance_rule="reachable_cve",
    )

    chains = store.find_chains_by_finding(1)
    assert len(chains) == 1
    assert chains[0]["id"] == chain_id

    edges = store.get_edges(chain_id)
    assert len(edges) == 1
    assert edges[0]["confidence"] == pytest.approx(0.9)
