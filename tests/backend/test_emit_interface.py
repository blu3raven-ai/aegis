"""Tests for EmitInterface — idempotent writes to DB + event bus."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import redis as redis_lib
from testcontainers.redis import RedisContainer

from src.correlation.chain_graph_store import ChainGraphStore
from src.correlation.emit_interface import EmitInterface
from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge, Finding
from sqlalchemy import delete, select


ORG = "acme-org"
REPO = "acme-org/emit-test-repo"


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest.fixture
def redis_client(redis_container):
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    client = redis_lib.Redis(host=host, port=int(port))
    client.flushdb()  # clean state per test
    return client


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(ChainEdge))
        await session.execute(delete(Chain))
        await session.execute(delete(Finding).where(Finding.org == ORG))
    run_db(_del)
    yield


def _make_emit(redis_client) -> EmitInterface:
    return EmitInterface(redis_client=redis_client, chain_store=ChainGraphStore())


def _get_finding(identity_key: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(
                Finding.org == ORG, Finding.identity_key == identity_key
            )
        )
        return result.scalars().first()
    return run_db(_q)


def _insert_finding(**kwargs) -> int:
    defaults = {
        "tool": "dependencies", "org": ORG, "repo": REPO,
        "identity_key": "sev-key", "state": "open",
        "severity": "medium", "detail": {},
    }
    defaults.update(kwargs)
    async def _ins(session):
        f = Finding(**defaults)
        session.add(f)
        await session.flush()
        return f.id
    return run_db(_ins)


# ── emit_finding ──────────────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_finding_creates_db_row(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    emit = _make_emit(redis_client)
    finding_id = emit.emit_finding(
        {
            "tool": "correlation",
            "org": ORG,
            "repo": REPO,
            "identity_key": "cve-2024-1234::acme-org/emit-test-repo",
            "severity": "critical",
            "detail": {"cve_id": "CVE-2024-1234"},
        },
        source_event_id="evt-001",
        rule_name="intel_match",
    )
    assert finding_id is not None
    row = _get_finding("cve-2024-1234::acme-org/emit-test-repo")
    assert row is not None
    assert row.severity == "critical"


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_finding_idempotent_on_duplicate_event(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    emit = _make_emit(redis_client)
    finding_data = {
        "tool": "correlation",
        "org": ORG,
        "repo": REPO,
        "identity_key": "idem-key-001",
        "severity": "high",
        "detail": {},
    }
    id1 = emit.emit_finding(finding_data, source_event_id="evt-002", rule_name="intel_match")
    id2 = emit.emit_finding(finding_data, source_event_id="evt-002", rule_name="intel_match")
    assert id1 is not None
    assert id2 is None  # second call suppressed by idempotency guard


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_finding_publishes_event(mock_pub, redis_client):
    pub = MagicMock()
    mock_pub.return_value = pub
    emit = _make_emit(redis_client)
    emit.emit_finding(
        {
            "tool": "correlation",
            "org": ORG,
            "repo": REPO,
            "identity_key": "pub-key-001",
            "severity": "medium",
            "detail": {},
        },
        source_event_id="evt-003",
        rule_name="intel_match",
    )
    pub.publish.assert_called_once()
    evt = pub.publish.call_args.args[0]
    assert evt.event_type == "finding.created"


# ── emit_chain ────────────────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_chain_creates_db_row(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    emit = _make_emit(redis_client)
    chain_id = emit.emit_chain(
        {"org_id": ORG, "chain_type": "reachable_cve", "severity": "high"},
        source_event_id="evt-010",
        rule_name="reachable_cve",
    )
    assert chain_id is not None
    store = ChainGraphStore()
    row = store.get_chain(chain_id)
    assert row is not None
    assert row["chain_type"] == "reachable_cve"


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_chain_idempotent_on_same_event(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    emit = _make_emit(redis_client)
    chain_data = {"org_id": ORG, "chain_type": "reachable_cve", "severity": "high"}
    id1 = emit.emit_chain(chain_data, source_event_id="evt-011", rule_name="reachable_cve")
    id2 = emit.emit_chain(chain_data, source_event_id="evt-011", rule_name="reachable_cve")
    assert id1 is not None
    assert id2 is None  # suppressed


# ── emit_chain_edge ───────────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_chain_edge_persists(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    emit = _make_emit(redis_client)
    chain_id = emit.emit_chain(
        {"org_id": ORG, "chain_type": "reachable_cve", "severity": "high"},
        source_event_id="evt-020",
        rule_name="reachable_cve",
    )
    emit.emit_chain_edge(
        chain_id, 1, 2, "taint_reaches_vulnerable_dep",
        confidence=0.85,
        rule_name="reachable_cve",
    )
    store = ChainGraphStore()
    edges = store.get_edges(chain_id)
    assert len(edges) == 1
    assert edges[0]["source_finding_id"] == 1
    assert edges[0]["target_finding_id"] == 2


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_chain_edge_idempotent(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    emit = _make_emit(redis_client)
    chain_id = emit.emit_chain(
        {"org_id": ORG, "chain_type": "reachable_cve", "severity": "high"},
        source_event_id="evt-021",
        rule_name="reachable_cve",
    )
    for _ in range(3):
        emit.emit_chain_edge(
            chain_id, 10, 20, "taint",
            confidence=0.9,
            rule_name="reachable_cve",
        )
    edges = ChainGraphStore().get_edges(chain_id)
    assert len(edges) == 1


# ── emit_severity_change ──────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_severity_change_updates_db(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    fid = _insert_finding(identity_key="sev-chg-1")
    emit = _make_emit(redis_client)
    emit.emit_severity_change(fid, "critical", reason="epss crossed 0.7", rule_name="epss_escalation")

    async def _check(session):
        result = await session.execute(select(Finding).where(Finding.id == fid))
        return result.scalars().first()
    row = run_db(_check)
    assert row.severity == "critical"


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_severity_change_idempotent(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    fid = _insert_finding(identity_key="sev-chg-2")
    emit = _make_emit(redis_client)
    emit.emit_severity_change(fid, "critical", reason="epss", rule_name="epss_escalation")
    emit.emit_severity_change(fid, "critical", reason="epss", rule_name="epss_escalation")
    # Event should only be published once
    assert mock_pub.return_value.publish.call_count == 1


# ── emit_close ────────────────────────────────────────────────────────────────


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_close_sets_state_fixed(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    fid = _insert_finding(identity_key="close-1", state="open")
    emit = _make_emit(redis_client)
    emit.emit_close(fid, reason="source file deleted", rule_name="lifecycle")

    async def _check(session):
        result = await session.execute(select(Finding).where(Finding.id == fid))
        return result.scalars().first()
    row = run_db(_check)
    assert row.state == "fixed"


@patch("src.correlation.emit_interface.get_event_publisher")
def test_emit_close_idempotent(mock_pub, redis_client):
    mock_pub.return_value = MagicMock()
    fid = _insert_finding(identity_key="close-2", state="open")
    emit = _make_emit(redis_client)
    emit.emit_close(fid, reason="deleted", rule_name="lifecycle")
    emit.emit_close(fid, reason="deleted", rule_name="lifecycle")
    assert mock_pub.return_value.publish.call_count == 1
