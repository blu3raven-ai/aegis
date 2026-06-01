"""Tests for ChainGraphStore — CRUD + queries against testcontainers Postgres."""
from __future__ import annotations

import pytest

from src.correlation.chain_graph_store import ChainGraphStore
from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge
from sqlalchemy import select, delete


ORG = "acme-org"


@pytest.fixture(autouse=True)
def _clean():
    """Remove all chain rows before each test."""
    async def _del(session):
        await session.execute(delete(ChainEdge))
        await session.execute(delete(Chain))
    run_db(_del)
    yield


# ── create_chain ──────────────────────────────────────────────────────────────


def test_create_chain_returns_ulid():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    assert isinstance(chain_id, str)
    assert len(chain_id) == 26


def test_create_chain_persists_to_db():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="data_exfil", severity="critical")
    row = store.get_chain(chain_id)
    assert row is not None
    assert row["org_id"] == ORG
    assert row["chain_type"] == "data_exfil"
    assert row["severity"] == "critical"
    assert row["status"] == "open"


def test_create_chain_default_status_is_open():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="medium")
    row = store.get_chain(chain_id)
    assert row["status"] == "open"


def test_create_chain_custom_status():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="low", status="acknowledged")
    row = store.get_chain(chain_id)
    assert row["status"] == "acknowledged"


# ── get_chain ────────────────────────────────────────────────────────────────


def test_get_chain_missing_returns_none():
    store = ChainGraphStore()
    assert store.get_chain("NONEXISTENT0123456789012") is None


# ── add_edge ─────────────────────────────────────────────────────────────────


def test_add_edge_persists():
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
    edges = store.get_edges(chain_id)
    assert len(edges) == 1
    e = edges[0]
    assert e["source_finding_id"] == 1
    assert e["target_finding_id"] == 2
    assert e["edge_type"] == "taint_reaches_vulnerable_dep"
    assert e["confidence"] == pytest.approx(0.9)
    assert e["provenance_rule"] == "reachable_cve"


def test_add_edge_duplicate_is_idempotent():
    """Second add_edge with same (chain, src, tgt, type) must not raise."""
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    for _ in range(3):
        store.add_edge(
            chain_id=chain_id,
            source_finding_id=10,
            target_finding_id=20,
            edge_type="taint_reaches_vulnerable_dep",
            confidence=0.9,
            provenance_rule="reachable_cve",
        )
    edges = store.get_edges(chain_id)
    assert len(edges) == 1  # only one despite 3 calls


# ── find_chains_by_finding ───────────────────────────────────────────────────


def test_find_chains_by_finding_source():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=5,
        target_finding_id=6,
        edge_type="taint_reaches_vulnerable_dep",
        confidence=0.8,
        provenance_rule="reachable_cve",
    )
    chains = store.find_chains_by_finding(5)
    assert len(chains) == 1
    assert chains[0]["id"] == chain_id


def test_find_chains_by_finding_target():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=5,
        target_finding_id=6,
        edge_type="taint_reaches_vulnerable_dep",
        confidence=0.8,
        provenance_rule="reachable_cve",
    )
    chains = store.find_chains_by_finding(6)
    assert len(chains) == 1


def test_find_chains_by_finding_unrelated_returns_empty():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=5,
        target_finding_id=6,
        edge_type="taint_reaches_vulnerable_dep",
        confidence=0.8,
        provenance_rule="reachable_cve",
    )
    assert store.find_chains_by_finding(99) == []


# ── update_chain_severity ────────────────────────────────────────────────────


def test_update_chain_severity():
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="data_exfil", severity="high")
    store.update_chain_severity(chain_id, "critical")
    row = store.get_chain(chain_id)
    assert row["severity"] == "critical"


# ── list_chains ──────────────────────────────────────────────────────────────


def test_list_chains_returns_all_for_org():
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.create_chain(org_id=ORG, chain_type="data_exfil", severity="critical")
    chains = store.list_chains(ORG)
    assert len(chains) == 2


def test_list_chains_filter_by_severity():
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.create_chain(org_id=ORG, chain_type="data_exfil", severity="critical")
    chains = store.list_chains(ORG, severity="critical")
    assert len(chains) == 1
    assert chains[0]["chain_type"] == "data_exfil"


def test_list_chains_filter_by_type():
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.create_chain(org_id=ORG, chain_type="data_exfil", severity="critical")
    chains = store.list_chains(ORG, chain_type="reachable_cve")
    assert len(chains) == 1
    assert chains[0]["severity"] == "high"


def test_list_chains_excludes_other_orgs():
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")
    store.create_chain(org_id="other-org", chain_type="reachable_cve", severity="medium")
    chains = store.list_chains(ORG)
    assert all(c["org_id"] == ORG for c in chains)
    assert len(chains) == 1


def test_list_chains_respects_limit():
    store = ChainGraphStore()
    for _ in range(5):
        store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="low")
    chains = store.list_chains(ORG, limit=3)
    assert len(chains) <= 3
