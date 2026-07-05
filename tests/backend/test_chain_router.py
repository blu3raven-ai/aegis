"""Tests for chain graph REST endpoints.

Creates a minimal FastAPI app with only the chains router (no lifespan, no
auth middleware) — mirrors the approach used in test_argus_webhook.py.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete

from src.correlation.chain_graph_store import ChainGraphStore
from src.correlation.router import router as chains_router
from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge

ORG = "acme-org"


@pytest.fixture(autouse=True)
def _clean():
    """Remove all chain rows before each test."""
    async def _del(session):
        await session.execute(delete(ChainEdge))
        await session.execute(delete(Chain))
    run_db(_del)
    yield


@pytest.fixture
def client():
    """Minimal app — only the chains router, no lifespan overhead."""
    mini = FastAPI()
    mini.include_router(chains_router)
    return TestClient(mini, raise_server_exceptions=True)


# ── list_chains ───────────────────────────────────────────────────────────────


def test_list_chains_empty(client: TestClient):
    resp = client.get(f"/api/v1/chains?org_id={ORG}")
    assert resp.status_code == 200
    assert resp.json() == {"chains": []}


def test_list_chains_returns_created_chain(client: TestClient):
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="reachable_cve", severity="high")

    resp = client.get(f"/api/v1/chains?org_id={ORG}")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["chains"]) == 1
    assert data["chains"][0]["id"] == chain_id
    assert data["chains"][0]["chain_type"] == "reachable_cve"


def test_list_chains_severity_filter(client: TestClient):
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="rce", severity="critical")
    store.create_chain(org_id=ORG, chain_type="data-exfil", severity="high")

    resp = client.get(f"/api/v1/chains?org_id={ORG}&severity=critical")
    data = resp.json()
    assert len(data["chains"]) == 1
    assert data["chains"][0]["severity"] == "critical"


def test_list_chains_chain_type_filter(client: TestClient):
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="rce", severity="critical")
    store.create_chain(org_id=ORG, chain_type="data-exfil", severity="high")

    resp = client.get(f"/api/v1/chains?org_id={ORG}&chain_type=rce")
    data = resp.json()
    assert len(data["chains"]) == 1
    assert data["chains"][0]["chain_type"] == "rce"


def test_list_chains_respects_limit(client: TestClient):
    store = ChainGraphStore()
    for i in range(5):
        store.create_chain(org_id=ORG, chain_type=f"type-{i}", severity="low")

    resp = client.get(f"/api/v1/chains?org_id={ORG}&limit=2")
    assert len(resp.json()["chains"]) == 2


def test_list_chains_isolates_by_org(client: TestClient):
    store = ChainGraphStore()
    store.create_chain(org_id=ORG, chain_type="rce", severity="critical")
    store.create_chain(org_id="other-org", chain_type="rce", severity="high")

    resp = client.get(f"/api/v1/chains?org_id={ORG}")
    data = resp.json()
    assert all(c["org_id"] == ORG for c in data["chains"])


# ── get_chain ─────────────────────────────────────────────────────────────────


def test_get_chain_not_found(client: TestClient):
    resp = client.get("/api/v1/chains/does-not-exist")
    assert resp.status_code == 404


def test_get_chain_returns_chain_and_edges(client: TestClient):
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="rce", severity="critical")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=10,
        target_finding_id=20,
        edge_type="taint_flow",
        confidence=0.95,
        provenance_rule="sast_to_dep",
    )

    resp = client.get(f"/api/v1/chains/{chain_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == chain_id
    assert data["chain_type"] == "rce"
    assert len(data["edges"]) == 1
    edge = data["edges"][0]
    assert edge["source_finding_id"] == 10
    assert edge["target_finding_id"] == 20
    assert edge["edge_type"] == "taint_flow"
    assert edge["confidence"] == pytest.approx(0.95)


def test_get_chain_no_edges(client: TestClient):
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="secret-leak", severity="medium")

    resp = client.get(f"/api/v1/chains/{chain_id}")
    assert resp.status_code == 200
    assert resp.json()["edges"] == []


# ── findings chains endpoint ──────────────────────────────────────────────────


def test_get_chains_for_finding_returns_correct_chains(client: TestClient):
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="rce", severity="critical")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=42,
        target_finding_id=99,
        edge_type="taint_flow",
        confidence=0.9,
        provenance_rule="rule_1",
    )

    resp = client.get("/api/v1/findings/42/chains")
    assert resp.status_code == 200
    chains = resp.json()["chains"]
    assert len(chains) == 1
    assert chains[0]["id"] == chain_id


def test_get_chains_for_finding_via_target(client: TestClient):
    store = ChainGraphStore()
    chain_id = store.create_chain(org_id=ORG, chain_type="data-exfil", severity="high")
    store.add_edge(
        chain_id=chain_id,
        source_finding_id=1,
        target_finding_id=77,
        edge_type="data_flow",
        confidence=0.8,
        provenance_rule="rule_2",
    )

    resp = client.get("/api/v1/findings/77/chains")
    assert resp.status_code == 200
    assert len(resp.json()["chains"]) == 1


def test_get_chains_for_finding_empty(client: TestClient):
    resp = client.get("/api/v1/findings/9999/chains")
    assert resp.status_code == 200
    assert resp.json()["chains"] == []
