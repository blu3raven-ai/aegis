"""Chain graph REST endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from src.correlation.chain_graph_store import ChainGraphStore

router = APIRouter(tags=["chains"])

_chains_prefix = "/api/v1/chains"
_findings_prefix = "/api/v1/findings"


@router.get(_chains_prefix)
async def list_chains(
    org_id: str,
    severity: str | None = None,
    chain_type: str | None = None,
    limit: int = Query(default=100, le=500),
):
    store = ChainGraphStore()
    chains = store.list_chains(org_id, severity=severity, chain_type=chain_type, limit=limit)
    return {"chains": chains}


@router.get(_chains_prefix + "/{chain_id}")
async def get_chain(chain_id: str):
    store = ChainGraphStore()
    chain = store.get_chain(chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="chain not found")
    edges = store.get_edges(chain_id)
    return {**chain, "edges": edges}


@router.get(_findings_prefix + "/{finding_id}/chains")
async def get_chains_for_finding(finding_id: int):
    store = ChainGraphStore()
    chains = store.find_chains_by_finding(finding_id)
    return {"chains": chains}
