"""DB-backed coverage of the decisions BLOCK path (TODO #61).

The pure-unit test_decisions_service.py covers policy parsing + the blocker
projector shape but not the block path itself (it needs real findings whose
asset resolves to a repo). Seed an asset + open finding and drive
DecisionService.evaluate end to end: block when an open finding is at/above a
blocking severity, allow otherwise, and resolve (org, repo) -> asset_ids.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Asset, Finding
from src.decisions.service import DecisionService, parse_policy

_ORG = "acme"
_REPO = "api"
_BLOCK_HIGH = parse_policy({"block_on": ["high", "critical"]})


@pytest_asyncio.fixture
async def repo_asset(db_session):
    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:{_ORG}/{_REPO}", display_name=f"{_ORG}/{_REPO}",
        asset_metadata={},
    ))
    await db_session.commit()
    yield asset_id
    await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


async def _add_finding(db_session, asset_id, *, severity, state="open", key=None):
    db_session.add(Finding(
        tool="dependencies_scanning",
        identity_key=key or f"k-{uuid.uuid4()}",
        state=state,
        severity=severity,
        asset_id=asset_id,
        title=f"{severity} finding",
    ))
    await db_session.commit()


@pytest.mark.asyncio
async def test_blocks_on_open_high_severity_via_org_repo(db_session, repo_asset):
    await _add_finding(db_session, repo_asset, severity="high")
    out = await DecisionService().evaluate(
        org_id=_ORG, repo=_REPO, policy=_BLOCK_HIGH, session=db_session,
    )
    assert out["decision"] == "block"
    assert out["source"] == "backend"
    assert len(out["blockers"]) == 1
    b = out["blockers"][0]
    assert b["severity"] == "high"
    assert b["repo"] == f"{_ORG}/{_REPO}"  # Asset.display_name, joined in


@pytest.mark.asyncio
async def test_allows_when_severity_below_block_threshold(db_session, repo_asset):
    await _add_finding(db_session, repo_asset, severity="low")
    out = await DecisionService().evaluate(
        org_id=_ORG, repo=_REPO, policy=_BLOCK_HIGH, session=db_session,
    )
    assert out["decision"] == "allow"
    assert out["blockers"] == []


@pytest.mark.asyncio
async def test_non_open_findings_do_not_block(db_session, repo_asset):
    await _add_finding(db_session, repo_asset, severity="critical", state="fixed")
    out = await DecisionService().evaluate(
        org_id=_ORG, repo=_REPO, policy=_BLOCK_HIGH, session=db_session,
    )
    assert out["decision"] == "allow"


@pytest.mark.asyncio
async def test_explicit_asset_ids_path(db_session, repo_asset):
    await _add_finding(db_session, repo_asset, severity="critical")
    out = await DecisionService().evaluate(
        org_id=None, repo=None, policy=_BLOCK_HIGH, session=db_session, asset_ids=[repo_asset],
    )
    assert out["decision"] == "block"


@pytest.mark.asyncio
async def test_empty_asset_scope_allows(db_session, repo_asset):
    await _add_finding(db_session, repo_asset, severity="high")
    # An explicitly-empty asset scope must short-circuit to allow (no blockers).
    out = await DecisionService().evaluate(
        org_id=_ORG, repo=_REPO, policy=_BLOCK_HIGH, session=db_session, asset_ids=[],
    )
    assert out["decision"] == "allow"


@pytest.mark.asyncio
async def test_requires_org_when_no_asset_ids(db_session):
    with pytest.raises(ValueError):
        await DecisionService().evaluate(
            org_id=None, repo=None, policy=_BLOCK_HIGH, session=db_session,
        )
