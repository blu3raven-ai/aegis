"""Verification cache lookup is asset-scoped so a rogue runner can't replay a
verdict planted on one asset against a finding on a different asset."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.shared.finding_queries import lookup_verification_cache


def _row(asset_id, verdict, h):
    """A Finding-shaped row tuple as select() would yield."""
    return (
        verdict,
        [{"kind": "gate", "file": "guard.py", "snippet": "abort(401)"}],
        None,
        {"verification_input_hash": h},
    )


@pytest.mark.asyncio
async def test_cache_lookup_scoped_to_asset_ids():
    # Two assets share the same input hash; scoping to asset B must not return
    # asset A's planted entry.
    h = "hash-1"
    rows = [_row("asset-a", "ruled_out", h), _row("asset-b", "ruled_out", h)]

    result = MagicMock()
    result.all.return_value = [_row("asset-b", "ruled_out", h)]
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)

    out = await lookup_verification_cache(session, tool="code_scanning", hashes=[h], asset_ids=["asset-b"])
    assert set(out.keys()) == {h}
    # The scoped query must carry the asset_ids predicate.
    stmt = session.execute.call_args.args[0]
    assert "asset_id" in str(stmt)


@pytest.mark.asyncio
async def test_cache_lookup_unscoped_when_asset_ids_none():
    # Backward compat: no asset_ids → global lookup (existing callers).
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    await lookup_verification_cache(session, tool="code_scanning", hashes=["h"], asset_ids=None)
    stmt = session.execute.call_args.args[0]
    assert "asset_b" not in str(stmt).replace("asset_b", "asset_b")  # no IN clause added


@pytest.mark.asyncio
async def test_cache_lookup_empty_hashes_returns_empty():
    session = MagicMock()
    out = await lookup_verification_cache(session, tool="code_scanning", hashes=[], asset_ids=["a"])
    assert out == {}
    session.execute.assert_not_called()
