"""Tests for patch_finding_detail lean-key guard.

After the blob offload, patch_finding_detail only accepts lean keys for the
given tool. Passing fat keys must raise ValueError immediately (before any DB
access) so callers can be updated to use upsert_finding instead.
"""
from __future__ import annotations

import pytest
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.finding_detail_blob import LEAN_KEYS
from src.storage import patch_finding_detail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOOL = "code_scanning"
_ORG = "patch-detail-test-org"


def _clean(org: str) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == _TOOL, Finding.org == org)
        )
    run_db(_del)


def _seed(org: str, key: str, detail: dict) -> Finding:
    async def _q(session):
        f = Finding(
            tool=_TOOL,
            org=org,
            repo="acme-org/api",
            identity_key=key,
            state="open",
            severity="high",
            detail=detail,
        )
        session.add(f)
        await session.flush()
        return f
    return run_db(_q)


def _fetch(org: str, key: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(
                Finding.tool == _TOOL,
                Finding.org == org,
                Finding.identity_key == key,
            )
        )
        return result.scalars().first()
    return run_db(_q)


# ---------------------------------------------------------------------------
# Guard tests
# ---------------------------------------------------------------------------

def test_patch_fat_key_raises_value_error():
    """Patching a fat key for code_scanning must raise ValueError immediately."""
    # 'snippet' is not in LEAN_KEYS['code_scanning']
    assert "snippet" not in LEAN_KEYS["code_scanning"]

    with pytest.raises(ValueError, match="fat keys"):
        patch_finding_detail(_TOOL, _ORG, "any-key", {"snippet": "some code"})


def test_patch_mixed_lean_and_fat_raises_value_error():
    """Even if some patch keys are lean, any fat key must trigger the guard."""
    with pytest.raises(ValueError, match="fat keys"):
        patch_finding_detail(
            _TOOL,
            _ORG,
            "any-key",
            {"ruleId": "r1", "dataflowTrace": {"nodes": []}},
        )


def test_patch_lean_key_updates_jsonb():
    """Patching a lean key must update the detail JSONB column."""
    org = f"{_ORG}-lean-patch"
    key = "patch-lean-test"
    _clean(org)

    _seed(org, key, {"ruleId": "old-rule", "confidence": "medium"})

    patch_finding_detail(_TOOL, org, key, {"confidence": "high"})

    finding = _fetch(org, key)
    assert finding is not None
    assert finding.detail.get("confidence") == "high"
    # Other lean keys must be preserved
    assert finding.detail.get("ruleId") == "old-rule"


def test_patch_unknown_tool_allows_empty_patch():
    """Unknown tool has empty LEAN_KEYS set; any non-empty patch is rejected."""
    # A tool not in LEAN_KEYS has lean_for_tool = set(), so any key is 'fat'
    with pytest.raises(ValueError, match="fat keys"):
        patch_finding_detail("unknown_tool", _ORG, "any-key", {"someKey": "val"})


def test_patch_lean_key_unknown_finding_is_noop():
    """Patching a non-existent finding is a silent no-op (no error raised)."""
    # No ValueError because the key is lean; the row simply isn't found
    patch_finding_detail(_TOOL, _ORG, "nonexistent-finding-xyz", {"ruleId": "r1"})
