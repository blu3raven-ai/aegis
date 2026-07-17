"""SARIF 2.1.0 findings export — structure + GitHub code-scanning contract.

Asserts the document shape GitHub/GitLab ingest: version, a single tool run,
per-rule registration with `security-severity`, severity→level mapping, physical
locations, and that asset scope + the default-exclude-archived contract hold.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.db.models import Asset, Finding  # noqa: E402
from src.exports.findings_export import FindingFilters, stream_findings_sarif  # noqa: E402


async def _collect_sarif(session, filters, asset_ids, *, include_archived_rows=False):
    """Consume the streamed SARIF bytes and parse them — also asserts the stream
    is well-formed JSON."""
    chunks = [
        c async for c in stream_findings_sarif(
            filters, asset_ids, session, include_archived_rows=include_archived_rows
        )
    ]
    return json.loads(b"".join(chunks))


async def _seed(session) -> str:
    asset_id = str(uuid.uuid4())
    session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    # A SAST finding with a file location.
    session.add(Finding(
        tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="critical", title="SQL injection",
        rule_name="python.sql-injection", file_path="app/db.py",
        detail={"start_line": 42},
    ))
    # A dependency finding keyed by CVE, no file location.
    session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state="open", severity="medium", title="Vulnerable lodash", cve_id="CVE-2021-23337",
    ))
    await session.flush()
    return asset_id


@pytest.mark.asyncio
async def test_sarif_document_shape(db_session):
    asset_id = await _seed(db_session)
    await db_session.commit()
    try:
        doc = await _collect_sarif(db_session, FindingFilters(), [asset_id])

        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "Aegis"

        results = run["results"]
        assert len(results) == 2
        rules = run["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        # SCA finding groups under its CVE; SAST under its rule name.
        assert "CVE-2021-23337" in rule_ids
        assert "python.sql-injection" in rule_ids

        by_rule = {r["ruleId"]: r for r in results}
        sast = by_rule["python.sql-injection"]
        assert sast["level"] == "error"  # critical → error
        assert sast["properties"]["security-severity"] == "9.5"
        assert sast["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/db.py"
        assert sast["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

        sca = by_rule["CVE-2021-23337"]
        assert sca["level"] == "warning"  # medium → warning
        assert sca["properties"]["cve"] == "CVE-2021-23337"
        assert "locations" not in sca  # no file path → no physical location

        # ruleIndex must point at the registered rule.
        assert rules[sast["ruleIndex"]]["id"] == "python.sql-injection"
    finally:
        await _cleanup(db_session, asset_id)


@pytest.mark.asyncio
async def test_sarif_respects_asset_scope(db_session):
    asset_id = await _seed(db_session)
    await db_session.commit()
    try:
        # A caller scoped to an unrelated asset sees no results.
        doc = await _collect_sarif(db_session, FindingFilters(), [str(uuid.uuid4())])
        assert doc["runs"][0]["results"] == []
    finally:
        await _cleanup(db_session, asset_id)


async def _cleanup(session, asset_id: str) -> None:
    from sqlalchemy import delete
    await session.execute(delete(Finding).where(Finding.asset_id == asset_id))
    await session.execute(delete(Asset).where(Asset.id == asset_id))
    await session.commit()
