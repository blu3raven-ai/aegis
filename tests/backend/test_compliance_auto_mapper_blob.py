"""Regression test: compliance auto-mapper reads fat keys from MinIO blob.

Rules 4 and 5 in src.compliance.mapper depend on fat keys (handles_sensitive_data
and is_public_facing) that live in the MinIO blob for code_scanning findings.
Before the fix, apply_finding_mappings read finding.detail (lean JSONB only)
instead of calling hydrate_detail, so those rules always evaluated to None and
no mappings were produced.

This test:
  - Upserts a code_scanning finding with fat keys in the full detail dict so
    the splitter routes them to MinIO.
  - Asserts that the compliance_control_mappings table contains the expected
    rows produced by Rules 4 (CC6.7) and 5 (CC6.6) after the upsert.

Requires testcontainers Postgres + MinIO (both started by conftest.py).
"""
from __future__ import annotations

import pytest
from sqlalchemy import delete as sa_delete, select

# Importing compliance models ensures the tables are registered with Base
# metadata before _create_tables runs create_all.
from src.compliance.models import ComplianceControlMapping
from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.finding_queries import upsert_finding


_TOOL = "code_scanning"
_ORG = "compliance-blob-regression-org"

# A code_scanning detail that includes both fat keys that drive Rules 4 and 5.
# The lean keys come from LEAN_KEYS["code_scanning"]; everything else is fat
# and will be uploaded to MinIO, then retrieved by hydrate_detail.
_FAT_DETAIL = {
    # lean keys (stay in JSONB)
    "ruleId": "java/xss",
    "ruleName": "Cross-Site Scripting",
    "filePath": "src/Handler.java",
    "startLine": 42,
    "endLine": 44,
    "message": "Reflected XSS via user input",
    "category": "security",
    "cwe": ["CWE-79"],
    "owasp": [],
    "confidence": "high",
    "language": "java",
    "fileClass": "source",
    "ruleIds": ["java/xss"],
    # fat keys (offloaded to MinIO — drive Rules 4 and 5)
    "handles_sensitive_data": True,
    "is_public_facing": True,
    "snippet": "resp.getWriter().write(req.getParam(\"q\"));",
    "dataflowTrace": {"nodes": [{"file": "Handler.java", "line": 42}]},
}


def _clean() -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == _TOOL, Finding.org == _ORG)
        )
    run_db(_del)


def _upsert_and_get_id() -> int:
    async def _q(session):
        f = await upsert_finding(
            session,
            tool=_TOOL,
            org=_ORG,
            repo="acme-org/api",
            identity_key="xss-handler-42-regression",
            state="open",
            severity="high",
            detail=_FAT_DETAIL,
        )
        return f.id
    return run_db(_q)


def _get_mappings(finding_id: int) -> list[ComplianceControlMapping]:
    async def _q(session):
        result = await session.execute(
            select(ComplianceControlMapping).where(
                ComplianceControlMapping.finding_id == finding_id
            )
        )
        return list(result.scalars().all())
    return run_db(_q)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_rule4_fires_when_handles_sensitive_data_is_fat(s3_endpoint):
    """Rule 4 must produce CC6.7 for code_scanning with handles_sensitive_data in blob."""
    _clean()
    finding_id = _upsert_and_get_id()

    mappings = _get_mappings(finding_id)
    control_ids = [(m.framework, m.control_id) for m in mappings]

    assert ("soc2", "CC6.7") in control_ids, (
        f"Rule 4 (soc2/CC6.7) not found in mappings for finding {finding_id}. "
        f"Got: {control_ids}"
    )
    assert ("pci-dss", "6.2.4") in control_ids, (
        f"Rule 4 (pci-dss/6.2.4) not found in mappings for finding {finding_id}. "
        f"Got: {control_ids}"
    )


def test_rule5_fires_when_is_public_facing_is_fat(s3_endpoint):
    """Rule 5 must produce CC6.6 for any finding with is_public_facing in blob."""
    _clean()
    finding_id = _upsert_and_get_id()

    mappings = _get_mappings(finding_id)
    control_ids = [(m.framework, m.control_id) for m in mappings]

    assert ("soc2", "CC6.6") in control_ids, (
        f"Rule 5 (soc2/CC6.6) not found in mappings for finding {finding_id}. "
        f"Got: {control_ids}"
    )
    # high severity + is_public_facing → PCI 11.3.1
    assert ("pci-dss", "11.3.1") in control_ids, (
        f"Rule 5 (pci-dss/11.3.1) not found in mappings for finding {finding_id}. "
        f"Got: {control_ids}"
    )


def test_no_fat_key_mappings_when_lean_only(s3_endpoint):
    """Without fat keys, Rules 4 and 5 must NOT fire (handles_sensitive_data/is_public_facing absent)."""
    lean_org = f"{_ORG}-lean-only"

    async def _upsert_lean(session):
        f = await upsert_finding(
            session,
            tool=_TOOL,
            org=lean_org,
            repo="acme-org/api",
            identity_key="lean-only-no-fat-keys",
            state="open",
            severity="high",
            detail={
                "ruleId": "java/npe",
                "ruleName": "Null Pointer",
                "filePath": "src/Svc.java",
                "startLine": 1,
                "endLine": 2,
                "message": "Potential NPE",
                "category": "reliability",
                "cwe": [],
                "owasp": [],
                "confidence": "medium",
                "language": "java",
                "fileClass": "source",
                "ruleIds": ["java/npe"],
                # no handles_sensitive_data, no is_public_facing
            },
        )
        return f.id

    # clean up
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == _TOOL, Finding.org == lean_org)
        )
    run_db(_del)

    finding_id = run_db(_upsert_lean)
    mappings = _get_mappings(finding_id)
    control_ids = [(m.framework, m.control_id) for m in mappings]

    assert ("soc2", "CC6.7") not in control_ids, "Rule 4 must not fire without handles_sensitive_data"
    assert ("soc2", "CC6.6") not in control_ids, "Rule 5 must not fire without is_public_facing"
