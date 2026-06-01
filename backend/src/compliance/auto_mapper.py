"""Auto-mapping trigger for compliance control mappings.

Called at finding/chain ingest time to derive and persist compliance mappings
without any manual configuration. Rule evaluation is cheap (pure Python),
so it runs synchronously before the DB session is committed.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.mapper import map_finding, map_chain
from src.compliance.models import ComplianceControlMapping
from src.db.models import Finding

logger = logging.getLogger(__name__)


async def apply_finding_mappings(
    session: AsyncSession,
    finding: Finding,
) -> int:
    """Derive and insert compliance mappings for a finding.

    Returns the number of mapping rows inserted. Idempotent — skips rows
    where (finding_id, framework, control_id) already exists.
    """
    from sqlalchemy import select

    drafts = map_finding(
        scanner_type=finding.tool,
        severity=finding.severity,
        metadata=finding.detail or {},
    )
    if not drafts:
        return 0

    existing_result = await session.execute(
        select(
            ComplianceControlMapping.framework,
            ComplianceControlMapping.control_id,
        ).where(ComplianceControlMapping.finding_id == finding.id)
    )
    existing_keys = {(r.framework, r.control_id) for r in existing_result.all()}

    inserted = 0
    for draft in drafts:
        key = (draft.framework, draft.control_id)
        if key in existing_keys:
            continue
        session.add(ComplianceControlMapping(
            finding_id=finding.id,
            chain_id=None,
            framework=draft.framework,
            control_id=draft.control_id,
            confidence=draft.confidence,
            rationale=draft.rationale,
        ))
        inserted += 1

    if inserted:
        logger.debug(
            "compliance.auto_mapper: inserted %d mappings for finding %d",
            inserted, finding.id,
        )
    return inserted


async def apply_chain_mappings(
    session: AsyncSession,
    chain_id: str,
    chain_type: str,
    severity: str,
) -> int:
    """Derive and insert compliance mappings for an attack chain.

    Returns the number of mapping rows inserted.
    """
    from sqlalchemy import select

    drafts = map_chain(chain_type=chain_type, severity=severity)
    if not drafts:
        return 0

    existing_result = await session.execute(
        select(
            ComplianceControlMapping.framework,
            ComplianceControlMapping.control_id,
        ).where(ComplianceControlMapping.chain_id == chain_id)
    )
    existing_keys = {(r.framework, r.control_id) for r in existing_result.all()}

    inserted = 0
    for draft in drafts:
        key = (draft.framework, draft.control_id)
        if key in existing_keys:
            continue
        session.add(ComplianceControlMapping(
            finding_id=None,
            chain_id=chain_id,
            framework=draft.framework,
            control_id=draft.control_id,
            confidence=draft.confidence,
            rationale=draft.rationale,
        ))
        inserted += 1

    if inserted:
        logger.debug(
            "compliance.auto_mapper: inserted %d mappings for chain %s",
            inserted, chain_id,
        )
    return inserted
