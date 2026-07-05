"""CorrelationState — read-only access layer for correlation rules.

Rules receive a CorrelationState instance via RuleContext and use it to look
up findings, cached SBOMs, chain memberships, and org-level settings without
constructing DB sessions themselves. All queries are read-only; writes go
through EmitInterface.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge, Finding, SbomComponent

logger = logging.getLogger(__name__)

# States considered "open" for correlation purposes (findings that can be acted on)
_OPEN_STATES = frozenset({"open", "deferred"})

# Severity ordering used for comparison across rules
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}


def _severity_rank(s: str | None) -> int:
    return _SEVERITY_ORDER.get((s or "unknown").lower(), -1)


def max_severity(*severities: str | None) -> str:
    """Return the highest severity from a collection of severity strings."""
    ranked = sorted(
        (s for s in severities if s),
        key=lambda s: _severity_rank(s),
        reverse=True,
    )
    return ranked[0] if ranked else "unknown"


class CorrelationState:
    """Read-only state provider injected into every rule evaluation.

    All methods are synchronous — they call run_db() internally so that rules
    can be written as plain Python without async/await.
    """

    # ── Findings ──────────────────────────────────────────────────────────────

    def lookup_findings(
        self,
        *,
        org_id: str | None = None,
        repo_id: str | None = None,
        cve_id: str | None = None,
        scanner_type: str | None = None,
        file_path: str | None = None,
        status: str | list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Query findings with optional filters.

        All filter args are ANDed. status can be a single value or list.
        Returns plain dicts so callers don't need to manage ORM sessions.
        """

        async def _fetch(session):
            stmt = select(Finding)

            if org_id is not None:
                stmt = stmt.where(Finding.org == org_id)
            if repo_id is not None:
                stmt = stmt.where(Finding.repo == repo_id)
            if scanner_type is not None:
                stmt = stmt.where(Finding.tool == scanner_type)

            if status is not None:
                if isinstance(status, list):
                    stmt = stmt.where(Finding.state.in_(status))
                else:
                    stmt = stmt.where(Finding.state == status)

            # CVE and file_path live inside the JSONB detail column
            if cve_id is not None:
                stmt = stmt.where(
                    Finding.detail["cve_id"].as_string() == cve_id
                )
            if file_path is not None:
                stmt = stmt.where(
                    Finding.detail["file_path"].as_string() == file_path
                )

            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_finding_to_dict(r) for r in rows]

        return run_db(_fetch)

    def lookup_open_findings(
        self,
        *,
        org_id: str | None = None,
        repo_id: str | None = None,
        cve_id: str | None = None,
        scanner_type: str | None = None,
        file_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Convenience wrapper: findings in open states only."""
        return self.lookup_findings(
            org_id=org_id,
            repo_id=repo_id,
            cve_id=cve_id,
            scanner_type=scanner_type,
            file_path=file_path,
            status=list(_OPEN_STATES),
        )

    # ── SBOM component lookups (via sbom_components table) ───────────────────

    def lookup_sboms_containing(
        self,
        package_name: str,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return repos whose SBOM contains package_name (+ optional exact version).

        Uses the sbom_components table populated by the dep scanner. Returns
        lightweight dicts: {org, repo, name, version, purl, ecosystem}.
        """

        async def _fetch(session):
            stmt = select(SbomComponent).where(SbomComponent.name == package_name)
            if version is not None:
                stmt = stmt.where(SbomComponent.version == version)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "org": r.org,
                    "repo": r.repo,
                    "name": r.name,
                    "version": r.version,
                    "purl": r.purl,
                    "ecosystem": r.ecosystem,
                }
                for r in rows
            ]

        return run_db(_fetch)

    # ── Chain lookups ─────────────────────────────────────────────────────────

    def lookup_chains_by_finding(self, finding_id: int) -> list[dict[str, Any]]:
        """Return all chains that include the given finding as a source or target."""

        async def _fetch(session):
            result = await session.execute(
                select(Chain)
                .join(ChainEdge, ChainEdge.chain_id == Chain.id)
                .where(
                    (ChainEdge.source_finding_id == finding_id)
                    | (ChainEdge.target_finding_id == finding_id)
                )
                .distinct()
            )
            rows = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "org_id": r.org_id,
                    "chain_type": r.chain_type,
                    "severity": r.severity,
                    "status": r.status,
                }
                for r in rows
            ]

        return run_db(_fetch)

    # ── Settings ──────────────────────────────────────────────────────────────

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Return a correlation-engine setting.

        Currently sourced from environment variables (AEGIS_CORRELATION_{KEY}).
        Later phases can promote this to a DB-backed AppConfig lookup.
        """
        import os

        env_key = f"AEGIS_CORRELATION_{key.upper()}"
        return os.environ.get(env_key, default)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _finding_to_dict(row: Finding) -> dict[str, Any]:
    return {
        "id": row.id,
        "tool": row.tool,
        "org": row.org,
        "repo": row.repo,
        "identity_key": row.identity_key,
        "state": row.state,
        "severity": row.severity,
        "detail": row.detail or {},
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
    }
