"""Go/No-Go deployment decision service.

Implements the spec §6.1 decision endpoint server-side so the CLI no longer
has to compute the result locally. The heuristic mirrors the CLI's
``_local_decision_heuristic`` so behaviour stays identical between the
backend-authorised path and the legacy local-fallback path.

Heuristic — one place, no constants duplicated downstream:

* Fetch open findings for the org (optionally narrowed to a single repo).
* Block when any finding's severity matches the configured ``block_on`` set.
* Otherwise allow.

The service is pure data access + a deterministic predicate. The router
layer translates HTTP concerns (request shape, error status codes).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, Finding

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
DEFAULT_BLOCK_ON: tuple[str, ...] = ("critical",)

# Cap so a malformed policy can't pull every finding for every org into memory.
MAX_BLOCKERS_RETURNED = 200


@dataclass(frozen=True)
class DecisionPolicy:
    """Policy that drives the heuristic. Override-able per request."""

    block_on: tuple[str, ...] = DEFAULT_BLOCK_ON


def parse_policy(raw: dict[str, Any] | None) -> DecisionPolicy:
    """Coerce a request-supplied policy dict into a validated DecisionPolicy.

    Raises ValueError when the policy shape is wrong. The router translates
    these into HTTP 400 so clients see a clear signal — fail-loudly over
    silent default substitution.
    """
    if raw is None:
        return DecisionPolicy()
    if not isinstance(raw, dict):
        raise ValueError("policy must be an object")

    block_on_raw = raw.get("block_on", DEFAULT_BLOCK_ON)
    if isinstance(block_on_raw, str):
        block_on_raw = [block_on_raw]
    if not isinstance(block_on_raw, (list, tuple)):
        raise ValueError("policy.block_on must be a list of severities")

    block_on: list[str] = []
    for item in block_on_raw:
        if not isinstance(item, str):
            raise ValueError("policy.block_on entries must be strings")
        sev = item.strip().lower()
        if not sev:
            continue
        if sev not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity in policy.block_on: {item!r}")
        block_on.append(sev)

    if not block_on:
        block_on = list(DEFAULT_BLOCK_ON)

    return DecisionPolicy(block_on=tuple(block_on))


def _finding_to_blocker(finding: Finding) -> dict[str, Any]:
    """Public-shape blocker — same vocabulary as /api/v1/findings rows."""
    return {
        "id": str(finding.id),
        "tool": finding.tool,
        "severity": (finding.severity or "").lower() or None,
        "state": finding.state,
        "repo": finding.repo,
        "identity_key": finding.identity_key,
        "title": finding.title or finding.identity_key,
        "cve": finding.cve_id,
    }


class DecisionService:
    """Backend-authorised decision engine."""

    async def evaluate(
        self,
        *,
        org_id: str | None = None,
        repo: str | None,
        policy: DecisionPolicy,
        session: AsyncSession,
        asset_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return a Go/No-Go verdict for the given org+repo+policy.

        Per-org isolation is mandatory: every query is scoped to ``org_id``
        or ``asset_ids``. Cross-org access is rejected upstream.
        """
        if asset_ids is None and not org_id:
            raise ValueError("org_id is required")

        # Resolve (org_id, repo) -> asset_ids when explicit asset_ids weren't
        # supplied. CI callers know the owner/repo pair but not the asset UUID
        # or source_type; match on the trailing segment of external_ref.
        if asset_ids is None:
            asset_ids = await self._resolve_asset_ids_from_org_repo(
                org_id=org_id, repo=repo, session=session,
            )

        blockers = await self._fetch_blockers(
            org_id=org_id,
            repo=repo,
            block_on=policy.block_on,
            session=session,
            asset_ids=asset_ids,
        )

        if blockers:
            verdict = "block"
            rationale = (
                f"{len(blockers)} open finding(s) at or above required severity "
                f"({', '.join(sorted(set(policy.block_on)))})."
            )
        else:
            verdict = "allow"
            rationale = (
                "No open findings at severity: "
                f"{', '.join(sorted(set(policy.block_on)))}."
            )

        return {
            "decision": verdict,
            "blockers": blockers,
            "rationale": rationale,
            "source": "backend",
        }

    async def _resolve_asset_ids_from_org_repo(
        self, *, org_id: str | None, repo: str | None, session: AsyncSession,
    ) -> list[str]:
        """Map a CI caller's (org_id, repo) into asset_ids.

        external_ref format is ``<source_type>:<owner>/<name>``. CI knows
        owner and (optionally) name; match on the trailing segment so the
        resolver works for github, gitlab, bitbucket, etc. without the
        caller having to know which.
        """
        if not org_id:
            return []
        if repo:
            suffix = f":{org_id}/{repo}"
            stmt = select(Asset.id).where(Asset.external_ref.like(f"%{suffix}"))
        else:
            # Narrow to all repo assets under this org
            pattern = f"%:{org_id}/%"
            stmt = select(Asset.id).where(
                Asset.external_ref.like(pattern), Asset.type == "repo",
            )
        rows = (await session.execute(stmt)).scalars().all()
        return [str(r) for r in rows]

    async def _fetch_blockers(
        self,
        *,
        org_id: str | None,
        repo: str | None,
        block_on: tuple[str, ...],
        session: AsyncSession,
        asset_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Read open findings matching the blocking severities, scoped to assets."""
        if asset_ids is not None and not asset_ids:
            return []

        clauses = [
            Finding.state == "open",
            func.lower(Finding.severity).in_(block_on),
        ]
        if asset_ids is not None:
            clauses.append(Finding.asset_id.in_(asset_ids))

        stmt = (
            select(Finding)
            .where(and_(*clauses))
            .order_by(Finding.id.asc())
            .limit(MAX_BLOCKERS_RETURNED)
        )
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
        return [_finding_to_blocker(f) for f in rows]
