"""EpssService — database operations for FIRST.org EPSS scores.

All writes use INSERT ... ON CONFLICT DO UPDATE (upsert) so the daily refresh
job is idempotent and safe to run multiple times without duplication.

DB operations use run_db() (background thread + dedicated engine) to avoid
event-loop conflicts when called from synchronous code or during test runs.
This follows the same pattern as src/kev/service.py.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import Asset, EpssScore, Finding

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EpssService:
    def upsert_scores(self, rows: Iterable[dict[str, Any]]) -> int:
        """UPSERT all rows by cve PK.

        Returns the number of net-new rows inserted (rows that did not exist
        before this call). Existing rows are still updated with the latest
        score/percentile/scored_date but are not counted as new.
        """
        rows_list = list(rows)
        if not rows_list:
            return 0

        now = _utcnow()
        payload = [{**r, "fetched_at": now} for r in rows_list]

        async def _run(session):
            existing_result = await session.execute(sa.select(EpssScore.cve))
            existing_ids: set[str] = {r[0] for r in existing_result.fetchall()}

            stmt = (
                pg_insert(EpssScore)
                .values(payload)
                .on_conflict_do_update(
                    index_elements=["cve"],
                    set_={
                        "score": pg_insert(EpssScore).excluded.score,
                        "percentile": pg_insert(EpssScore).excluded.percentile,
                        "scored_date": pg_insert(EpssScore).excluded.scored_date,
                        "fetched_at": pg_insert(EpssScore).excluded.fetched_at,
                    },
                )
            )
            await session.execute(stmt)

            new_ids = {r["cve"] for r in rows_list} - existing_ids
            return len(new_ids)

        return run_db(_run)

    def get_score(self, cve: str) -> EpssScore | None:
        """Fetch a single EPSS score by CVE ID, or None if not in feed."""
        async def _run(session):
            result = await session.execute(
                sa.select(EpssScore).where(EpssScore.cve == cve.upper())
            )
            return result.scalar_one_or_none()

        return run_db(_run)

    def top_findings_by_epss(
        self,
        org_id: str | None = None,
        limit: int = 20,
        *,
        asset_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return open findings ranked by EPSS score, descending.

        Joins findings against epss_scores on the typed cve_id column.
        The identity_key fallback covers older records where cve_id was not
        backfilled.
        """
        if asset_ids is None and org_id is None:
            raise ValueError("either org_id or asset_ids is required")

        # Org-only callers no longer have an asset scope; fail closed. Everything
        # with a scope runs the same query as top_findings_by_asset_ids.
        if not asset_ids:
            return []
        return self.top_findings_by_asset_ids(asset_ids, limit=limit)

    def top_findings_by_asset_ids(self, asset_ids: list[str], limit: int = 20) -> list[dict[str, Any]]:
        """Return open findings scoped by asset_ids ranked by EPSS score, descending."""
        async def _run(session):
            join_stmt = (
                sa.select(
                    Finding.id.label("finding_id"),
                    Finding.tool,
                    Finding.asset_id,
                    Asset.display_name.label("repo"),
                    Finding.severity,
                    Finding.identity_key,
                    EpssScore.cve,
                    EpssScore.score,
                    EpssScore.percentile,
                    EpssScore.scored_date,
                )
                .select_from(Finding)
                .join(
                    EpssScore,
                    sa.or_(
                        Finding.cve_id == EpssScore.cve,
                        Finding.identity_key.contains(EpssScore.cve),
                    ),
                )
                .join(Asset, Asset.id == Finding.asset_id)
                .where(Finding.asset_id.in_(asset_ids), Finding.state == "open")
                .order_by(EpssScore.score.desc(), Finding.id.asc())
                .limit(limit)
            )

            rows = (await session.execute(join_stmt)).fetchall()
            return [
                {
                    "finding_id": r.finding_id,
                    "tool": r.tool,
                    "repo": r.repo,
                    "severity": r.severity,
                    "identity_key": r.identity_key,
                    "cve": r.cve,
                    "epss_score": r.score,
                    "epss_percentile": r.percentile,
                    "scored_date": r.scored_date.isoformat() if r.scored_date else None,
                }
                for r in rows
            ]

        return run_db(_run)
