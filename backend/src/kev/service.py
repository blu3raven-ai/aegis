"""KevService — database operations for the CISA KEV catalog.

All writes use INSERT ... ON CONFLICT DO UPDATE (upsert) so the daily refresh
job is idempotent and safe to run multiple times without duplication.

DB operations use run_db() (background thread + dedicated engine) to avoid
event-loop conflicts when called from synchronous code or during test runs.
This follows the same pattern as src/api_keys/service.py.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import Finding, KevEntry

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class KevService:
    def upsert_catalog(self, entries: list[dict[str, Any]]) -> list[str]:
        """UPSERT all entries by cve_id PK.

        Returns the sorted list of net-new CVE ids inserted (rows that did not
        exist before this call) so callers can react to newly KEV-listed CVEs.
        Updates to existing rows are not included because the catalog rarely
        changes existing entries.
        """
        if not entries:
            return []

        now = _utcnow()
        rows = [{**e, "ingested_at": now} for e in entries]

        async def _run(session):
            existing_result = await session.execute(sa.select(KevEntry.cve_id))
            existing_ids: set[str] = {r[0] for r in existing_result.fetchall()}

            stmt = (
                pg_insert(KevEntry)
                .values(rows)
                .on_conflict_do_update(
                    index_elements=["cve_id"],
                    set_={
                        "vendor_project": pg_insert(KevEntry).excluded.vendor_project,
                        "product": pg_insert(KevEntry).excluded.product,
                        "vulnerability_name": pg_insert(KevEntry).excluded.vulnerability_name,
                        "date_added": pg_insert(KevEntry).excluded.date_added,
                        "short_description": pg_insert(KevEntry).excluded.short_description,
                        "required_action": pg_insert(KevEntry).excluded.required_action,
                        "due_date": pg_insert(KevEntry).excluded.due_date,
                        "known_ransomware_use": pg_insert(KevEntry).excluded.known_ransomware_use,
                        "notes": pg_insert(KevEntry).excluded.notes,
                        "cwes": pg_insert(KevEntry).excluded.cwes,
                        "ingested_at": pg_insert(KevEntry).excluded.ingested_at,
                    },
                )
            )
            await session.execute(stmt)

            new_ids = {e["cve_id"] for e in entries} - existing_ids
            return sorted(new_ids)

        return run_db(_run)

    def get_entry(self, cve_id: str) -> KevEntry | None:
        """Fetch a single KEV entry by CVE ID, or None if not in catalog."""
        async def _run(session):
            result = await session.execute(
                sa.select(KevEntry).where(KevEntry.cve_id == cve_id.upper())
            )
            return result.scalar_one_or_none()

        return run_db(_run)

    def list_recent(self, days: int = 30) -> list[KevEntry]:
        """Return entries added to the catalog within the last N days."""
        cutoff = date.today() - timedelta(days=days)

        async def _run(session):
            result = await session.execute(
                sa.select(KevEntry)
                .where(KevEntry.date_added >= cutoff)
                .order_by(KevEntry.date_added.desc())
            )
            return list(result.scalars().all())

        return run_db(_run)

    def get_exposure_summary(self, *, asset_ids: list[str]) -> dict[str, Any]:
        """Compute KEV overlap for the caller's accessible open findings.

        Joins findings against kev_entries on the typed cve_id column.
        The identity_key fallback covers older records where cve_id was not
        backfilled.

        Returns counts and the top KEV-matched findings sorted by occurrence.
        Empty `asset_ids` yields an empty summary (fail-closed scoping).
        """
        if not asset_ids:
            return {
                "open_findings_total": 0,
                "open_findings_in_kev": 0,
                "kev_overdue": 0,
                "kev_with_ransomware": 0,
                "top_kev_findings": [],
            }

        today = date.today()

        async def _run(session):
            scope_open = Finding.asset_id.in_(asset_ids)

            open_total_result = await session.execute(
                sa.select(sa.func.count())
                .select_from(Finding)
                .where(scope_open, Finding.state == "open")
            )
            open_findings_total: int = open_total_result.scalar_one() or 0

            # Join open findings to KEV entries via the CVE stored in detail JSON.
            # Three fallback paths handle different scanner output shapes.
            kev_join_stmt = (
                sa.select(
                    KevEntry.cve_id,
                    KevEntry.vulnerability_name,
                    KevEntry.due_date,
                    KevEntry.known_ransomware_use,
                    sa.func.count(Finding.id).label("finding_count"),
                )
                .select_from(Finding)
                .join(
                    KevEntry,
                    sa.or_(
                        Finding.cve_id == KevEntry.cve_id,
                        Finding.identity_key.contains(KevEntry.cve_id),
                    ),
                )
                .where(scope_open, Finding.state == "open")
                .group_by(
                    KevEntry.cve_id,
                    KevEntry.vulnerability_name,
                    KevEntry.due_date,
                    KevEntry.known_ransomware_use,
                )
                .order_by(sa.desc("finding_count"))
                .limit(20)
            )

            kev_rows = (await session.execute(kev_join_stmt)).fetchall()

            kev_total = sum(r.finding_count for r in kev_rows)
            kev_overdue = sum(
                r.finding_count
                for r in kev_rows
                if r.due_date and r.due_date < today
            )
            kev_ransomware = sum(
                r.finding_count
                for r in kev_rows
                if r.known_ransomware_use
            )

            top_findings = [
                {
                    "cve_id": r.cve_id,
                    "vulnerability_name": r.vulnerability_name,
                    "finding_count": r.finding_count,
                    "due_date": r.due_date.isoformat() if r.due_date else None,
                    "known_ransomware_use": bool(r.known_ransomware_use),
                }
                for r in kev_rows[:10]
            ]

            return {
                "open_findings_total": open_findings_total,
                "open_findings_in_kev": kev_total,
                "kev_overdue": kev_overdue,
                "kev_with_ransomware": kev_ransomware,
                "top_kev_findings": top_findings,
            }

        return run_db(_run)
