"""Idempotent backfill: populate typed columns from existing findings.detail.

Run as: python -m src.shared.finding_queryable_backfill [--batch-size 500] [--dry-run]

Walks the findings table in id-ordered batches, skipping rows that already have
any of the 5 typed columns (cve_id, file_path, title, rule_name, package_name)
populated. For each remaining row: call extract_queryable_fields(detail) and
UPDATE the 5 columns.

Idempotent: re-runs skip already-populated rows. Rows where the extractor finds
no matching keys (all 5 columns remain None) are re-processed on subsequent runs
but no-op DB writes occur — same trade-off as finding_detail_backfill.py for
lean-only rows.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Finding
from src.shared.finding_queryable_fields import extract_queryable_fields

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500


@dataclass
class BackfillStats:
    processed: int = 0     # rows examined (selected by the WHERE filter)
    populated: int = 0     # rows where extractor returned at least one non-None field
    all_null: int = 0      # rows where extractor returned all None (detail had no matching keys)
    errored: int = 0       # rows that raised during processing


async def backfill_batch(
    session: AsyncSession,
    batch_size: int,
    cursor_id: int,
    dry_run: bool = False,
) -> tuple[BackfillStats, int | None]:
    """Process one batch starting after cursor_id.

    Returns (stats, next_cursor_id) where next_cursor_id is None when there
    are no more rows to process.

    Failure isolation: a per-row exception logs and increments errored but does
    not abort the batch. The errored row keeps all 5 typed columns NULL so it is
    retried on the next run. next_cursor is the MAX id seen in the batch,
    regardless of per-row success, so an errored row never causes an infinite
    loop within the same run.
    """
    stats = BackfillStats()

    result = await session.execute(
        select(Finding.id, Finding.tool, Finding.detail)
        .where(
            Finding.id > cursor_id,
            Finding.cve_id.is_(None),
            Finding.file_path.is_(None),
            Finding.title.is_(None),
            Finding.rule_name.is_(None),
            Finding.package_name.is_(None),
        )
        .order_by(Finding.id)
        .limit(batch_size)
    )
    rows = list(result.all())

    if not rows:
        return stats, None

    next_cursor = rows[-1][0]  # rows[-1].id

    for row_id, tool, detail in rows:
        try:
            extracted = extract_queryable_fields(detail or {})
            has_any = any(v is not None for v in extracted.values())

            if dry_run:
                stats.processed += 1
                if has_any:
                    stats.populated += 1
                else:
                    stats.all_null += 1
                continue

            # Unconditionally UPDATE: we "touch" all-null rows so re-run filter works.
            await session.execute(
                update(Finding)
                .where(Finding.id == row_id)
                .values(
                    cve_id=extracted["cve_id"],
                    file_path=extracted["file_path"],
                    title=extracted["title"],
                    rule_name=extracted["rule_name"],
                    package_name=extracted["package_name"],
                )
            )
            stats.processed += 1
            if has_any:
                stats.populated += 1
            else:
                stats.all_null += 1
        except Exception:
            logger.exception("backfill failed for finding id=%s", row_id)
            stats.errored += 1

    if not dry_run:
        await session.commit()

    # Signal end-of-table when this batch was smaller than the page size.
    if len(rows) < batch_size:
        return stats, None

    return stats, next_cursor


async def backfill_all(
    batch_size: int = DEFAULT_BATCH_SIZE,
    dry_run: bool = False,
) -> BackfillStats:
    """Drive the cursor loop over all un-populated typed columns.

    Returns cumulative stats across all batches.

    Creates a fresh engine bound to the running event loop so this coroutine
    is safe to call from asyncio.run() as a CLI entrypoint, and equally safe
    to call from test harnesses that create their own loops.
    """
    total = BackfillStats()
    cursor_id = 0

    engine = create_async_engine(DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with session_factory() as session:
            while True:
                batch_stats, next_cursor = await backfill_batch(
                    session, batch_size, cursor_id, dry_run=dry_run
                )
                total.processed += batch_stats.processed
                total.populated += batch_stats.populated
                total.all_null += batch_stats.all_null
                total.errored += batch_stats.errored

                logger.info(
                    "batch cursor=%d processed=%d populated=%d all_null=%d errored=%d",
                    cursor_id,
                    batch_stats.processed,
                    batch_stats.populated,
                    batch_stats.all_null,
                    batch_stats.errored,
                )

                if next_cursor is None:
                    break
                cursor_id = next_cursor
    finally:
        await engine.dispose()

    return total


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read rows + extract fields but skip DB updates.",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse_args()
    stats = asyncio.run(backfill_all(batch_size=args.batch_size, dry_run=args.dry_run))
    logger.info("Backfill complete: %s", stats)
    return 0 if stats.errored == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
