"""Idempotent backfill: offload existing findings.detail fat fields to MinIO.

Run as: python -m src.shared.finding_detail_backfill [--batch-size 500] [--dry-run]

Walks the findings table in id-ordered batches, skipping rows that already
have detail_blob_key set. For each remaining row: split the detail dict per
tool, PUT the fat subset to MinIO at findings/{id}/detail.json, and rewrite
the row's detail (lean only) + detail_blob_key in a single transaction.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass, field

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Finding
from src.shared.finding_detail_blob import (
    put_detail_blob,
    split_detail,
)

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500


@dataclass
class BackfillStats:
    processed: int = 0   # rows successfully examined and updated (or dry-run counted)
    blobbed: int = 0      # rows that produced a blob written to MinIO
    lean_only: int = 0    # rows with no fat keys (blob_key stays None, row still updated)
    errored: int = 0      # rows that raised during processing


async def backfill_batch(
    session,
    batch_size: int,
    cursor_id: int,
    dry_run: bool = False,
) -> tuple[BackfillStats, int | None]:
    """Process one batch starting after cursor_id.

    Returns (stats, next_cursor_id) where next_cursor_id is None when there
    are no more rows to process.

    Failure isolation: a per-row exception logs and increments errored but does
    not abort the batch. The errored row keeps detail_blob_key IS NULL so it is
    retried on the next run.  next_cursor is the MAX id seen in the batch,
    regardless of per-row success, so an errored row never causes an infinite
    loop within the same run.
    """
    stats = BackfillStats()

    result = await session.execute(
        select(Finding)
        .where(Finding.id > cursor_id, Finding.detail_blob_key.is_(None))
        .order_by(Finding.id)
        .limit(batch_size)
    )
    rows = list(result.scalars().all())

    if not rows:
        return stats, None

    next_cursor = rows[-1].id

    for row in rows:
        try:
            lean, fat = split_detail(row.tool, row.detail or {})
            if dry_run:
                stats.processed += 1
                continue
            blob_key = None
            if fat:
                blob_key = put_detail_blob(row.id, fat)
                stats.blobbed += 1
            else:
                stats.lean_only += 1
            await session.execute(
                update(Finding)
                .where(Finding.id == row.id)
                .values(detail=lean, detail_blob_key=blob_key)
            )
            stats.processed += 1
        except Exception:
            logger.exception("backfill failed for finding id=%s", row.id)
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
    """Drive the cursor loop over all un-blobbed findings.

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
                total.blobbed += batch_stats.blobbed
                total.lean_only += batch_stats.lean_only
                total.errored += batch_stats.errored

                logger.info(
                    "batch cursor=%d processed=%d blobbed=%d lean_only=%d errored=%d",
                    cursor_id,
                    batch_stats.processed,
                    batch_stats.blobbed,
                    batch_stats.lean_only,
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
        help="Read rows + compute split but skip MinIO put and DB update.",
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
