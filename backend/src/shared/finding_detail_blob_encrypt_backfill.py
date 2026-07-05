"""Idempotent backfill: encrypt at rest any finding-detail blob still stored as
plaintext JSON (written before detail-blob encryption).

Run as: python -m src.shared.finding_detail_blob_encrypt_backfill [--batch-size 500] [--dry-run]

Walks findings that have a detail_blob_key, in id-ordered batches. For each: read
the raw object; if it is already encrypted, skip; otherwise parse the plaintext
JSON and re-upload it encrypted via put_detail_blob. The DB row is untouched (the
blob key is stable), so this is pure object-store rewriting.

Idempotent: re-runs skip already-encrypted blobs. A blob that is missing or
unparseable is counted as errored and left as-is.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Finding
from src.shared.encryption import is_encrypted
from src.shared.finding_detail_blob import put_detail_blob
from src.shared.object_store import download_bytes

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500


@dataclass
class Stats:
    processed: int = 0
    encrypted: int = 0
    already_encrypted: int = 0
    errored: int = 0


async def _backfill_batch(session: AsyncSession, batch_size: int, cursor_id: int, dry_run: bool):
    stats = Stats()
    rows = (
        await session.execute(
            select(Finding.id, Finding.detail_blob_key)
            .where(Finding.id > cursor_id, Finding.detail_blob_key.isnot(None))
            .order_by(Finding.id)
            .limit(batch_size)
        )
    ).all()
    if not rows:
        return stats, None
    next_cursor = rows[-1][0]

    for finding_id, blob_key in rows:
        stats.processed += 1
        try:
            raw = download_bytes(blob_key)
            if raw is None:
                logger.warning("blob missing for finding id=%s key=%r", finding_id, blob_key)
                stats.errored += 1
                continue
            if is_encrypted(raw.decode()):
                stats.already_encrypted += 1
                continue
            fat = json.loads(raw.decode())
            if not dry_run:
                put_detail_blob(finding_id, fat)  # re-uploads encrypted under the stable key
            stats.encrypted += 1
        except Exception:
            logger.exception("encrypt-backfill failed for finding id=%s", finding_id)
            stats.errored += 1

    return stats, (next_cursor if len(rows) == batch_size else None)


async def backfill_all(batch_size: int = DEFAULT_BATCH_SIZE, dry_run: bool = False) -> Stats:
    total = Stats()
    cursor_id = 0
    engine = create_async_engine(DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as session:
            while True:
                batch, next_cursor = await _backfill_batch(session, batch_size, cursor_id, dry_run)
                total.processed += batch.processed
                total.encrypted += batch.encrypted
                total.already_encrypted += batch.already_encrypted
                total.errored += batch.errored
                logger.info(
                    "batch cursor=%d processed=%d encrypted=%d already=%d errored=%d",
                    cursor_id, batch.processed, batch.encrypted,
                    batch.already_encrypted, batch.errored,
                )
                if next_cursor is None:
                    break
                cursor_id = next_cursor
    finally:
        await engine.dispose()
    return total


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--dry-run", action="store_true", help="Report counts; write nothing.")
    args = parser.parse_args()
    stats = asyncio.run(backfill_all(batch_size=args.batch_size, dry_run=args.dry_run))
    logger.info("Encrypt-backfill complete: %s", stats)
    return 0 if stats.errored == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
