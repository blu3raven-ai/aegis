"""Idempotent backfill: re-classify license + dependency-origin columns on
existing SBOM components.

Run as: python -m src.sbom.license_origin_backfill [--batch-size 500] [--dry-run]

The license columns (#1063) and the tri-state ``is_direct`` (#1070) are populated
only on the asset's next scan, so the estate under-reports license risk and
direct/transitive origin until then. This walks every asset that has an SBOM, in
id-ordered batches, downloads its stored CycloneDX blob, and re-runs the normal
``populate_components`` pipeline — which re-derives ``license_expression``,
``license_category``, ``is_direct`` and ``source_tool`` from the same blob that
ingest used. No new SBOM parsing lives here, so the result is identical by
construction to ingest-time classification.

Idempotent and resumable: re-running reproduces the same values (the blob is the
authoritative latest SBOM), and the id cursor advances per asset regardless of
outcome so an errored asset never loops. Each asset's original ``scanned_at`` is
preserved so re-classifying doesn't reset the displayed scan time. A missing or
empty blob is a fail-safe skip (existing rows are NOT deleted) and is reported,
not counted as success.
"""
from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass

from sqlalchemy import select

from src.containers.sbom_store import populate_sbom_components as populate_image
from src.db.helpers import run_db
from src.db.models import Asset, Sbom
from src.dependencies.sbom_store import populate_sbom_components as populate_repo
from src.sbom.storage import download_from_minio

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500


@dataclass
class BackfillStats:
    processed: int = 0              # SBOM rows examined
    reindexed: int = 0             # assets whose components were re-classified
    components_indexed: int = 0    # total component rows rewritten
    skipped_no_blob: int = 0       # blob missing/evicted from MinIO (rows untouched)
    skipped_empty: int = 0         # blob present but no components (rows untouched)
    skipped_unknown_type: int = 0  # asset type outside repo|image (defensive)
    errored: int = 0               # assets that raised during re-index

    def __str__(self) -> str:
        return (
            f"processed={self.processed} reindexed={self.reindexed} "
            f"components_indexed={self.components_indexed} "
            f"skipped_no_blob={self.skipped_no_blob} skipped_empty={self.skipped_empty} "
            f"skipped_unknown_type={self.skipped_unknown_type} errored={self.errored}"
        )


def _fetch_batch(cursor_id: int, batch_size: int) -> list[tuple]:
    """One id-ordered batch of (sbom_id, asset_id, s3_key, asset_type, display_name,
    scanned_at) past the cursor — every asset that has an SBOM, full estate."""
    async def _query(session):
        rows = (
            await session.execute(
                select(
                    Sbom.id, Sbom.asset_id, Sbom.s3_key,
                    Asset.type, Asset.display_name, Sbom.scanned_at,
                )
                .join(Asset, Asset.id == Sbom.asset_id)
                .where(Sbom.id > cursor_id)
                .order_by(Sbom.id)
                .limit(batch_size)
            )
        ).all()
        return [tuple(r) for r in rows]

    return run_db(_query)


def _reindex_asset(row: tuple, dry_run: bool, stats: BackfillStats) -> None:
    sbom_id, asset_id, s3_key, asset_type, display_name, scanned_at = row
    name = display_name or asset_id

    sbom = download_from_minio(s3_key)
    if sbom is None:
        stats.skipped_no_blob += 1
        logger.warning("[backfill] no SBOM blob for %s (%s) — rows kept, needs re-scan", name, s3_key)
        return
    if not isinstance(sbom, dict) or not sbom.get("components"):
        stats.skipped_empty += 1
        return

    if dry_run:
        stats.reindexed += 1
        stats.components_indexed += len(sbom["components"])
        return

    if asset_type == "repo":
        count = populate_repo(name, name, sbom, asset_id=asset_id, scanned_at=scanned_at)
    elif asset_type == "image":
        count = populate_image(name, name, sbom, asset_id=asset_id, scanned_at=scanned_at)
    else:
        stats.skipped_unknown_type += 1
        return

    stats.reindexed += 1
    stats.components_indexed += count


def backfill_all(batch_size: int = DEFAULT_BATCH_SIZE, dry_run: bool = False) -> BackfillStats:
    """Re-index every asset's SBOM components, batched by Sbom.id."""
    stats = BackfillStats()
    cursor = 0
    while True:
        batch = _fetch_batch(cursor, batch_size)
        if not batch:
            break
        for row in batch:
            stats.processed += 1
            try:
                _reindex_asset(row, dry_run, stats)
            except Exception:
                stats.errored += 1
                logger.exception("[backfill] failed to re-index asset %s", row[1])
            cursor = row[0]  # advance by Sbom.id regardless of per-asset outcome
        logger.info("[backfill] %s", stats)
        if len(batch) < batch_size:
            break
    return stats


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Re-classify SBOM license + dependency-origin columns.")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--dry-run", action="store_true", help="Classify + count without writing.")
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse_args()
    stats = backfill_all(batch_size=args.batch_size, dry_run=args.dry_run)
    logger.info("[backfill] complete (dry_run=%s): %s", args.dry_run, stats)
    return 0 if stats.errored == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
