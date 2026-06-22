"""OSV catalog refresh + reconcile job.

Single callable: refresh_osv_catalog(). Designed to be called from
AutoRerunScheduler on a daily tick or from the admin /internal/osv/refresh
endpoint.

Wiring:
  fetcher.fetch_ecosystem(ecosystem)  → stream of parsed advisories
  store.upsert_advisories(...)        → Postgres + MinIO write
  store.list_changed_since(ts)        → which advisory_ids moved this pass
  rematch.reconcile_sbom_matches(ids) → re-match affected SBOMs in-backend

Per-ecosystem failures are logged and reported but do not abort the
whole pass — other ecosystems still get processed.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.models import OsvRefreshRun
from src.osv.ecosystems import DEFAULT_FETCH_ECOSYSTEMS
from src.osv.rematch import reconcile_sbom_matches
from src.osv.fetcher import fetch_ecosystem
from src.osv.store import OsvStore

logger = logging.getLogger(__name__)

# OSV's GCS bucket directory names are case-sensitive (e.g. "PyPI", "crates.io",
# "RubyGems"); a wrong-cased name silently 404s. The canonical list lives in
# src.osv.ecosystems and covers language + distro ecosystems.
_DEFAULT_ECOSYSTEMS = ",".join(DEFAULT_FETCH_ECOSYSTEMS)


def _configured_ecosystems() -> list[str]:
    raw = os.environ.get("OSV_ECOSYSTEMS", _DEFAULT_ECOSYSTEMS)
    return [e.strip() for e in raw.split(",") if e.strip()]


@asynccontextmanager
async def _get_session() -> AsyncGenerator[AsyncSession, None]:
    """Open a fresh AsyncSession against the current event loop.

    Mirrors the pattern in src.osv.store to avoid pytest-asyncio loop-reuse
    issues. Each call creates and disposes its own engine so the asyncpg
    connection is always bound to the active loop.
    """
    from src.db.engine import DATABASE_URL
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    finally:
        await engine.dispose()


async def _record_run_start() -> int:
    """Insert an osv_refresh_runs row, return its id."""
    now = datetime.now(timezone.utc)
    async with _get_session() as session:
        run = OsvRefreshRun(
            started_at=now,
            advisories_added=0,
            advisories_changed=0,
            jobs_enqueued=0,
        )
        session.add(run)
        await session.flush()
        run_id = run.id
    return run_id


async def _record_run_finish(
    run_id: int,
    *,
    advisories_added: int,
    advisories_changed: int,
    jobs_enqueued: int,
    error: str | None,
) -> None:
    now = datetime.now(timezone.utc)
    async with _get_session() as session:
        await session.execute(
            sa.update(OsvRefreshRun)
            .where(OsvRefreshRun.id == run_id)
            .values(
                finished_at=now,
                advisories_added=advisories_added,
                advisories_changed=advisories_changed,
                jobs_enqueued=jobs_enqueued,
                error=error,
            )
        )


async def _last_finished_at() -> datetime:
    """Return finished_at of the most recent successful refresh, or epoch-zero."""
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    async with _get_session() as session:
        result = await session.execute(
            sa.select(OsvRefreshRun.finished_at)
            .where(OsvRefreshRun.finished_at.is_not(None))
            .where(OsvRefreshRun.error.is_(None))
            .order_by(OsvRefreshRun.finished_at.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
    return row if row is not None else epoch


async def _async_refresh() -> dict:
    started = time.time()
    run_id = await _record_run_start()
    since = await _last_finished_at()
    store = OsvStore()

    total_added = 0
    errors: list[str] = []

    for ecosystem in _configured_ecosystems():
        try:
            advisories = fetch_ecosystem(ecosystem)
            count = await store.upsert_advisories(advisories, ecosystem=ecosystem)
            total_added += count
            logger.info("osv_refresh: %s — %d advisories upserted", ecosystem, count)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{ecosystem}: {exc}")
            logger.exception("osv_refresh: ecosystem %s failed", ecosystem)

    changed_ids = await store.list_changed_since(since)
    # Re-match affected SBOMs directly in the backend (no runner jobs). The
    # osv_refresh_runs.jobs_enqueued column now records the count of findings
    # reconciled rather than dispatched jobs.
    findings_reconciled = await reconcile_sbom_matches(
        changed_ids, refresh_run_id=run_id,
    )

    error_str = "; ".join(errors) if errors else None
    await _record_run_finish(
        run_id,
        advisories_added=total_added,
        advisories_changed=len(changed_ids),
        jobs_enqueued=findings_reconciled,
        error=error_str,
    )

    runtime_ms = int((time.time() - started) * 1000)
    return {
        "refresh_run_id": run_id,
        "advisories_added": total_added,
        "advisories_changed": len(changed_ids),
        "findings_reconciled": findings_reconciled,
        "runtime_ms": runtime_ms,
        "error": error_str,
    }


def refresh_osv_catalog() -> dict:
    """Sync entrypoint — wraps the async pipeline in asyncio.run().

    Returns a summary dict suitable for logging or admin endpoint response.
    """
    return asyncio.run(_async_refresh())


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    print(refresh_osv_catalog())
    sys.exit(0)
