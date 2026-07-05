"""PackageReleaseDateService — cache reads/writes for deps.dev publish dates.

Batched to keep DB round-trips flat regardless of finding count: one read for
all requested coordinates, one upsert for everything freshly fetched. Uses
run_db() (background thread + dedicated engine) like the EPSS/KEV services so it
is safe to call from the synchronous ingest path.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Iterable

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import PackageReleaseDate

logger = logging.getLogger(__name__)

# (system, name, version)
Coord = tuple[str, str, str]


class PackageReleaseDateService:
    def get_cached(self, coords: Iterable[Coord]) -> dict[Coord, date | None]:
        """Return cached publish dates for the coordinates already known.

        A coordinate present in the map (even mapping to None) is a cache hit —
        None means "deps.dev has no date", cached to avoid re-querying a miss.
        Coordinates absent from the map are cache misses to be fetched.
        """
        wanted = list({c for c in coords})
        if not wanted:
            return {}

        async def _run(session):
            keys = [sa.tuple_(*c) for c in wanted]
            stmt = sa.select(
                PackageReleaseDate.system,
                PackageReleaseDate.name,
                PackageReleaseDate.version,
                PackageReleaseDate.published_at,
            ).where(
                sa.tuple_(
                    PackageReleaseDate.system,
                    PackageReleaseDate.name,
                    PackageReleaseDate.version,
                ).in_(keys)
            )
            rows = (await session.execute(stmt)).all()
            return {(s, n, v): pub for s, n, v, pub in rows}

        return run_db(_run)

    def upsert(self, rows: list[dict]) -> int:
        """UPSERT (system, name, version) → published_at. Returns row count."""
        if not rows:
            return 0
        now = datetime.now(timezone.utc)
        payload = [{**r, "fetched_at": now} for r in rows]

        async def _run(session):
            stmt = (
                pg_insert(PackageReleaseDate)
                .values(payload)
                .on_conflict_do_update(
                    index_elements=["system", "name", "version"],
                    set_={
                        "published_at": pg_insert(PackageReleaseDate).excluded.published_at,
                        "fetched_at": pg_insert(PackageReleaseDate).excluded.fetched_at,
                    },
                )
            )
            await session.execute(stmt)
            await session.commit()
            return len(payload)

        return run_db(_run)
