"""OSV mirror storage layer — Postgres index + MinIO blob bodies.

upsert_advisories writes both stores atomically per-advisory. A partial
failure (MinIO ok, Postgres fails) is OK because the next refresh pass
will re-write both; partial state never causes incorrect matches because
the Postgres index is the authoritative join target.

The Postgres row carries the MinIO key — there's no out-of-band naming
contract, callers always go through this layer.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Iterable

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.models import OsvAdvisory, OsvVulnerableRange
from src.osv.malicious import is_malicious_advisory
from src.osv.severity import severity_word_from_osv_body
from src.shared.object_store import get_s3_client

logger = logging.getLogger(__name__)

OSV_BUCKET = "osv"


@asynccontextmanager
async def _get_session() -> AsyncGenerator[AsyncSession, None]:
    """Open a fresh AsyncSession against the current event loop.

    pytest-asyncio creates a new loop per test, which breaks SQLAlchemy engine
    caches that were created on a previous loop. Creating the engine here
    (once per context-manager call) ensures the asyncpg connection is always
    bound to the active loop. Production code uses the shared engine from
    src.db.engine instead, but calling _get_session from tests still works
    correctly because the engine is torn down with the session.
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


def _upload_blob(key: str, data: bytes, bucket: str = OSV_BUCKET) -> None:
    """Write a blob to MinIO. Creates the bucket on first call if missing."""
    client = get_s3_client()
    try:
        client.head_bucket(Bucket=bucket)
    except Exception:
        client.create_bucket(Bucket=bucket)
        logger.info("osv_store: created bucket %s", bucket)
    client.put_object(Bucket=bucket, Key=key, Body=data, ContentType="application/json")


def _download_blob(key: str, bucket: str = OSV_BUCKET) -> bytes | None:
    client = get_s3_client()
    try:
        resp = client.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()
    except Exception:
        return None


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        s = str(value)
        s = s.rstrip("Z") + "+00:00" if s.endswith("Z") else s
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _derive_severity(adv: dict) -> str | None:
    """Short severity level for the header row (fits VARCHAR(16)).

    Reads ``database_specific.severity`` when present, otherwise maps the CVSS
    vector's base score to a band (see ``osv.severity``); the full CVSS vector
    stays in the MinIO blob body. Returns None when neither is available.
    """
    # Malicious-package reports carry no CVSS; the package itself is
    # compromised, so they are always treated as critical.
    if is_malicious_advisory(adv.get("id")):
        return "critical"
    return severity_word_from_osv_body(adv)


def _flatten_ranges(adv: dict, fallback_ecosystem: str) -> list[dict]:
    """Convert an OSV advisory's nested affected/ranges/events into flat rows.

    Each row is one vulnerable interval. A single OSV ``range`` may carry several
    ``introduced``/``fixed`` pairs describing disjoint intervals (e.g. affected
    in 1.x, fixed in 1.5, re-introduced in 2.0, fixed in 2.3) — each pair becomes
    its own row. When an affected block enumerates explicit ``versions`` and has
    no usable ranges, each version becomes a point interval so exact matches
    still fire.
    """
    rows: list[dict] = []

    def _row(pkg_name, ecosystem, introduced, fixed, last_affected):
        return {
            "package_name": pkg_name,
            "ecosystem": ecosystem,
            "range_introduced": introduced,
            "range_fixed": fixed,
            "range_last_affected": last_affected,
        }

    for affected in adv.get("affected") or []:
        pkg = affected.get("package") or {}
        pkg_name = pkg.get("name")
        ecosystem = pkg.get("ecosystem") or fallback_ecosystem
        if not pkg_name:
            continue

        ranges = affected.get("ranges") or []
        produced = 0
        for rng in ranges:
            # GIT-type ranges carry commit SHAs, not version strings; they cannot
            # be ordered as semver and would produce meaningless or spurious matches.
            if rng.get("type") == "GIT":
                continue
            # OSV events are ordered; an "introduced" opens an interval that the
            # next "fixed"/"last_affected" closes. An unclosed interval is
            # open-ended (everything from "introduced" onward is affected).
            # Consecutive "introduced" without an intervening "fixed" replace
            # the pending open interval rather than emitting a spurious open range.
            open_introduced: str | None = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    open_introduced = str(event["introduced"])
                elif "fixed" in event:
                    rows.append(_row(pkg_name, ecosystem, open_introduced or "0", str(event["fixed"]), None))
                    produced += 1
                    open_introduced = None
                elif "last_affected" in event:
                    rows.append(_row(pkg_name, ecosystem, open_introduced or "0", None, str(event["last_affected"])))
                    produced += 1
                    open_introduced = None
            if open_introduced is not None:
                rows.append(_row(pkg_name, ecosystem, open_introduced, None, None))
                produced += 1

        if produced == 0:
            # No usable ranges — fall back to the explicit affected-version list.
            versions = affected.get("versions") or []
            for ver in versions:
                rows.append(_row(pkg_name, ecosystem, str(ver), None, str(ver)))
            if not versions and is_malicious_advisory(adv.get("id")):
                # Malicious-package reports frequently name the package with no
                # ranges or versions — the whole package is compromised. Emit an
                # open-ended interval so every installed version matches.
                rows.append(_row(pkg_name, ecosystem, "0", None, None))

    return rows


class OsvStore:
    """Postgres + MinIO storage for the OSV mirror."""

    async def upsert_advisories(
        self,
        advisories: Iterable[dict],
        *,
        ecosystem: str,
    ) -> int:
        """UPSERT advisory headers and replace their ranges atomically.

        Returns the count of advisories written this pass (added + updated).
        Blob writes happen first; Postgres row is only written if blob upload
        succeeds, so the row's blob_key always points to readable data.
        """
        now = datetime.now(timezone.utc)
        written = 0

        async with _get_session() as session:
            for adv in advisories:
                adv_id = adv.get("id")
                if not adv_id:
                    logger.warning("osv_store: advisory missing 'id', skipping")
                    continue

                blob_key = f"osv/{ecosystem}/{adv_id}.json"
                _upload_blob(blob_key, json.dumps(adv).encode("utf-8"))

                header_stmt = pg_insert(OsvAdvisory).values(
                    advisory_id=adv_id,
                    ecosystem=ecosystem,
                    summary=adv.get("summary"),
                    severity=_derive_severity(adv),
                    kind="malicious" if is_malicious_advisory(adv_id) else "vulnerability",
                    blob_key=blob_key,
                    published_at=_parse_iso(adv.get("published")),
                    modified_at=_parse_iso(adv.get("modified")) or now,
                    refreshed_at=now,
                ).on_conflict_do_update(
                    index_elements=["advisory_id"],
                    set_={
                        "summary": pg_insert(OsvAdvisory).excluded.summary,
                        "severity": pg_insert(OsvAdvisory).excluded.severity,
                        "kind": pg_insert(OsvAdvisory).excluded.kind,
                        "blob_key": pg_insert(OsvAdvisory).excluded.blob_key,
                        "published_at": pg_insert(OsvAdvisory).excluded.published_at,
                        "modified_at": pg_insert(OsvAdvisory).excluded.modified_at,
                        "refreshed_at": pg_insert(OsvAdvisory).excluded.refreshed_at,
                    },
                )
                await session.execute(header_stmt)

                await session.execute(
                    sa.delete(OsvVulnerableRange).where(
                        OsvVulnerableRange.advisory_id == adv_id
                    )
                )
                range_rows = _flatten_ranges(adv, fallback_ecosystem=ecosystem)
                if range_rows:
                    await session.execute(
                        sa.insert(OsvVulnerableRange),
                        [{"advisory_id": adv_id, **r} for r in range_rows],
                    )
                written += 1

        return written

    async def list_ranges_for_advisory(self, advisory_id: str) -> list[OsvVulnerableRange]:
        async with _get_session() as session:
            result = await session.execute(
                sa.select(OsvVulnerableRange).where(
                    OsvVulnerableRange.advisory_id == advisory_id
                )
            )
            return list(result.scalars().all())

    async def get_advisory_detail(self, advisory_id: str) -> dict | None:
        """Return advisory header + blob body for the detail view."""
        async with _get_session() as session:
            result = await session.execute(
                sa.select(OsvAdvisory).where(OsvAdvisory.advisory_id == advisory_id)
            )
            row = result.scalar_one_or_none()

        if row is None:
            return None

        body_bytes = _download_blob(row.blob_key)
        body = json.loads(body_bytes) if body_bytes else None
        return {
            "advisory_id": row.advisory_id,
            "ecosystem": row.ecosystem,
            "summary": row.summary,
            "severity": row.severity,
            "published_at": row.published_at,
            "modified_at": row.modified_at,
            "body": body,
        }

    async def list_changed_since(self, since: datetime) -> list[str]:
        """Return advisory_ids whose modified_at > since."""
        async with _get_session() as session:
            result = await session.execute(
                sa.select(OsvAdvisory.advisory_id).where(OsvAdvisory.modified_at > since)
            )
            return [row[0] for row in result.fetchall()]
