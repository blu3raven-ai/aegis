"""Image aggregator service — derives image inventory from findings.detail JSONB."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text

from src.db.engine import get_session

_CONTAINER_TOOL = "container_scanning"


@dataclass
class ImageRowData:
    image_digest: str
    image_name: str | None
    image_tag: str | None
    first_seen_at: datetime
    last_scanned_at: datetime | None
    critical: int
    high: int
    medium: int
    low: int
    repos: list[str]
    layer_count: int | None = None
    size_bytes: int | None = None
    base_os: str | None = None


@dataclass
class ImageListResult:
    images: list[ImageRowData]
    next_cursor: str | None
    total_count: int


def _encode_cursor(last_scanned_at: datetime, image_digest: str) -> str:
    payload = {"ts": last_scanned_at.isoformat(), "digest": image_digest}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def _decode_cursor(cursor: str | None) -> tuple[datetime, str] | None:
    if not cursor:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return datetime.fromisoformat(payload["ts"]), payload["digest"]
    except Exception as e:
        raise ValueError("Invalid cursor") from e


# The cursor predicate is in HAVING because it references the aggregate MAX(last_seen_at).
# Tuple comparison (MAX(last_seen_at), image_digest) < (cursor_ts, cursor_digest) is correct
# for our DESC ordering: it filters out rows whose (ts, digest) sort AFTER the cursor.
_LIST_SQL = text(
    """
    SELECT
      detail->>'imageDigest' AS image_digest,
      MAX(detail->>'imageName') AS image_name,
      MAX(detail->>'imageTag') AS image_tag,
      MIN(first_seen_at) AS first_seen_at,
      MAX(last_seen_at) AS last_scanned_at,
      COUNT(*) FILTER (WHERE severity = 'critical' AND state = 'open') AS critical,
      COUNT(*) FILTER (WHERE severity = 'high' AND state = 'open') AS high,
      COUNT(*) FILTER (WHERE severity = 'medium' AND state = 'open') AS medium,
      COUNT(*) FILTER (WHERE severity = 'low' AND state = 'open') AS low,
      COALESCE(ARRAY_AGG(DISTINCT repo) FILTER (WHERE repo IS NOT NULL), ARRAY[]::text[]) AS repos,
      MAX(NULLIF(detail->>'layerCount', ''))::int AS layer_count,
      MAX(NULLIF(detail->>'sizeBytes', ''))::bigint AS size_bytes,
      MAX(detail->>'baseOs') AS base_os
    FROM findings
    WHERE asset_id = ANY(:asset_ids)
      AND tool = :tool
      AND detail->>'imageDigest' IS NOT NULL
    GROUP BY detail->>'imageDigest'
    HAVING (:cursor_ts IS NULL OR (MAX(last_seen_at), detail->>'imageDigest') < (:cursor_ts, :cursor_digest))
    ORDER BY MAX(last_seen_at) DESC, detail->>'imageDigest' DESC
    LIMIT :limit
    """
)

_COUNT_SQL = text(
    """
    SELECT COUNT(DISTINCT detail->>'imageDigest')
    FROM findings
    WHERE asset_id = ANY(:asset_ids)
      AND tool = :tool
      AND detail->>'imageDigest' IS NOT NULL
    """
)


async def list_images(asset_ids: list[str], cursor: str | None, limit: int) -> ImageListResult:
    if not asset_ids:
        return ImageListResult(images=[], next_cursor=None, total_count=0)

    decoded = _decode_cursor(cursor)
    cursor_ts = decoded[0] if decoded else None
    cursor_digest = decoded[1] if decoded else None

    async with get_session() as session:
        rows = (await session.execute(
            _LIST_SQL,
            {
                "asset_ids": asset_ids,
                "tool": _CONTAINER_TOOL,
                "cursor_ts": cursor_ts,
                "cursor_digest": cursor_digest,
                "limit": limit + 1,
            },
        )).all()

        has_more = len(rows) > limit
        page = rows[:limit]

        images = [
            ImageRowData(
                image_digest=r.image_digest,
                image_name=r.image_name,
                image_tag=r.image_tag,
                first_seen_at=r.first_seen_at,
                last_scanned_at=r.last_scanned_at,
                critical=r.critical,
                high=r.high,
                medium=r.medium,
                low=r.low,
                repos=list(r.repos or []),
                layer_count=r.layer_count,
                size_bytes=r.size_bytes,
                base_os=r.base_os,
            )
            for r in page
        ]

        next_cursor = (
            _encode_cursor(images[-1].last_scanned_at, images[-1].image_digest)
            if has_more and images
            else None
        )

        total_count = int(
            (await session.execute(_COUNT_SQL, {"asset_ids": asset_ids, "tool": _CONTAINER_TOOL})).scalar() or 0
        )

        return ImageListResult(images=images, next_cursor=next_cursor, total_count=total_count)
