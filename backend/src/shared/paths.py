from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso_utc(value: str) -> datetime:
    """Parse an ISO date string into a timezone-aware UTC datetime.

    Handles 'Z'-suffixed, offset-aware, and naive (no-tz) strings.
    Naive strings are assumed UTC.
    """
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


DATA_DIR = Path(os.environ.get("DATA_DIR") or str(repo_root() / "data"))



def normalize_org(org: str) -> str:
    result = "".join(ch.lower() if ch.isalnum() or ch in "_.-" else "_" for ch in org.strip())
    # Strip leading dots and reject traversal sequences
    result = result.lstrip(".")
    if not result or ".." in result:
        raise ValueError(f"Invalid organization name: {org!r}")
    return result


def normalize_path_segment(value: str) -> str:
    """Sanitize a path segment (e.g., run_id) to prevent directory traversal."""
    result = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in value.strip())
    if not result:
        raise ValueError(f"Invalid path segment: {value!r}")
    return result


def parse_org_values(values: list[str]) -> list[str]:
    by_key: dict[str, str] = {}
    for value in values:
        for item in value.split(","):
            org = item.strip()
            if not org:
                continue
            by_key.setdefault(org.lower(), org)
    return list(by_key.values())
