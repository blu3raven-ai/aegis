from __future__ import annotations

from datetime import datetime, timezone

from src.db.helpers import run_db
from src.db.models import License


def read_license_key() -> str | None:
    """Read license key from database."""
    async def _query(session):
        row = await session.get(License, 1)
        if not row or not row.key_data:
            return None
        return row.key_data.strip() or None

    try:
        return run_db(_query)
    except Exception:
        return None


def write_license_key(key: str) -> None:
    """Write license key to database."""
    async def _query(session):
        row = await session.get(License, 1)
        if row:
            row.key_data = key
            row.activated_at = datetime.now(timezone.utc)
        else:
            session.add(License(id=1, key_data=key, activated_at=datetime.now(timezone.utc)))

    run_db(_query)


def remove_license_key() -> None:
    """Remove license key from database."""
    async def _query(session):
        row = await session.get(License, 1)
        if row:
            await session.delete(row)

    run_db(_query)
