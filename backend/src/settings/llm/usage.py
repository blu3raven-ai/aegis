"""Daily LLM token usage ledger — atomic UPSERT into llm_usage_daily."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import LlmUsageDaily


def _today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


def record_usage(*, org_id: str, tokens_in: int, tokens_out: int, scans: int = 1) -> None:
    today = _today()

    async def _q(session: AsyncSession) -> None:
        stmt = pg_insert(LlmUsageDaily).values(
            org_id=org_id,
            date=today,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            scans=scans,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["org_id", "date"],
            set_={
                "tokens_in": LlmUsageDaily.tokens_in + stmt.excluded.tokens_in,
                "tokens_out": LlmUsageDaily.tokens_out + stmt.excluded.tokens_out,
                "scans": LlmUsageDaily.scans + stmt.excluded.scans,
            },
        )
        await session.execute(stmt)

    run_db(_q)


def record_usage_from_findings(findings: list[dict], *, org_id: str = "default") -> None:
    """Sum verification_metadata.tokens_{in,out} across a batch and record one daily entry.

    No-op when no finding carries verification token counts.
    """
    total_in = 0
    total_out = 0
    for f in findings:
        meta = f.get("verification_metadata") or {}
        total_in += int(meta.get("tokens_in", 0) or 0)
        total_out += int(meta.get("tokens_out", 0) or 0)
    if total_in or total_out:
        record_usage(org_id=org_id, tokens_in=total_in, tokens_out=total_out, scans=1)


def daily_remaining(*, org_id: str, daily_budget: int) -> int:
    today = _today()

    async def _q(session: AsyncSession) -> int:
        row = (
            await session.execute(
                select(LlmUsageDaily).where(
                    LlmUsageDaily.org_id == org_id,
                    LlmUsageDaily.date == today,
                )
            )
        ).scalar_one_or_none()
        used = (row.tokens_in + row.tokens_out) if row else 0
        return max(0, daily_budget - used)

    return run_db(_q)
