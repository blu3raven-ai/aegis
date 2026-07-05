"""LLM usage REST API — daily token spend for the cost meter and chart."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import LlmUsageDaily
from src.settings.llm.service import fetch_public_llm_config
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS

router = APIRouter(prefix="/api/v1/settings/llm/usage", tags=["settings"])

_DEFAULT_ORG_ID = "default"


@router.get("")
def get_usage(
    request: Request,
    days: int = Query(30, ge=1, le=365, description="Window size in days"),
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Return a day-by-day token-spend series + today's quota status."""
    org_id = _DEFAULT_ORG_ID

    cfg = fetch_public_llm_config(org_id)
    today_budget = int((cfg or {}).get("daily_token_budget", 0))

    end = dt.datetime.now(dt.timezone.utc).date()
    start = end - dt.timedelta(days=days - 1)

    async def _q(session: AsyncSession) -> list[LlmUsageDaily]:
        result = await session.execute(
            select(LlmUsageDaily)
            .where(LlmUsageDaily.org_id == org_id)
            .where(LlmUsageDaily.date >= start)
            .order_by(LlmUsageDaily.date)
        )
        return list(result.scalars().all())

    rows = run_db(_q)
    by_date = {r.date: r for r in rows}

    series: list[dict] = []
    for i in range(days):
        d = start + dt.timedelta(days=i)
        r = by_date.get(d)
        series.append(
            {
                "date": d.isoformat(),
                "tokens_in": r.tokens_in if r else 0,
                "tokens_out": r.tokens_out if r else 0,
                "scans": r.scans if r else 0,
            }
        )

    today_used = series[-1]["tokens_in"] + series[-1]["tokens_out"] if series else 0
    return {
        "days": series,
        "today_used": today_used,
        "today_budget": today_budget,
        "today_remaining": max(0, today_budget - today_used),
    }
