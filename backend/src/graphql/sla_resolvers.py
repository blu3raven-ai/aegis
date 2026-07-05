"""SLA-related GraphQL resolvers."""
from __future__ import annotations

from typing import Any

from src.graphql.types import BreachSummary, SeverityBreachStat
from src.sla.service import get_sla_service


def sla_breach_summary(*, asset_ids: list[str], info_context: dict[str, Any]) -> BreachSummary:
    """Mirror of GET /api/v1/sla/breach-summary, scoped by asset_ids."""
    service = get_sla_service()
    data = service.summary_by_asset_ids(asset_ids)

    def _stat(sev_dict: dict) -> SeverityBreachStat:
        return SeverityBreachStat(
            open=int(sev_dict.get("open", 0)),
            breached=int(sev_dict.get("breached", 0)),
            breached_pct=float(sev_dict.get("breached_pct", 0.0)),
        )

    return BreachSummary(
        critical=_stat(data.get("critical", {})),
        high=_stat(data.get("high", {})),
        medium=_stat(data.get("medium", {})),
        low=_stat(data.get("low", {})),
    )
