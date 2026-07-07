"""EPSS-related GraphQL resolvers."""
from __future__ import annotations

from typing import Any

from src.graphql.types import EpssTopFinding, EpssTopResponse
from src.epss.service import EpssService

_service = EpssService()


def epss_top(*, asset_ids: list[str], limit: int = 20, info_context: dict[str, Any] | None = None) -> EpssTopResponse:
    """Mirror of GET /api/v1/epss/top, scoped by asset_ids."""
    if not asset_ids:
        return EpssTopResponse(findings=[], count=0)

    limit = max(1, min(limit or 20, 200))
    all_findings = _service.top_findings_by_asset_ids(asset_ids, limit=limit)

    return EpssTopResponse(
        findings=[
            EpssTopFinding(
                finding_id=int(f["finding_id"]),
                tool=str(f.get("tool", "")),
                repo=str(f.get("repo", "")),
                severity=str(f.get("severity", "")),
                identity_key=str(f.get("identity_key", "")),
                cve=str(f.get("cve", "")),
                epss_score=float(f.get("epss_score") or 0),
                epss_percentile=float(f.get("epss_percentile") or 0),
                scored_date=f.get("scored_date"),
            )
            for f in all_findings
        ],
        count=len(all_findings),
    )
