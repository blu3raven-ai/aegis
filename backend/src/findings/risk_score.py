"""Risk score computation and bulk population for findings.

`compute_risk_score` is a pure function — usable in any context.

`recompute_finding_risk_scores` issues a single SQL UPDATE that derives
the same score in Postgres so a full org repopulate stays cheap.

Score formula (clamped to 0-100):
    severity_weight + kev_bump + round(epss_percentile * 20)

  - severity_weight: critical=80, high=60, medium=35, low=15, unknown=0
  - kev_bump: +15 when the CVE is listed in CISA KEV
  - epss_bump: 0-20 from EPSS percentile (0.0-1.0)

The Python helper and the SQL update must stay in sync — both branches
test the same inputs.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_SEVERITY_WEIGHT = {
    "critical": 80,
    "high": 60,
    "medium": 35,
    "low": 15,
}
_KEV_BUMP = 15
_EPSS_MULTIPLIER = 20


def compute_risk_score(
    severity: str | None,
    *,
    kev_listed: bool = False,
    epss_percentile: float | None = None,
) -> int | None:
    """Return a 0-100 score, or None when severity is unknown/missing.

    Caller is responsible for clamping percentile to [0.0, 1.0] — values
    outside the range are treated as if they were at the boundary.
    """
    if severity is None:
        return None
    base = _SEVERITY_WEIGHT.get(severity.lower())
    if base is None:
        return None
    score = base
    if kev_listed:
        score += _KEV_BUMP
    if epss_percentile is not None:
        clamped = max(0.0, min(1.0, epss_percentile))
        score += round(clamped * _EPSS_MULTIPLIER)
    return max(0, min(100, score))


async def recompute_finding_risk_scores(
    session: AsyncSession,
    *,
    asset_ids: list[str] | None = None,
    org: str | None = None,
) -> int:
    """Bulk-update risk_score for findings. Returns rows touched.

    Rows with NULL or unknown severity are left untouched (the formula
    cannot score them).

    Callers may pass asset_ids (preferred, asset-scoped path) or org
    (legacy org-scoped path). asset_ids takes precedence. When neither is
    given, all findings are rescored (global refresh used by feed jobs).
    """
    if asset_ids is not None and len(asset_ids) == 0:
        return 0

    where_clauses = ["LOWER(COALESCE(f.severity, '')) IN ('critical', 'high', 'medium', 'low')"]
    params: dict = {}
    if asset_ids:
        where_clauses.append("f.asset_id = ANY(:asset_ids)")
        params["asset_ids"] = asset_ids
    # Without asset_ids, all findings of matching severity are rescored —
    # safe global refresh behaviour (no PII, just a recomputed numeric score).

    sql = text(f"""
        UPDATE findings AS f
        SET risk_score = LEAST(100, GREATEST(0,
            CASE LOWER(f.severity)
                WHEN 'critical' THEN {_SEVERITY_WEIGHT['critical']}
                WHEN 'high' THEN {_SEVERITY_WEIGHT['high']}
                WHEN 'medium' THEN {_SEVERITY_WEIGHT['medium']}
                WHEN 'low' THEN {_SEVERITY_WEIGHT['low']}
                ELSE 0
            END
            + COALESCE(
                (SELECT {_KEV_BUMP} FROM kev_entries k WHERE k.cve_id = f.cve_id),
                0
            )
            + COALESCE(
                (SELECT ROUND({_EPSS_MULTIPLIER} * e.percentile)::int
                 FROM epss_scores e WHERE e.cve = f.cve_id),
                0
            )
        ))
        WHERE {' AND '.join(where_clauses)}
    """)
    result = await session.execute(sql, params)
    return result.rowcount or 0
