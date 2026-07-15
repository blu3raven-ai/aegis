"""GraphQL resolvers for the cross-scanner findings surface.

Replaces the GET /api/v1/findings REST list endpoint. Summary counts,
assignable-user lookups, and mutations live on REST (GET /findings/summary,
GET /findings/assignable-users, PATCH /findings/{id}, PATCH /findings).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

import strawberry

from src.db.engine import get_session
from src.findings.service import (
    FindingsListFilters,
    list_findings,
)


@strawberry.type
class FindingRow:
    id: str
    scanner: str
    severity: Optional[str]
    state: Optional[str]
    title: Optional[str]
    cve: Optional[str]
    package: Optional[str]
    file_path: Optional[str]
    line: Optional[int]
    repo: Optional[str]
    org_id: str
    created_at: Optional[str]
    updated_at: Optional[str]
    epss_percentile: Optional[float] = None
    kev: Optional[bool] = None
    malicious: Optional[bool] = None
    cwe: Optional[str] = None
    risk_score: Optional[int] = None
    cvss_score: Optional[float] = None
    action_band: Optional[str] = None
    assignee_user_id: Optional[str] = None
    verdict: Optional[str] = None
    has_fix: Optional[bool] = None
    # One-line disproof for ruled-out findings, so the "considered but ruled out"
    # list can show WHY without a per-row detail fetch. None for other verdicts.
    ruled_out_reason: Optional[str] = None


@strawberry.type
class FindingsVerdictCounts:
    total: int
    confirmed: int
    needs_verify: int
    possible: int
    ruled_out: int
    legacy: int
    needs_runtime_verification: int = 0


@strawberry.type
class FindingsSearchResult:
    findings: list[FindingRow]
    next_cursor: Optional[str]
    total_count: int
    verdict_counts: Optional[FindingsVerdictCounts] = None


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [v.strip() for v in value.split(",") if v.strip()]
    return parts or None


def _parse_iso_or_none(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"invalid first_seen_after: {value}") from exc


def _ruled_out_reason(d: dict[str, Any]) -> str | None:
    """The verifier's grounded disproof sentence, only for ruled-out findings."""
    if d.get("verdict") != "ruled_out":
        return None
    meta = d.get("verification_metadata")
    reason = meta.get("ruled_out_reason") if isinstance(meta, dict) else None
    text = reason.get("reasoning") if isinstance(reason, dict) else None
    return text.strip() if isinstance(text, str) and text.strip() else None


def _row_from_dict(d: dict[str, Any]) -> FindingRow:
    return FindingRow(
        id=str(d.get("id") or ""),
        scanner=str(d.get("scanner") or ""),
        severity=d.get("severity"),
        state=d.get("state"),
        title=d.get("title"),
        cve=d.get("cve"),
        package=d.get("package"),
        file_path=d.get("file_path"),
        line=d.get("line"),
        repo=d.get("repo"),
        org_id=str(d.get("org_id") or ""),
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
        epss_percentile=d.get("epss_percentile"),
        kev=d.get("kev"),
        malicious=d.get("malicious"),
        cwe=d.get("cwe"),
        risk_score=d.get("risk_score"),
        cvss_score=d.get("cvss_score"),
        action_band=d.get("action_band"),
        assignee_user_id=d.get("assignee_user_id"),
        verdict=d.get("verdict"),
        has_fix=bool(d.get("recommended_fix")),
        ruled_out_reason=_ruled_out_reason(d),
    )


async def findings_search(
    *,
    asset_ids: list[str],
    org: Optional[str] = None,
    severity: Optional[str] = None,
    scanner: Optional[str] = None,
    state: Optional[str] = None,
    q: Optional[str] = None,
    cve: Optional[str] = None,
    repo: Optional[str] = None,
    sort: str = "severity",
    direction: str = "desc",
    limit: int = 50,
    cursor: Optional[str] = None,
    page: int = 1,
    archived: Optional[bool] = None,
    first_seen_after: Optional[str] = None,
    cwe: Optional[str] = None,
    kev: Optional[bool] = None,
    epss_min: Optional[float] = None,
    risk_score_min: Optional[int] = None,
    bands: Optional[str] = None,
    assignee: Optional[str] = None,
    verdict: Optional[str] = None,
) -> FindingsSearchResult:
    async with get_session() as session:
        filters = FindingsListFilters(
            org_id=org or "",
            asset_ids=asset_ids,
            severity=_split_csv(severity),
            scanner=_split_csv(scanner),
            state=_split_csv(state),
            q=q,
            cve=cve,
            repo=_split_csv(repo),
            sort=sort,
            direction=direction,
            limit=limit,
            cursor=cursor,
            archived=archived,
            first_seen_after=_parse_iso_or_none(first_seen_after),
            cwe=cwe,
            kev=kev,
            epss_min=epss_min,
            risk_score_min=risk_score_min,
            bands=_split_csv(bands),
            assignee_user_id=assignee,
            page=page,
            verdict=verdict,
        )
        payload = await list_findings(filters, session)

    vc = payload.get("verdict_counts")
    return FindingsSearchResult(
        findings=[_row_from_dict(f) for f in payload.get("findings") or []],
        next_cursor=payload.get("next_cursor"),
        total_count=int(payload.get("total_count") or 0),
        verdict_counts=FindingsVerdictCounts(**vc) if vc else None,
    )
