"""Release listing service — reads pre_release ScanRun rows for org-wide views.

Pure data access; no HTTP concerns. The router translates filters and shapes
the response. Cursor pagination is keyset-style on (started_at DESC, id DESC),
mirroring `findings/service.py` so the encoding is consistent across the API.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, nulls_last, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import EpssScore, Finding, KevEntry, ScanRun

# Spec-defined surface — keep narrow so the Pydantic Literal matches exactly.
_VALID_STATUSES = frozenset({"queued", "running", "completed", "failed"})
_VALID_VERDICTS = frozenset({"go", "warn", "no_go", "pending", "unknown"})

# Map raw DB statuses (which may include ingesting/cancelled) onto the public set
# so a stale enum from the runner pipeline doesn't break the response model.
_STATUS_NORMALISE = {
    "queued": "queued",
    "running": "running",
    "ingesting": "running",
    "completed": "completed",
    "failed": "failed",
    "cancelled": "failed",
}

MAX_LIMIT = 100
DEFAULT_LIMIT = 20

# Values of metadata.source that indicate a CI-triggered scan. The field is set
# by scans/service.py::submit_scan (currently "user") and by future CI webhooks.
_CI_SOURCES = frozenset({"ci", "github_actions", "gitlab_ci", "bitbucket_pipelines"})


@dataclass
class ReleaseListFilters:
    asset_ids: list[str]
    repo_id: str | None = None
    status: str | None = None
    verdict: str | None = None
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


@dataclass
class ReleaseRow:
    scan_id: str
    repo_id: str
    repo: str
    ref: str | None
    commit_sha: str
    short_sha: str
    verdict: str
    blocker_count: int
    warn_count: int
    scanner_count: int
    status: str
    started_at: str | None
    finished_at: str | None
    triggered_by: dict[str, str]


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> dict[str, Any]:
    pad = "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(cursor + pad)
        return json.loads(raw)
    except (binascii.Error, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid cursor") from exc


def _normalise_status(raw: str | None) -> str:
    # why: the runner is the sole producer of ScanRun.status. A silent fallback
    # would mislabel a new runner state as "failed" and hide the regression;
    # raise instead so the missing mapping surfaces immediately.
    key = (raw or "").lower()
    if key not in _STATUS_NORMALISE:
        raise ValueError(f"unknown ScanRun status: {raw!r}")
    return _STATUS_NORMALISE[key]


def _compute_verdict(status: str, counts: dict[str, Any]) -> str:
    """Derive the release verdict from progress + status.

    Order matches the spec: blockers (criticals) trump warns (highs), and
    severity-based verdicts only apply once the scan has any findings recorded.
    A clean completed scan resolves to `go`; in-flight scans resolve to
    `pending`; terminal non-completed scans resolve to `unknown`.
    """
    blocker = int(counts.get("critical") or 0)
    warn = int(counts.get("high") or 0)

    if blocker > 0:
        return "no_go"
    if warn > 0:
        return "warn"
    if status == "completed":
        return "go"
    if status in {"queued", "running"}:
        return "pending"
    return "unknown"


def _triggered_by(meta: dict[str, Any]) -> dict[str, str]:
    submitted_by = meta.get("submitted_by")
    if meta.get("source") in _CI_SOURCES:
        actor_id = submitted_by or "ci"
        return {
            "actor_type": "ci",
            "actor_id": actor_id,
            "display_name": actor_id,
        }
    actor_id = submitted_by or "unknown"
    return {
        "actor_type": "user",
        "actor_id": actor_id,
        "display_name": actor_id,
    }


def _row_from_scan(row: ScanRun) -> ReleaseRow:
    meta: dict[str, Any] = row.metadata_json or {}
    progress: dict[str, Any] = row.progress or {}
    counts: dict[str, Any] = progress.get("finding_counts") or {}

    status = _normalise_status(row.status)
    verdict = _compute_verdict(status, counts)
    blocker_count = int(counts.get("critical") or 0)
    warn_count = int(counts.get("high") or 0)

    commit_sha = meta.get("commit_sha") or ""
    repo_id = meta.get("repo_id") or ""
    repo_short = repo_id.split("/", 1)[1] if "/" in repo_id else repo_id

    scanner_types = meta.get("scanner_types") or []

    # started_at is the row's actual run-start time; fall back to submitted_at so
    # queued (not-yet-running) scans still surface with a stable ordering key.
    started_dt: datetime | None = row.started_at
    started_iso: str | None
    if started_dt is not None:
        started_iso = started_dt.isoformat()
    else:
        raw_submitted = meta.get("submitted_at")
        started_iso = raw_submitted if isinstance(raw_submitted, str) else None

    finished_iso: str | None = (
        row.finished_at.isoformat() if row.finished_at is not None else None
    )

    return ReleaseRow(
        scan_id=row.id,
        repo_id=repo_id,
        repo=repo_short,
        ref=meta.get("ref"),
        commit_sha=commit_sha,
        short_sha=commit_sha[:7],
        verdict=verdict,
        blocker_count=blocker_count,
        warn_count=warn_count,
        scanner_count=len(scanner_types) if isinstance(scanner_types, list) else 0,
        status=status,
        started_at=started_iso,
        finished_at=finished_iso,
        triggered_by=_triggered_by(meta),
    )


def _normalise_filters(filters: ReleaseListFilters) -> ReleaseListFilters:
    status: str | None = None
    if filters.status:
        status = filters.status.lower()
        if status not in _VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")

    verdict: str | None = None
    if filters.verdict:
        verdict = filters.verdict.lower()
        if verdict not in _VALID_VERDICTS:
            raise ValueError(f"invalid verdict: {verdict}")

    return ReleaseListFilters(
        asset_ids=filters.asset_ids,
        repo_id=filters.repo_id or None,
        status=status,
        verdict=verdict,
        limit=filters.limit,
        cursor=filters.cursor,
    )


def _cursor_predicate(payload: dict[str, Any]):
    """Resume keyset pagination after the cursor's (started_at, id) pair.

    Ordering is `started_at DESC NULLS LAST, id DESC`. NULL `started_at` rows
    (queued scans whose runner hasn't picked them up yet) sit at the tail of
    the list, so a cursor with `started_at=None` resumes inside that tail and
    only compares on `id`.
    """
    last_id = payload.get("id")
    if last_id is None:
        return None

    last_ts = payload.get("started_at")
    if last_ts is None:
        return and_(ScanRun.started_at.is_(None), ScanRun.id < last_id)

    try:
        last_dt = datetime.fromisoformat(last_ts)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid cursor") from exc

    # Either we're still in the non-NULL block (started_at strictly older, or
    # tied and id smaller), or we've moved past it into the NULL tail.
    return or_(
        ScanRun.started_at < last_dt,
        and_(ScanRun.started_at == last_dt, ScanRun.id < last_id),
        ScanRun.started_at.is_(None),
    )


async def list_releases(
    raw_filters: ReleaseListFilters,
    session: AsyncSession,
) -> dict[str, Any]:
    """Return paginated pre-release scans scoped to the caller's accessible assets."""
    filters = _normalise_filters(raw_filters)

    if not filters.asset_ids:
        return {"releases": [], "next_cursor": None}

    where = [
        ScanRun.tool == "pre_release",
        ScanRun.asset_id.in_(filters.asset_ids),
    ]
    if filters.status:
        # Reverse the public status onto the raw DB enum so the SQL filter
        # is honest about what we're matching on disk.
        raw_matches = [
            raw for raw, public in _STATUS_NORMALISE.items() if public == filters.status
        ]
        where.append(ScanRun.status.in_(raw_matches))
    if filters.repo_id:
        # metadata_json is JSONB; the `->>` operator returns the value as text.
        where.append(ScanRun.metadata_json["repo_id"].astext == filters.repo_id)

    base_where = and_(*where)

    page_where = base_where
    if filters.cursor:
        payload = _decode_cursor(filters.cursor)
        cursor_clause = _cursor_predicate(payload)
        if cursor_clause is not None:
            page_where = and_(base_where, cursor_clause)

    stmt = (
        select(ScanRun)
        .where(page_where)
        .order_by(nulls_last(ScanRun.started_at.desc()), ScanRun.id.desc())
        .limit(filters.limit + 1)
    )
    result = await session.execute(stmt)
    rows = list(result.scalars().all())

    has_more = len(rows) > filters.limit
    page_rows = rows[: filters.limit]

    # Verdict is computed in Python from progress JSON; filtering in SQL would
    # require duplicating the precedence logic and miss the status-derived
    # pending/unknown verdicts. Filter post-query — the trade-off is that a
    # verdict-filtered page can come back partial (callers must follow the
    # cursor to continue) which is fine for V1 per the plan's perf carve-out.
    release_rows = [_row_from_scan(r) for r in page_rows]
    if filters.verdict:
        release_rows = [r for r in release_rows if r.verdict == filters.verdict]

    next_cursor: str | None = None
    if has_more and page_rows:
        last_raw = page_rows[-1]
        ts = last_raw.started_at.isoformat() if last_raw.started_at else None
        next_cursor = _encode_cursor({"started_at": ts, "id": last_raw.id})

    return {
        "releases": [r.__dict__ for r in release_rows],
        "next_cursor": next_cursor,
    }


# ── Release Detail ────────────────────────────────────────────────────────────


@dataclass
class BlockerDiffRowData:
    finding_id: int
    diff_status: str
    severity: str
    title: str
    file_path: str | None
    cve_id: str | None
    cwe_id: str | None
    scanner: str
    first_seen_at: str
    introduced_by_commit_sha: str | None
    is_kev: bool
    epss_score: float | None


@dataclass
class ReleaseDetailRow:
    summary: ReleaseRow
    baseline_scan_id: str | None
    baseline_ref: str | None
    baseline_taken_at: str | None
    scanners_run: list[str]
    blockers_diff: list[BlockerDiffRowData]
    improvements: list[BlockerDiffRowData]


def _baseline_ref(baseline: ScanRun) -> str:
    meta: dict[str, Any] = baseline.metadata_json or {}
    sha = meta.get("commit_sha") or ""
    short = sha[:7]
    ref = meta.get("ref") or "main"
    return f"{ref}@{short}" if short else ref


def _first_cwe(detail: dict[str, Any] | None) -> str | None:
    # v1 approximation: Finding.detail["cwe"] is a list (scanners emit 0..N CWEs).
    # We surface the first id so the response model stays single-valued.
    if not detail:
        return None
    cwes = detail.get("cwe")
    if isinstance(cwes, list) and cwes:
        first = cwes[0]
        return str(first) if first else None
    if isinstance(cwes, str) and cwes:
        return cwes
    return None


def _scanner_of(finding: Finding) -> str:
    # `engine` is the normalized scanner name (e.g. "trivy", "semgrep"); `tool`
    # is the finding type ("dependencies", "sast"). Engine is the right label
    # for the UI but is nullable on older rows — fall back to tool.
    # why: surface missing scanner identity instead of an invisible empty string
    # so the regression is visible to operators rather than hidden in the UI.
    return finding.engine or finding.tool or "unknown"


def _build_diff_row(
    finding: Finding,
    diff_status: str,
    kev_set: set[str],
    epss_lookup: dict[str, float],
) -> BlockerDiffRowData:
    cve_id = finding.cve_id
    # why: both KEV (CISA feed contract) and EPSS (fetcher uppercases on ingest)
    # publish CVE ids in uppercase, so .upper() is the safe shared join key.
    is_kev = bool(cve_id and cve_id.upper() in kev_set)
    epss_score = epss_lookup.get(cve_id.upper()) if cve_id else None
    return BlockerDiffRowData(
        finding_id=finding.id,
        diff_status=diff_status,
        severity=(finding.severity or "").lower(),
        title=finding.title or "",
        file_path=finding.file_path,
        cve_id=cve_id,
        cwe_id=_first_cwe(finding.detail),
        scanner=_scanner_of(finding),
        first_seen_at=finding.first_seen_at.isoformat() if finding.first_seen_at else "",
        introduced_by_commit_sha=finding.introduced_by_commit_sha,
        is_kev=is_kev,
        epss_score=epss_score,
    )


async def _lookup_kev_epss(
    session: AsyncSession,
    cve_ids: set[str],
) -> tuple[set[str], dict[str, float]]:
    """Batch KEV/EPSS lookups for the diff's CVE set.

    Returns (kev_set, epss_lookup) keyed by uppercase CVE so the diff row
    builder doesn't need to issue per-row queries.
    """
    if not cve_ids:
        return set(), {}
    normalised = {c.upper() for c in cve_ids if c}
    if not normalised:
        return set(), {}

    kev_rows = await session.execute(
        select(KevEntry.cve_id).where(KevEntry.cve_id.in_(normalised))
    )
    kev_set = {r[0] for r in kev_rows.fetchall()}

    epss_rows = await session.execute(
        select(EpssScore.cve, EpssScore.score).where(EpssScore.cve.in_(normalised))
    )
    epss_lookup = {r[0]: r[1] for r in epss_rows.fetchall()}

    return kev_set, epss_lookup


async def _find_baseline(
    target: ScanRun,
    session: AsyncSession,
) -> ScanRun | None:
    """Most recent completed pre_release scan on `main` for the same repo+org.

    Strictly older than the target's started_at and not the target itself; if
    target.started_at is NULL, no baseline can exist (we need an ordering key).
    """
    if target.started_at is None:
        return None

    target_meta: dict[str, Any] = target.metadata_json or {}
    target_repo_id = target_meta.get("repo_id")
    if not target_repo_id:
        return None

    stmt = (
        select(ScanRun)
        .where(
            ScanRun.tool == "pre_release",
            ScanRun.asset_id == target.asset_id,
            ScanRun.status == "completed",
            ScanRun.id != target.id,
            ScanRun.started_at < target.started_at,
            ScanRun.metadata_json["repo_id"].astext == target_repo_id,
            ScanRun.metadata_json["ref"].astext == "main",
        )
        .order_by(ScanRun.started_at.desc(), ScanRun.id.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def _compute_blocker_diff(
    target: ScanRun,
    baseline: ScanRun | None,
    session: AsyncSession,
) -> tuple[list[BlockerDiffRowData], list[BlockerDiffRowData]]:
    """Return (blockers_diff, improvements) for the target scan.

    blockers_diff covers currently-open criticals (new + persisted) plus
    criticals that disappeared from the open set without being marked fixed
    (gone). improvements are criticals that were open at baseline time and
    have since been closed (fixed).

    V1 carve-out: "in baseline" is approximated by `first_seen_at <= baseline.started_at`
    on the current Finding row — we have no temporal snapshot table.
    """
    target_meta: dict[str, Any] = target.metadata_json or {}
    repo = target_meta.get("repo_id")
    if not repo:
        return [], []

    asset_id = target.asset_id
    if not asset_id:
        return [], []

    # why: V1 uses live open-critical state for the target side; a release rerun
    # some time after the scan reflects today's posture rather than the
    # scan-finish snapshot. Acceptable for V1; revisit when ScanRun→Findings
    # temporal linking lands.
    current_stmt = select(Finding).where(
        Finding.asset_id == asset_id,
        Finding.severity == "critical",
        Finding.state == "open",
    )
    current_findings = list((await session.execute(current_stmt)).scalars().all())
    # why: Finding has UNIQUE(tool, asset_id, identity_key); two scanners can share
    # an identity_key, so key by (tool, identity_key) to avoid silently dropping
    # one of them in the diff.
    current_by_key: dict[tuple[str, str], Finding] = {
        (f.tool, f.identity_key): f for f in current_findings
    }

    baseline_critical_keys: set[tuple[str, str]] = set()
    baseline_findings_by_key: dict[tuple[str, str], Finding] = {}
    if baseline is not None and baseline.started_at is not None:
        # Baseline set: criticals (any state today) that existed at or before
        # baseline.started_at. Closed-after-baseline rows still belong here so
        # the "fixed" bucket can pick them up.
        baseline_stmt = select(Finding).where(
            Finding.asset_id == asset_id,
            Finding.severity == "critical",
            Finding.first_seen_at <= baseline.started_at,
        )
        baseline_rows = list((await session.execute(baseline_stmt)).scalars().all())
        for row in baseline_rows:
            # Exclude rows that were already fixed before the baseline ran —
            # they weren't a blocker at baseline time.
            if row.fixed_at is not None and row.fixed_at <= baseline.started_at:
                continue
            key = (row.tool, row.identity_key)
            baseline_findings_by_key[key] = row
            baseline_critical_keys.add(key)

    # Build CVE set for batch KEV/EPSS lookup across every finding we may emit.
    cve_ids: set[str] = set()
    for f in current_findings:
        if f.cve_id:
            cve_ids.add(f.cve_id)
    for f in baseline_findings_by_key.values():
        if f.cve_id:
            cve_ids.add(f.cve_id)

    kev_set, epss_lookup = await _lookup_kev_epss(session, cve_ids)

    blockers: list[BlockerDiffRowData] = []
    improvements: list[BlockerDiffRowData] = []

    # new + persisted: walk the target's current criticals.
    for key, finding in current_by_key.items():
        status = "persisted" if key in baseline_critical_keys else "new"
        blockers.append(_build_diff_row(finding, status, kev_set, epss_lookup))

    # gone + fixed: rows that were critical at baseline but aren't open-critical now.
    for key, baseline_finding in baseline_findings_by_key.items():
        if key in current_by_key:
            continue  # already accounted for as persisted
        # Resolve current state from the live Finding row.
        live_state = (baseline_finding.state or "").lower()
        # why: only `fixed` counts as an improvement. `dismissed`/`deferred` are
        # explicit user decisions not to fix — they're not blockers for this
        # release, but they aren't security wins either, so they stay in
        # blockers_diff as `gone`.
        if live_state == "fixed":
            improvements.append(
                _build_diff_row(baseline_finding, "fixed", kev_set, epss_lookup)
            )
        else:
            blockers.append(
                _build_diff_row(baseline_finding, "gone", kev_set, epss_lookup)
            )

    return blockers, improvements


async def get_release(
    scan_id: str,
    asset_ids: list[str],
    session: AsyncSession,
) -> ReleaseDetailRow | None:
    """Fetch a single release with its blocker diff against the prior baseline.

    Returns None if the scan is missing or sits outside the caller's accessible
    assets — the router maps both to 404 so access boundaries don't leak via
    the response code.
    """
    if not asset_ids:
        return None
    target = (await session.execute(
        select(ScanRun).where(
            ScanRun.id == scan_id,
            ScanRun.asset_id.in_(asset_ids),
            ScanRun.tool == "pre_release",
        )
    )).scalar_one_or_none()
    if target is None:
        return None

    summary = _row_from_scan(target)

    baseline = await _find_baseline(target, session)
    blockers, improvements = await _compute_blocker_diff(target, baseline, session)

    meta: dict[str, Any] = target.metadata_json or {}
    scanners_run = meta.get("scanner_types") or []
    if not isinstance(scanners_run, list):
        scanners_run = []

    baseline_scan_id = baseline.id if baseline is not None else None
    baseline_ref = _baseline_ref(baseline) if baseline is not None else None
    baseline_taken_at = (
        baseline.started_at.isoformat()
        if baseline is not None and baseline.started_at is not None
        else None
    )

    return ReleaseDetailRow(
        summary=summary,
        baseline_scan_id=baseline_scan_id,
        baseline_ref=baseline_ref,
        baseline_taken_at=baseline_taken_at,
        scanners_run=list(scanners_run),
        blockers_diff=blockers,
        improvements=improvements,
    )
