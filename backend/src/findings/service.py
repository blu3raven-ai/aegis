"""Cross-scanner findings aggregation."""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import and_, false as sa_false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, EpssScore, Finding, KevEntry, User
from src.findings.action_band import ACT, ATTEND, TRACK, action_band, band_ordinal
from src.shared.finding_detail_blob import hydrate_detail
from src.shared.archived_filter import exclude_archived, only_archived

# Internal tool name (DB) -> public scanner shorthand (API surface).
# Public shorthand matches the CLI/UI vocabulary; the DB uses the longer form
# that the per-scanner ingest paths write.
_TOOL_TO_PUBLIC = {
    "dependencies_scanning": "deps",
    "container_scanning": "container",
    "code_scanning": "sast",
    "secret_scanning": "secrets",
    "iac_scanning": "iac",
    "agent_scanning": "agent",
    "deep_audit": "audit",
}
_PUBLIC_TO_TOOL = {v: k for k, v in _TOOL_TO_PUBLIC.items()}

# Accept either vocabulary on the scanner filter — the public shorthand
# (deps/sast/...) or the internal tool name (dependencies_scanning/...) — and
# resolve both to the internal tool for the query. The UI sends the long form,
# so rejecting it returned an empty/errored findings list.
_SCANNER_INPUT_TO_TOOL = {**_PUBLIC_TO_TOOL, **{t: t for t in _TOOL_TO_PUBLIC}}

VALID_SCANNERS = frozenset(_SCANNER_INPUT_TO_TOOL.keys())
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_STATES = frozenset({"open", "closed", "dismissed", "fixed", "deferred"})

# Concrete verdict values stored in Finding.verdict.
VALID_VERDICTS = frozenset({"confirmed", "needs_verify", "possible", "ruled_out"})

# Accepted ?verdict= filter values. "legacy" matches verdict IS NULL
# (findings ingested before LLM verification ran); "all" disables the filter.
_VALID_VERDICT_FILTERS = VALID_VERDICTS | frozenset({"legacy", "all"})
VALID_SORTS = frozenset(
    {"severity", "severity_age", "epss", "risk_score", "action_band", "newest", "oldest", "created_at", "updated_at"}
)

# Sorts paginated by page number (offset), not keyset cursor. They never emit a
# next_cursor, and _cursor_predicate must not build a keyset clause for them — a
# stray/stale cursor under one of these would otherwise key on the wrong column.
_DEFERRED_CURSOR_SORTS = frozenset(
    {"severity_age", "epss", "risk_score", "action_band", "newest", "oldest"}
)

# Ordering value used to sort severities — higher = more severe.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Server-side cap so a malicious or buggy client can't exhaust memory.
MAX_LIMIT = 200
DEFAULT_LIMIT = 50

# Cap free-text search length so an attacker can't force expensive ILIKE scans.
MAX_Q_LENGTH = 200


@dataclass
class FindingsListFilters:
    org_id: str
    asset_ids: list[str] = field(default_factory=list)
    severity: list[str] | None = None
    scanner: list[str] | None = None
    state: list[str] | None = None
    q: str | None = None
    cve: str | None = None
    # Repo scope: each value an Asset.display_name (e.g. "github:acme/foo").
    # The findings-page dropdown sends one; the per-source view sends the
    # source's repositories. Matched with IN.
    repo: list[str] | None = None
    sort: str = "severity"
    direction: str = "desc"
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None
    # Two-state archived view: None/False → hide archived (default user-facing
    # behaviour), True → show ONLY archived rows for archive-review surfaces.
    # There is intentionally no "include both" mode here — compliance flows
    # belong in the reports endpoint via include_archived=True.
    archived: bool | None = None
    first_seen_after: datetime | None = None
    cwe: str | None = None
    kev: bool | None = None
    epss_min: float | None = None
    risk_score_min: int | None = None
    # Additive categorical filter: subset of {"act","attend","track"}. Composes
    # with risk_score_min; both stay on the dataclass during the Phase C overlap.
    bands: list[str] | None = None
    assignee_user_id: str | None = None
    page: int = 1
    # None defaults to hiding ruled_out; "all" disables the filter entirely.
    verdict: str | None = None


def _normalize_filters(filters: FindingsListFilters) -> FindingsListFilters:
    """Apply caps and lowercase normalisation. Raises ValueError on invalid input."""
    if not filters.asset_ids and not filters.org_id:
        raise ValueError("org_id is required")

    severity = None
    if filters.severity:
        severity = [s.lower() for s in filters.severity if s]
        bad = [s for s in severity if s not in VALID_SEVERITIES]
        if bad:
            raise ValueError(f"invalid severity: {bad}")

    scanner = None
    if filters.scanner:
        scanner = [s.lower() for s in filters.scanner if s]
        bad = [s for s in scanner if s not in VALID_SCANNERS]
        if bad:
            raise ValueError(f"invalid scanner: {bad}")

    state = None
    if filters.state:
        state = [s.lower() for s in filters.state if s]
        bad = [s for s in state if s not in VALID_STATES]
        if bad:
            raise ValueError(f"invalid state: {bad}")

    sort = (filters.sort or "severity").lower()
    if sort not in VALID_SORTS:
        raise ValueError(f"invalid sort: {sort}")

    direction = (filters.direction or "desc").lower()
    if direction not in ("asc", "desc"):
        raise ValueError(f"invalid direction: {direction}")

    limit = filters.limit if filters.limit and filters.limit > 0 else DEFAULT_LIMIT
    limit = min(limit, MAX_LIMIT)

    q: str | None = None
    if filters.q:
        q = filters.q.strip()[:MAX_Q_LENGTH] or None

    cve: str | None = None
    if filters.cve:
        cve = filters.cve.strip()[:64] or None

    # Cap each value (display_name length) and the count so the IN list stays
    # bounded regardless of how many repos a source has.
    repo: list[str] | None = None
    if filters.repo:
        repo = [r.strip()[:255] for r in filters.repo if r and r.strip()][:500] or None

    first_seen_after = filters.first_seen_after  # caller passes a real datetime or None

    cwe = filters.cwe.strip().upper()[:32] if filters.cwe else None
    kev = bool(filters.kev) if filters.kev is not None else None
    epss_min = min(max(float(filters.epss_min), 0.0), 1.0) if filters.epss_min is not None else None
    risk_score_min = (
        min(max(int(filters.risk_score_min), 0), 100) if filters.risk_score_min is not None else None
    )

    bands: list[str] | None = None
    if filters.bands:
        bands = [b.lower() for b in filters.bands if b]
        bad = [b for b in bands if b not in (ACT, ATTEND, TRACK)]
        if bad:
            raise ValueError(f"invalid band: {bad}")

    assignee_user_id: str | None = None
    if filters.assignee_user_id:
        assignee_user_id = filters.assignee_user_id.strip()[:255] or None

    page = max(1, int(filters.page or 1))

    verdict: str | None = None
    if filters.verdict:
        v = filters.verdict.strip().lower()
        if v not in _VALID_VERDICT_FILTERS:
            raise ValueError(f"invalid verdict: {filters.verdict!r}")
        verdict = v

    return FindingsListFilters(
        org_id=filters.org_id,
        asset_ids=list(filters.asset_ids) if filters.asset_ids else [],
        severity=severity,
        scanner=scanner,
        state=state,
        q=q,
        cve=cve,
        repo=repo,
        sort=sort,
        direction=direction,
        limit=limit,
        cursor=filters.cursor,
        archived=filters.archived,
        first_seen_after=first_seen_after,
        cwe=cwe,
        kev=kev,
        epss_min=epss_min,
        risk_score_min=risk_score_min,
        bands=bands,
        assignee_user_id=assignee_user_id,
        page=page,
        verdict=verdict,
    )


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


def _band_ordinal_sql():
    """SQL CASE mirroring action_band() -> band ordinal (act=3/attend=2/track=1).
    Kept in sync with findings.action_band (parity-tested)."""
    from sqlalchemy import case
    is_kev = Finding.cve_id.in_(select(KevEntry.cve_id))
    is_high = func.lower(Finding.severity).in_(("critical", "high"))
    is_reachable = Finding.detail["reachability"].astext == "reachable"
    return case(
        (and_(is_kev, is_high), 3),
        (is_kev, 2),
        (and_(is_reachable, is_high), 2),
        else_=1,
    )


def _severity_rank_expr():
    """SQL CASE mapping the severity string to an ordinal (critical=4 … low=1,
    unknown=0) so ORDER BY / keyset comparisons use severity precedence rather
    than the lexicographic order of the string."""
    from sqlalchemy import case
    return case(
        (func.lower(Finding.severity) == "critical", 4),
        (func.lower(Finding.severity) == "high", 3),
        (func.lower(Finding.severity) == "medium", 2),
        (func.lower(Finding.severity) == "low", 1),
        else_=0,
    )


def _sort_columns(sort: str, direction: str):
    """Return the list of ORDER BY columns for the given sort + direction.

    Always tie-breaks on `Finding.id` so cursor pagination is deterministic
    when the primary sort key has duplicates.
    """
    desc = direction == "desc"
    if sort == "severity_age":
        rank_expr = _severity_rank_expr()
        return [
            rank_expr.desc() if desc else rank_expr.asc(),
            Finding.first_seen_at.desc() if desc else Finding.first_seen_at.asc(),
            Finding.id.desc() if desc else Finding.id.asc(),
        ]
    if sort == "newest":
        return [Finding.first_seen_at.desc(), Finding.id.desc()]
    if sort == "oldest":
        return [Finding.first_seen_at.asc(), Finding.id.asc()]
    if sort == "risk_score":
        # NULLs land at the end regardless of direction so unscored rows don't
        # crowd the top of a "Risk score (high to low)" view.
        primary = (
            Finding.risk_score.desc().nullslast()
            if desc
            else Finding.risk_score.asc().nullslast()
        )
        return [primary, Finding.id.desc() if desc else Finding.id.asc()]
    if sort == "action_band":
        band = _band_ordinal_sql()
        sev_rank = _severity_rank_expr()
        primary = band.desc() if desc else band.asc()
        secondary = sev_rank.desc() if desc else sev_rank.asc()
        # Transparent tiebreak: band, then severity rank, then id. EPSS is
        # intentionally NOT a tiebreak here — it would force a join and EPSS is
        # never an input to the band decision.
        return [primary, secondary, Finding.id.desc() if desc else Finding.id.asc()]
    if sort == "severity":
        # Sort by severity rank — Postgres CASE expression so we can use the
        # ordinal rather than the lexicographic order of the severity string.
        rank_expr = _severity_rank_expr()
        primary = rank_expr.desc() if desc else rank_expr.asc()
        secondary = Finding.id.desc() if desc else Finding.id.asc()
        return [primary, secondary]
    if sort == "created_at":
        primary = Finding.created_at.desc() if desc else Finding.created_at.asc()
        secondary = Finding.id.desc() if desc else Finding.id.asc()
        return [primary, secondary]
    # updated_at
    primary = Finding.updated_at.desc() if desc else Finding.updated_at.asc()
    secondary = Finding.id.desc() if desc else Finding.id.asc()
    return [primary, secondary]


def _cursor_predicate(cursor_payload: dict[str, Any], sort: str, direction: str):
    """Build the WHERE clause that resumes a paginated query after a cursor.

    Keyset pagination — selects rows strictly after the cursor's (sort_value, id)
    according to the sort direction. Comparing only on `id` would be wrong when
    the sort column has ties.
    """
    last_id = cursor_payload.get("id")
    if last_id is None:
        return None

    # Page-number sorts never mint a cursor; a stray/stale one must not inject a
    # keyset clause keyed on the wrong column. Fail closed to no predicate.
    if sort in _DEFERRED_CURSOR_SORTS:
        return None

    if sort == "severity":
        last_rank = cursor_payload.get("rank")
        if last_rank is None:
            return None
        rank_expr = _severity_rank_expr()
        if direction == "desc":
            return or_(
                rank_expr < last_rank,
                and_(rank_expr == last_rank, Finding.id < last_id),
            )
        return or_(
            rank_expr > last_rank,
            and_(rank_expr == last_rank, Finding.id > last_id),
        )

    last_ts = cursor_payload.get("ts")
    if last_ts is None:
        return None
    last_dt = datetime.fromisoformat(last_ts) if isinstance(last_ts, str) else last_ts
    col = Finding.created_at if sort == "created_at" else Finding.updated_at
    if direction == "desc":
        return or_(col < last_dt, and_(col == last_dt, Finding.id < last_id))
    return or_(col > last_dt, and_(col == last_dt, Finding.id > last_id))


def _build_next_cursor(last: Finding, sort: str) -> str:
    if sort == "severity":
        rank = _SEVERITY_RANK.get((last.severity or "").lower(), 0)
        return _encode_cursor({"rank": rank, "id": last.id})
    if sort == "created_at":
        ts = last.created_at.isoformat() if last.created_at else None
        return _encode_cursor({"ts": ts, "id": last.id})
    ts = last.updated_at.isoformat() if last.updated_at else None
    return _encode_cursor({"ts": ts, "id": last.id})


def _build_where_clauses(filters: FindingsListFilters) -> list:
    # Prefer asset-scoped filter; without asset_ids, return no results (fail-closed).
    if filters.asset_ids:
        clauses: list = [Finding.asset_id.in_(filters.asset_ids)]
    else:
        # Fail closed when no asset scope is provided.
        clauses = [sa_false()]
    if filters.severity:
        clauses.append(func.lower(Finding.severity).in_(filters.severity))
    if filters.verdict is None:
        clauses.append(
            or_(Finding.verdict.is_(None), Finding.verdict != "ruled_out")
        )
    elif filters.verdict == "legacy":
        clauses.append(Finding.verdict.is_(None))
    elif filters.verdict in VALID_VERDICTS:
        clauses.append(Finding.verdict == filters.verdict)
    if filters.scanner:
        internal_tools = [_SCANNER_INPUT_TO_TOOL[s] for s in filters.scanner]
        clauses.append(Finding.tool.in_(internal_tools))
    if filters.state:
        clauses.append(Finding.state.in_(filters.state))
    if filters.cve:
        cve_upper = filters.cve.upper()
        clauses.append(Finding.cve_id == cve_upper)
    if filters.repo:
        # Each value is an Asset.display_name (e.g. "github:acme/foo"): one from
        # the findings dropdown, or many for the per-source scope.
        clauses.append(
            Finding.asset_id.in_(
                select(Asset.id).where(Asset.display_name.in_(filters.repo))
            )
        )
    if filters.first_seen_after:
        clauses.append(Finding.first_seen_at >= filters.first_seen_after)
    if filters.q:
        like = f"%{filters.q}%"
        clauses.append(
            or_(
                Finding.identity_key.ilike(like),
                Finding.title.ilike(like),
                Finding.rule_name.ilike(like),
                Finding.package_name.ilike(like),
                Finding.file_path.ilike(like),
                Finding.cve_id.ilike(like),
            )
        )

    if filters.kev is True:
        kev_subq = select(KevEntry.cve_id)
        clauses.append(Finding.cve_id.in_(kev_subq))

    if filters.cwe:
        # JSONB array containment: KevEntry.cwes @> [filters.cwe]
        cwe_subq = select(KevEntry.cve_id).where(KevEntry.cwes.contains([filters.cwe]))
        clauses.append(Finding.cve_id.in_(cwe_subq))

    if filters.risk_score_min is not None:
        clauses.append(Finding.risk_score >= filters.risk_score_min)

    if filters.bands:
        clauses.append(_band_ordinal_sql().in_([band_ordinal(b) for b in filters.bands]))

    if filters.assignee_user_id:
        clauses.append(Finding.assignee_user_id == filters.assignee_user_id)

    return clauses


class _KevLookup(Protocol):
    def is_kev(self, cve: str | None) -> bool: ...
    def first_cwe(self, cve: str | None) -> str | None: ...


class _NoKev:
    """No-KEV lookup — used when a query doesn't preload KEV state. Returns all-false."""
    def is_kev(self, cve: str | None) -> bool:
        return False
    def first_cwe(self, cve: str | None) -> str | None:
        return None


def _secret_type_label(detail: dict) -> str | None:
    """Human-facing secret type from the scanner's detector name, or None.

    Secret findings hash the matched value into the identity key, so without
    a real title the public response would leak that hash. The detector
    (e.g. "AWS", "github-pat") is the useful triage signal instead.
    """
    detector = (detail.get("detector") or "").strip()
    if not detector:
        return None
    label = detector.replace("-", " ").replace("_", " ").strip()
    lowered = label.lower()
    if any(word in lowered for word in ("secret", "token", "key", "credential", "password")):
        return label
    return f"{label} secret"


def _secret_verified(detail: dict) -> bool | None:
    """Whether the scanner confirmed the secret is a *live* credential.

    The scanner classification is the source of truth — a live credential is
    recorded as a ``verified_secret`` (vs ``uncertain``) classification entry at
    ingest; fall back to the raw ``Verified`` flag. Returns None when the
    detector can't validate (so the UI shows "unverified", not "inactive").
    """
    for entry in detail.get("classificationHistory") or []:
        if isinstance(entry, dict) and entry.get("source") == "scanner":
            value = entry.get("value")
            if value == "verified_secret":
                return True
            if value == "uncertain":
                return False
    raw = detail.get("raw") or {}
    if isinstance(raw, dict) and "Verified" in raw:
        return bool(raw["Verified"])
    return None


# Mirrors runner extract_context.CONTEXT_RADIUS. Used only as a backwards-compat
# fallback to anchor windows stored before the runner emitted a start line; new
# scans carry code_window_start_line directly.
_CONTEXT_RADIUS = 40

# Mirrors the runner secrets-normalizer redaction marker. Every detected secret
# in a code window is masked to this before storage.
_SECRET_REDACTION = "•••redacted-secret•••"

# High-confidence credential shapes scrubbed from a secret finding's *context*
# window (defense in depth). The finding's own value is masked precisely from
# raw.Raw/RawV2/Secret/Match; this catches an UNRELATED credential that happens
# to sit on a nearby line of the surrounding code. Deliberately limited to
# unambiguous, well-known prefixes so ordinary config isn't mangled.
_KNOWN_SECRET_PATTERNS = re.compile(
    r"""(?x)
    eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}(?:\.[A-Za-z0-9_=-]+)?  # JWT
  | sk-[A-Za-z0-9_-]{20,}                                            # OpenAI / Stripe secret key
  | AKIA[0-9A-Z]{16}                                                 # AWS access key id
  | gh[pousr]_[A-Za-z0-9]{30,}                                       # GitHub token
  | xox[baprs]-[A-Za-z0-9-]{10,}                                     # Slack token
  | AIza[0-9A-Za-z_-]{35}                                            # Google API key
    """
)


def _scrub_known_secrets(text: str) -> str:
    """Mask well-known credential formats anywhere in a secret context window."""
    return _KNOWN_SECRET_PATTERNS.sub(_SECRET_REDACTION, text)


def _secret_highlight_line(
    window: str,
    win_start: int | None,
    reported_line: int | None,
    secret_values: list[str],
) -> int | None:
    """Absolute file line to highlight for a secret within its code window.

    The scanner's reported line can be off — notably git-history scans, where
    the diff-relative line drifts from the file's current line — but the window
    is anchored to real file lines. So highlight the line that actually holds
    the secret: the redaction marker (the runner masks every detected value) or,
    for older unmasked windows, the raw value. Nearest the reported line wins
    when a window holds several secrets; falls back to the reported line.
    """
    if win_start is None:
        return reported_line
    needles = [v for v in secret_values if v]
    needles.append(_SECRET_REDACTION)
    hits = [
        win_start + i
        for i, text in enumerate(window.split("\n"))
        if any(n in text for n in needles)
    ]
    if not hits:
        return reported_line
    if reported_line is None:
        return hits[0]
    return min(hits, key=lambda ln: abs(ln - reported_line))


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def _container_image(detail: dict) -> dict[str, Any] | None:
    """Image context for a container finding: which image carries the vuln, its
    base OS, digest (for pinning), and layer count. None when no image is known."""
    name = (detail.get("imageName") or "").strip()
    if not name:
        return None
    return {
        "name": name,
        "tag": (detail.get("imageTag") or "").strip() or None,
        "digest": (detail.get("imageDigest") or "").strip() or None,
        "base_os": (detail.get("baseOs") or "").strip() or None,
        "layer_count": _as_int(detail.get("layerCount")),
        # The layer that introduced the vulnerable package (digest + 0-based
        # ordinal), when syft could attribute it. None for OS packages it can't.
        "layer_digest": (detail.get("layerDigest") or "").strip() or None,
        "layer_index": _as_int(detail.get("layerIndex")),
        # Newer registry tags available for this image (opt-in tag listing).
        "newer_tags": [t for t in (detail.get("newerTags") or []) if isinstance(t, str)] or None,
    }


def _code_preview(tool: str, detail: dict) -> dict[str, Any] | None:
    """Client-safe code preview with line anchoring and a highlight range.

    Secrets return only the *redacted* match (never `secretSnippet`, the raw
    value) and no line context. Code findings prefer the surrounding window —
    anchored to its real first line — so the offending line(s) can be shown
    highlighted in context, falling back to the bare matched snippet.
    """
    if tool == "secret_scanning":
        raw = detail.get("raw") or {}
        # Prefer the runner-extracted code window (already redacted of every
        # detected secret) so the secret shows in its file context. Defense in
        # depth: re-mask this finding's own value here before it leaves the API.
        window = (detail.get("code_window") or "").strip("\n")
        # Every field a detector may carry the raw secret in. TruffleHog puts it
        # in Raw/RawV2 for some detectors and Secret/Match for others; masking
        # only Raw/RawV2 left the plaintext value in the window (and the no-window
        # fallback) for the rest. Mask longest-first so a value that contains a
        # shorter one is fully removed. Redacted is the safe display form.
        secret_values = sorted(
            (v for v in (raw.get("Raw"), raw.get("RawV2"), raw.get("Secret"), raw.get("Match")) if v),
            key=len,
            reverse=True,
        )
        if window:
            win_start = _as_int(detail.get("code_window_start_line"))
            line = _as_int(detail.get("line"))
            # Locate the true secret line before re-masking (older windows may
            # still carry the raw value), then re-mask this finding's own value
            # as defense in depth before it leaves the API.
            highlight = _secret_highlight_line(window, win_start, line, secret_values)
            for value in secret_values:
                window = window.replace(value, _SECRET_REDACTION)
            # Scrub any OTHER well-known credential sitting in the surrounding
            # context lines (line anchoring above is unaffected — only text
            # content changes, never line count).
            window = _scrub_known_secrets(window)
            if win_start is not None:
                return {"text": window, "start_line": win_start, "highlight_start": highlight, "highlight_end": highlight}
        # No window: only the pre-redacted display form is safe. Never fall back
        # to Match — for many detectors that IS the raw secret.
        redacted = (raw.get("Redacted") or "").strip()
        if not redacted:
            return None
        return {"text": redacted, "start_line": None, "highlight_start": None, "highlight_end": None}

    # Code, IaC, container, and dependency findings are all file+line+window:
    # prefer the surrounding window (anchored to its real first line) so the
    # offending line(s) show highlighted in context, else the bare snippet. For
    # deps the "line" is the manifest declaration site captured by the runner.
    hl_start = _as_int(detail.get("startLine") or detail.get("start_line"))
    hl_end = _as_int(detail.get("endLine") or detail.get("end_line")) or hl_start

    window = (detail.get("code_window") or "").strip("\n")
    win_start = _as_int(detail.get("code_window_start_line"))
    if window and win_start is None and hl_start is not None:
        win_start = max(1, hl_start - _CONTEXT_RADIUS)
    if window and win_start is not None:
        return {"text": window, "start_line": win_start, "highlight_start": hl_start, "highlight_end": hl_end}

    snippet = (detail.get("snippet") or "").strip("\n")
    if snippet:
        return {"text": snippet, "start_line": hl_start, "highlight_start": hl_start, "highlight_end": hl_end}
    return None


def _first_line(text: str, cap: int = 120) -> str:
    """First line of a message, trimmed and length-capped for use as a title."""
    line = text.strip().split("\n", 1)[0].strip()
    return line[:cap].rstrip()


def _sast_title(finding: Finding, detail: dict) -> str:
    """Readable title for a code-scanning finding.

    The stored Finding.title leaks the clone path + rule id, so prefer the
    scanner's human-written message (the headline a code-scanning alert
    shows), then the rule name, before falling back to the raw title (which the
    frontend trims to a basename).
    """
    message = (detail.get("message") or "").strip()
    if message:
        return _first_line(message)
    rule = (detail.get("ruleName") or detail.get("ruleId") or "").strip()
    if rule and "/workspace/" not in rule:
        return rule
    return finding.title or finding.identity_key


def _detail_cwe(detail: dict) -> str | None:
    """First CWE id carried on the finding detail (SAST/IaC), or None."""
    cwe = detail.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0]).strip() or None
    if isinstance(cwe, str) and cwe.strip():
        return cwe.strip()
    return None


def _patched_version_str(value: object) -> str | None:
    """Extract a plain version string from a patchedVersion value.

    Handles both the plain-string form stored by the normalizers and the dict
    form {"identifier": "..."} present in raw findings before normalization.
    """
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        id_ = value.get("identifier")
        if isinstance(id_, str) and id_:
            return id_
    return None


def _deps_upgrade_fix(finding: Finding, detail: dict) -> dict | None:
    """Synthesize the deterministic upgrade fix for a dependency/container
    finding from the OSV-derived patched version already stored on the finding.
    Returns None when there's no patched version to upgrade to."""
    if finding.tool not in ("dependencies_scanning", "container_scanning"):
        return None
    to_version = _patched_version_str(detail.get("patchedVersion"))
    if not to_version:
        return None
    fix: dict[str, str] = {"toVersion": to_version}
    if finding.package_name:
        fix["packageName"] = finding.package_name
    from_version = detail.get("currentVersion")
    if isinstance(from_version, str) and from_version:
        fix["fromVersion"] = from_version
    return fix


def _finding_to_dict(
    finding: Finding,
    kev_lookup: _KevLookup | None = None,
    epss_lookup: dict[str, float] | None = None,
    repo: str | None = None,
    *,
    hydrate: bool = False,
) -> dict[str, Any]:
    """Serialise a Finding to the public response shape (now including kev + cwe).

    ``hydrate`` merges the fat detail blob from MinIO before serialising — the
    code window, snippet, code flows, and manifest snippet all live there, not
    in the lean JSONB column. The single-finding detail view passes
    ``hydrate=True``; the list path stays lean (one MinIO GET per row would
    defeat the lean/fat split), so it omits those heavy fields by design.
    """
    lookup = kev_lookup or _NoKev()
    detail: dict = (hydrate_detail(finding) if hydrate else finding.detail) or {}

    package = None
    pkg_name = finding.package_name
    pkg_version = detail.get("package_version") or detail.get("current_version")
    if pkg_name:
        package = f"{pkg_name}@{pkg_version}" if pkg_version else pkg_name

    if finding.tool == "code_scanning":
        title = _sast_title(finding, detail)
    elif finding.tool == "secret_scanning":
        title = finding.title or _secret_type_label(detail) or "Detected secret"
    elif pkg_name:
        # Dependencies/container: the stored title and identity_key are an
        # opaque coordinate (pkg::name::ecosystem::advisory). Show the readable
        # "<package> <version>" slug instead; the CVE rides along as the
        # identifier below.
        title = f"{pkg_name} {pkg_version}" if pkg_version else pkg_name
    else:
        title = finding.title or finding.cve_id or finding.identity_key

    line_raw = detail.get("start_line") or detail.get("startLine") or detail.get("line")
    try:
        line = int(line_raw) if line_raw is not None else None
    except (ValueError, TypeError):
        line = None

    # What an analyst needs to triage, beyond the metadata: the scanner's
    # explanation, the rule that fired, the weakness class, and the fix.
    description = (detail.get("message") or "").strip() or None
    rule = (detail.get("ruleName") or detail.get("ruleId") or "").strip() or None
    remediation = (detail.get("fixSuggestion") or "").strip() or None
    confidence = (detail.get("confidence") or "").strip().lower() or None
    cwe = lookup.first_cwe(finding.cve_id) or _detail_cwe(detail)
    preview = _code_preview(finding.tool, detail)

    return {
        "id": str(finding.id),
        "scanner": _TOOL_TO_PUBLIC.get(finding.tool, finding.tool),
        "severity": (finding.severity or "").lower() or None,
        "state": finding.state,
        "title": title,
        "cve": finding.cve_id,
        "package": package,
        "file_path": finding.file_path,
        "line": line,
        # repo/org are no longer columns on Finding (Plan D); the repo is the
        # finding's asset display_name ("owner/repo"), supplied by the caller.
        "repo": repo,
        "org_id": repo.split("/", 1)[0] if repo and "/" in repo else None,
        # Concrete repo web URL (self-hosted hosts); FAT detail, so present on the
        # hydrated drawer path and None on the lean list path. Drives the
        # view-in-repo deep-link for self-hosted SCM instances.
        "repo_html_url": (detail.get("repoHtmlUrl") or "").strip() or None,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
        "kev": lookup.is_kev(finding.cve_id),
        "malicious": bool(finding.malicious),
        "cwe": cwe,
        "description": description,
        "rule": rule,
        "remediation": remediation,
        "confidence": confidence,
        # Secret triage signals: the detector that fired and whether the
        # credential was confirmed live. Both None for non-secret findings.
        "secret_detector": _secret_type_label(detail) if finding.tool == "secret_scanning" else None,
        "secret_verified": _secret_verified(detail) if finding.tool == "secret_scanning" else None,
        # Provenance: the commit that introduced the finding, when the scanner
        # captured it (secrets carry the blame commit). None when unknown.
        "introduced_by_commit": (detail.get("commit") or "").strip() or None,
        # Image context for container findings; None for every other scanner.
        "container_image": (
            _container_image(detail) if finding.tool == "container_scanning" else None
        ),
        "epss_percentile": (epss_lookup or {}).get(finding.cve_id) if finding.cve_id else None,
        "risk_score": finding.risk_score,
        "action_band": action_band(
            finding.severity,
            kev_listed=lookup.is_kev(finding.cve_id),
            reachability=detail.get("reachability"),
        ),
        "assignee_user_id": finding.assignee_user_id,
        "verdict": finding.verdict,
        # LLM-verification reasoning behind the verdict: cited source/sink/gate
        # evidence, the exploit-chain narrative, the runner-derived reachability,
        # and the model/token footer. Promoted typed columns win; reachability
        # lives in the lean detail blob.
        "evidence": finding.evidence,
        "exploit_chain": finding.exploit_chain,
        "verification_metadata": finding.verification_metadata,
        "reachability": detail.get("reachability"),
        "code_snippet": preview["text"] if preview else None,
        "code_snippet_start_line": preview["start_line"] if preview else None,
        "code_highlight_start": preview["highlight_start"] if preview else None,
        "code_highlight_end": preview["highlight_end"] if preview else None,
        # Ordered taint path (source -> sink) for SAST flow findings, when present.
        "code_flows": detail.get("code_flows") or None,
        # Structured fix payload. The promoted typed column wins (runner-emitted
        # fix for secrets/IaC/SAST), then any lean-detail value, then a synthesized
        # upgrade fix from the OSV patched version for deps/container findings.
        "recommended_fix": (
            finding.recommended_fix
            or detail.get("recommended_fix")
            or _deps_upgrade_fix(finding, detail)
        ),
    }


def _advisory_references(raw: Any) -> list[str]:
    """Normalise the stored references (list of {"url": …} dicts or bare
    strings) to a flat list of URLs."""
    out: list[str] = []
    for ref in raw or []:
        if isinstance(ref, dict) and ref.get("url"):
            out.append(ref["url"])
        elif isinstance(ref, str) and ref:
            out.append(ref)
    return out


def finding_advisory(finding: Finding) -> dict[str, Any] | None:
    """Advisory enrichment for a finding's vulnerability, for the drawer's
    Security Brief: the summary/description, severity + CVSS vector, the
    affected → patched version range, references, and dates.

    The deps/container lifecycle flattens the advisory into top-level detail
    keys (``summary``, ``cvssVector``, ``vulnerableVersionRange``, …) and stores
    the heavy ones in the fat blob, so this hydrates from MinIO and reads the
    flat keys. Returns None for findings with no advisory (SAST / secrets / IaC).
    """
    detail = hydrate_detail(finding)
    advisory_id = detail.get("advisoryId") or None
    summary = (detail.get("summary") or "").strip() or None
    cvss_vector = detail.get("cvssVector") or None
    affected = (detail.get("vulnerableVersionRange") or "").strip() or None
    fixed = detail.get("patchedVersion") or None

    # Nothing advisory-shaped → not a vuln finding (or no advisory data).
    if not (advisory_id or summary or cvss_vector or affected):
        return None

    return {
        "advisory_id": advisory_id,
        "cve_id": detail.get("cveId") or finding.cve_id,
        "severity": (finding.severity or "").strip().lower() or None,
        "cvss_vector": cvss_vector,
        "summary": summary,
        "description": (detail.get("description") or "").strip() or None,
        "published_at": detail.get("publishedAt") or None,
        "affected_range": affected,
        "fixed_version": fixed,
        "references": _advisory_references(detail.get("references")),
    }


async def advisory_intel(cve_id: str | None, session: AsyncSession) -> dict[str, Any]:
    """EPSS percentile + KEV status for a CVE, to round out the advisory brief.

    When the CVE is in CISA KEV, ``kev_detail`` carries the regulatory remediation
    deadline (``due_date``), the catalog-add date, and the known-ransomware flag —
    the deadline analysts triage against. None when the CVE isn't listed.
    """
    if not cve_id:
        return {"epss_percentile": None, "kev": False, "kev_detail": None}
    epss = await session.execute(
        select(EpssScore.percentile).where(EpssScore.cve == cve_id)
    )
    kev = await session.execute(
        select(KevEntry.due_date, KevEntry.date_added, KevEntry.known_ransomware_use).where(
            KevEntry.cve_id == cve_id
        )
    )
    percentile = epss.scalar_one_or_none()
    kev_row = kev.first()
    kev_detail = None
    if kev_row is not None:
        due, added, ransomware = kev_row
        kev_detail = {
            "due_date": due.isoformat() if due else None,
            "date_added": added.isoformat() if added else None,
            "known_ransomware": bool(ransomware),
        }
    return {
        "epss_percentile": float(percentile) if percentile is not None else None,
        "kev": kev_detail is not None,
        "kev_detail": kev_detail,
    }


def _related_match(finding: Finding):
    """The 'same vulnerability' predicate for blast-radius queries: prefer the
    CVE, else the package. None when the finding has neither."""
    if finding.cve_id:
        return Finding.cve_id == finding.cve_id
    if finding.package_name:
        return Finding.package_name == finding.package_name
    return None


# Findings in these states no longer "affect" an asset, so they don't count
# toward the blast radius.
_BLAST_INACTIVE_STATES = ("fixed", "dismissed", "closed")


async def count_related_repos(
    finding: Finding, asset_ids: list[str], session: AsyncSession
) -> int:
    """The vuln's blast radius: how many *other* in-scope assets carry an active
    finding that shares this finding's CVE (preferred) or package. Scoped to the
    caller's assets and bounded to non-archived, still-affecting findings."""
    match = _related_match(finding)
    if not asset_ids or match is None:
        return 0

    stmt = (
        select(func.count(func.distinct(Finding.asset_id)))
        .where(Finding.asset_id.in_(asset_ids))
        .where(match)
        .where(Finding.state.notin_(_BLAST_INACTIVE_STATES))
    )
    stmt = exclude_archived(stmt, Finding)
    if finding.asset_id is not None:
        stmt = stmt.where(Finding.asset_id != finding.asset_id)
    result = await session.execute(stmt)
    return int(result.scalar() or 0)


async def base_image_recommendation(
    image_digest: str | None, session: AsyncSession
) -> dict[str, Any] | None:
    """Recommended newer base tag for an image, if one has fewer vulns.

    Reads the cache the opt-in base-image recommendation flow writes. Returns
    None when there's no digest, no cached row, or the row's negative (nothing
    improved on the current image)."""
    if not image_digest:
        return None
    from src.db.models import BaseImageRecommendation

    row = (
        await session.execute(
            select(BaseImageRecommendation).where(
                BaseImageRecommendation.image_digest == image_digest
            )
        )
    ).scalar_one_or_none()
    if row is None or not row.recommended_tag:
        return None
    return {
        "recommended_tag": row.recommended_tag,
        "current_vuln_count": row.current_vuln_count,
        "recommended_vuln_count": row.recommended_vuln_count,
    }


async def layer_concentration(
    finding: Finding, session: AsyncSession
) -> dict[str, Any] | None:
    """Per-image layer concentration for a container finding.

    Groups this image's open container findings by the layer that introduced
    them and returns the single most-affected layer — "layer N accounts for X of
    Y findings on this image" — so a triager can see whether the base image (low
    layers) is the dominant source. Returns None for non-container findings, an
    image with no layer-attributed findings, or an unscoped finding.

    Only findings whose ``layerIndex`` is stored lean are counted, so this
    reflects images scanned since layer attribution became queryable; older
    findings simply don't contribute until rescanned.
    """
    if finding.tool != "container_scanning" or finding.asset_id is None:
        return None

    layer_expr = Finding.detail["layerIndex"].astext
    stmt = (
        select(layer_expr, func.count())
        .where(Finding.asset_id == finding.asset_id)
        .where(Finding.tool == "container_scanning")
        .where(Finding.state == "open")
        .where(layer_expr.isnot(None))
        .group_by(layer_expr)
    )
    rows = (await session.execute(stmt)).all()
    if not rows:
        return None

    total = sum(int(count) for _, count in rows)
    top_layer, top_count = max(rows, key=lambda r: int(r[1]))
    try:
        layer_index = int(top_layer)
    except (TypeError, ValueError):
        return None
    return {
        "layer_index": layer_index,
        "finding_count": int(top_count),
        "total_with_layer": total,
    }


async def list_related_findings(
    finding: Finding, asset_ids: list[str], session: AsyncSession, *, limit: int = 25
) -> list[dict[str, Any]]:
    """Blast-radius drill-down: one representative finding per *other* in-scope
    repo that shares this finding's CVE/package, worst-severity first. Each row
    is enough for the UI to deep-link to that finding."""
    match = _related_match(finding)
    if not asset_ids or match is None:
        return []

    stmt = (
        select(Finding.id, Finding.severity, Finding.state, Asset.display_name)
        .join(Asset, Asset.id == Finding.asset_id)
        .where(Finding.asset_id.in_(asset_ids))
        .where(match)
        .where(Finding.state.notin_(_BLAST_INACTIVE_STATES))
    )
    stmt = exclude_archived(stmt, Finding)
    if finding.asset_id is not None:
        stmt = stmt.where(Finding.asset_id != finding.asset_id)

    # Keep the worst-severity finding per repo so the list reads one-per-repo.
    by_repo: dict[str, tuple[Any, int, str | None, str | None]] = {}
    for fid, severity, state, repo in (await session.execute(stmt)).all():
        if not repo:
            continue
        rank = _SEVERITY_RANK.get((severity or "").lower(), 0)
        if repo not in by_repo or rank > by_repo[repo][1]:
            by_repo[repo] = (fid, rank, (severity or "").lower() or None, state)

    rows = [
        {"finding_id": str(fid), "repo": repo, "severity": sev, "state": state}
        for repo, (fid, _rank, sev, state) in by_repo.items()
    ]
    rows.sort(key=lambda r: -_SEVERITY_RANK.get(r["severity"] or "", 0))
    return rows[:limit]


async def list_findings(
    raw_filters: FindingsListFilters,
    session: AsyncSession,
) -> dict[str, Any]:
    """Return paginated findings + total count for the given filters.

    Cursor pagination: the response includes `next_cursor` when more rows
    exist past the current page. `total_count` is the unpaginated total —
    a separate COUNT(*) query so the UI can display "1–50 of 12,345".
    """
    filters = _normalize_filters(raw_filters)

    where = _build_where_clauses(filters)

    cursor_clause = None
    if filters.cursor:
        payload = _decode_cursor(filters.cursor)
        cursor_clause = _cursor_predicate(payload, filters.sort, filters.direction)

    base_where = and_(*where)

    def _apply_archived_filter(stmt, archived: bool | None):
        if archived is True:
            return only_archived(stmt, Finding)
        return exclude_archived(stmt, Finding)

    count_stmt = select(func.count()).select_from(Finding).where(base_where)
    if filters.epss_min is not None:
        from src.db.models import EpssScore
        count_stmt = (
            count_stmt
            .join(EpssScore, EpssScore.cve == Finding.cve_id)
            .where(EpssScore.percentile >= filters.epss_min)
        )
    count_stmt = _apply_archived_filter(count_stmt, filters.archived)
    count_result = await session.execute(count_stmt)
    total = int(count_result.scalar() or 0)

    page_where = base_where
    if cursor_clause is not None:
        page_where = and_(base_where, cursor_clause)

    epss_join_needed = filters.epss_min is not None

    offset = (filters.page - 1) * filters.limit if not filters.cursor else 0

    if filters.sort == "epss":
        from src.db.models import EpssScore
        page_stmt = (
            select(Finding)
            .outerjoin(EpssScore, EpssScore.cve == Finding.cve_id)
            .where(page_where)
            .order_by(
                EpssScore.percentile.desc().nullslast() if filters.direction == "desc" else EpssScore.percentile.asc().nullsfirst(),
                Finding.id.desc(),
            )
            .offset(offset)
            .limit(filters.limit + 1)
        )
        if filters.epss_min is not None:
            page_stmt = page_stmt.where(EpssScore.percentile >= filters.epss_min)
    elif epss_join_needed:
        from src.db.models import EpssScore
        page_stmt = (
            select(Finding)
            .join(EpssScore, EpssScore.cve == Finding.cve_id)
            .where(page_where)
            .where(EpssScore.percentile >= filters.epss_min)
            .order_by(*_sort_columns(filters.sort, filters.direction))
            .offset(offset)
            .limit(filters.limit + 1)
        )
    else:
        page_stmt = (
            select(Finding)
            .where(page_where)
            .order_by(*_sort_columns(filters.sort, filters.direction))
            .offset(offset)
            .limit(filters.limit + 1)
        )
    page_stmt = _apply_archived_filter(page_stmt, filters.archived)
    page_result = await session.execute(page_stmt)
    rows = list(page_result.scalars().all())

    has_more = len(rows) > filters.limit
    page = rows[: filters.limit]
    next_cursor = _build_next_cursor(page[-1], filters.sort) if has_more and page else None
    if filters.sort in _DEFERRED_CURSOR_SORTS:
        next_cursor = None  # cursor pagination for these sorts is deferred to PR 5 (page-number pagination)
    if not filters.cursor:
        next_cursor = None

    cve_ids = [f.cve_id for f in page if f.cve_id]
    kev_set: set[str] = set()
    kev_cwes: dict[str, list[str]] = {}
    epss_percentiles: dict[str, float] = {}
    if cve_ids:
        kev_result = await session.execute(
            select(KevEntry.cve_id, KevEntry.cwes).where(KevEntry.cve_id.in_(cve_ids))
        )
        for cve, cwes in kev_result.all():
            kev_set.add(cve)
            if isinstance(cwes, list) and cwes:
                kev_cwes[cve] = [str(c) for c in cwes]

        from src.db.models import EpssScore
        epss_result = await session.execute(
            select(EpssScore.cve, EpssScore.percentile).where(EpssScore.cve.in_(cve_ids))
        )
        for cve, percentile in epss_result.all():
            epss_percentiles[cve] = float(percentile)

    class _RealKev:
        def is_kev(self, cve):
            return bool(cve) and cve in kev_set
        def first_cwe(self, cve):
            if not cve:
                return None
            cwes = kev_cwes.get(cve)
            return cwes[0] if cwes else None

    lookup = _RealKev()

    verdict_counts = await _verdict_counts_for_filters(filters, session)

    # Resolve each finding's repo (Asset.display_name) in one query — repo is
    # no longer a Finding column.
    page_asset_ids = {f.asset_id for f in page if f.asset_id}
    repo_by_asset: dict[str, str] = {}
    if page_asset_ids:
        repo_rows = await session.execute(
            select(Asset.id, Asset.display_name).where(Asset.id.in_(page_asset_ids))
        )
        repo_by_asset = {str(aid): name for aid, name in repo_rows.all()}

    return {
        "findings": [
            _finding_to_dict(
                f, kev_lookup=lookup, epss_lookup=epss_percentiles,
                repo=repo_by_asset.get(str(f.asset_id)) if f.asset_id else None,
            )
            for f in page
        ],
        "next_cursor": next_cursor,
        "total_count": total,
        "verdict_counts": verdict_counts,
    }


async def _verdict_counts_for_filters(
    filters: FindingsListFilters,
    session: AsyncSession,
) -> dict[str, int]:
    """Per-verdict counts for the filter set, with the verdict filter itself disabled.

    Keeps chip counts stable as the user toggles between verdicts.
    """
    counts_filters = FindingsListFilters(**{**filters.__dict__, "verdict": "all"})
    where = _build_where_clauses(counts_filters)
    base_where = and_(*where)

    stmt = (
        select(Finding.verdict, func.count())
        .where(base_where)
        .group_by(Finding.verdict)
    )
    stmt = exclude_archived(stmt, Finding) if filters.archived is not True else only_archived(stmt, Finding)
    rows = await session.execute(stmt)

    out = {
        "total": 0,
        "confirmed": 0,
        "needs_verify": 0,
        "possible": 0,
        "ruled_out": 0,
        "legacy": 0,
    }
    for verdict, n in rows.all():
        n_int = int(n or 0)
        out["total"] += n_int
        if verdict is None:
            out["legacy"] += n_int
        elif verdict in out:
            out[verdict] += n_int
    return out


# Number of days the "fixed this week" bucket looks back. Matches the mock's
# "Resolved this week" KPI.
FIXED_WINDOW_DAYS = 7


async def summarize_findings(
    session: AsyncSession,
    *,
    asset_ids: list[str] | None = None,
    org_id: str | None = None,
) -> dict[str, int]:
    """Return cross-scanner KPI counts for the findings page.

    All buckets exclude archived rows. `open_*` counts include only rows in
    state=open; `fixed_recent` counts rows in state=fixed with fixed_at within
    the trailing FIXED_WINDOW_DAYS window; `dismissed` is all non-archived rows
    in state=dismissed regardless of age.

    Callers must supply either asset_ids (preferred, asset-scoped path) or
    org_id (legacy org-scoped path). asset_ids takes precedence.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=FIXED_WINDOW_DAYS)
    sev = func.lower(Finding.severity)
    state = func.lower(Finding.state)

    stmt = select(
        func.count().filter(state == "open").label("open"),
        func.count().filter(and_(state == "open", sev == "critical")).label("critical"),
        func.count().filter(and_(state == "open", sev == "high")).label("high"),
        func.count().filter(and_(state == "open", sev == "medium")).label("medium"),
        func.count().filter(and_(state == "open", sev == "low")).label("low"),
        func.count()
        .filter(and_(state == "fixed", Finding.fixed_at.is_not(None), Finding.fixed_at >= cutoff))
        .label("fixed_recent"),
        func.count().filter(state == "dismissed").label("dismissed"),
    )
    if asset_ids:
        stmt = stmt.where(Finding.asset_id.in_(asset_ids))
    elif org_id:
        # Fail closed when no asset scope is provided.
        stmt = stmt.where(sa_false())
    else:
        raise ValueError("summarize_findings requires asset_ids or org_id")
    stmt = exclude_archived(stmt, Finding)

    row = (await session.execute(stmt)).one()
    return {
        "open": int(row.open or 0),
        "critical": int(row.critical or 0),
        "high": int(row.high or 0),
        "medium": int(row.medium or 0),
        "low": int(row.low or 0),
        "fixed_recent": int(row.fixed_recent or 0),
        "dismissed": int(row.dismissed or 0),
        "fixed_window_days": FIXED_WINDOW_DAYS,
    }


async def assign_finding(
    finding_id: int,
    assignee_user_id: str | None,
    session: AsyncSession,
    asset_ids: list[str],
) -> tuple[Finding, str | None]:
    """Set or clear the assignee on a finding.

    Returns (finding, previous_assignee). Raises LookupError if the finding
    does not exist or its asset is outside the caller's scope (404 path —
    avoids leaking existence). Raises ValueError if assignee_user_id is
    non-empty but references a user that does not exist.
    """
    if assignee_user_id is not None:
        normalized = assignee_user_id.strip()
        if len(normalized) > 255:
            raise ValueError("assignee_user_id exceeds 255 characters")
        assignee_user_id = normalized or None

    finding = (
        await session.execute(select(Finding).where(Finding.id == finding_id))
    ).scalars().first()
    # Secrets findings (asset_id=NULL) have no per-source isolation and are
    # not surfaced through the asset-scoped /findings list, so they are out
    # of scope for assignment too.
    if (
        finding is None
        or not finding.asset_id
        or finding.asset_id not in asset_ids
    ):
        raise LookupError(f"finding {finding_id} not found")

    if assignee_user_id is not None:
        user_id = (
            await session.execute(select(User.id).where(User.id == assignee_user_id))
        ).scalar_one_or_none()
        if user_id is None:
            raise ValueError(f"unknown user: {assignee_user_id}")

    previous = finding.assignee_user_id
    finding.assignee_user_id = assignee_user_id
    finding.updated_at = datetime.now(timezone.utc)
    await session.flush()
    return finding, previous


MAX_ASSIGNABLE_USERS_LIMIT = 50


async def list_assignable_users(
    session: AsyncSession,
    *,
    q: str | None = None,
    limit: int = 20,
    allowed_user_ids: set[str] | None = None,
) -> list[dict[str, str]]:
    """Return up to `limit` active users matching `q` on username or email.

    Trims and lowers `q` before the LIKE pattern build so the caller can pass
    raw input without normalising. Empty/whitespace queries return the first
    `limit` users by username order.

    `allowed_user_ids` scopes the result to co-assignees the caller may see:
    `None` applies no restriction (caller sees every asset), an empty set
    yields no rows (caller has no asset scope), and a populated set restricts
    the query to those ids.
    """
    if allowed_user_ids is not None and not allowed_user_ids:
        return []
    capped_limit = max(1, min(int(limit or 20), MAX_ASSIGNABLE_USERS_LIMIT))
    stmt = select(User.id, User.username).where(User.status == "active")
    if allowed_user_ids is not None:
        stmt = stmt.where(User.id.in_(allowed_user_ids))
    if q:
        normalized = q.strip()
        if normalized:
            like = f"%{normalized}%"
            stmt = stmt.where(or_(User.username.ilike(like), User.email.ilike(like)))
    stmt = stmt.order_by(User.username.asc()).limit(capped_limit)

    rows = (await session.execute(stmt)).all()
    return [
        {"id": row.id, "username": row.username or ""}
        for row in rows
    ]
