"""Unit tests for the cross-scanner findings aggregation service.

Uses a fake AsyncSession so the tests run without Postgres. The fake session
exercises the filter, sort, cursor, and pagination logic by recording the
SQL it would have run and feeding back canned Finding rows.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import pytest

from src.db.models import Finding
from src.shared.finding_queryable_fields import extract_queryable_fields
from src.findings.service import (
    DEFAULT_LIMIT,
    FIXED_WINDOW_DAYS,
    MAX_LIMIT,
    MAX_Q_LENGTH,
    FindingsListFilters,
    _build_where_clauses,
    _decode_cursor,
    _encode_cursor,
    _finding_to_dict,
    _normalize_filters,
    list_findings,
    summarize_findings,
)


# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


def _make_finding(
    id: int = 1,
    tool: str = "dependencies",
    severity: str = "high",
    state: str = "open",
    org: str = "acme-org",
    repo: str = "acme-org/api",
    detail: dict | None = None,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> Finding:
    f = Finding()
    f.id = id
    f.tool = tool
    f.org = org
    f.identity_key = f"key-{id}"
    f.severity = severity
    f.state = state
    f.repo = repo
    f.detail = detail if detail is not None else {"title": f"Finding {id}", "cve_id": "CVE-2026-0001"}
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f.created_at = created_at or base + timedelta(days=id)
    f.updated_at = updated_at or base + timedelta(days=id)
    f.first_seen_at = base
    f.last_seen_at = base
    qf = extract_queryable_fields(f.detail or {})
    f.cve_id = qf["cve_id"]
    f.file_path = qf["file_path"]
    f.title = qf["title"]
    f.rule_name = qf["rule_name"]
    f.package_name = qf["package_name"]
    return f


class _FakeSession:
    """Async session double — returns the same Finding list for every page query.

    The service runs two queries per call: a COUNT(*) then the actual page.
    The fake distinguishes them by checking whether the statement has a LIMIT.
    """

    def __init__(self, findings: list[Finding]):
        self._findings = findings

    async def execute(self, stmt):
        compiled = str(stmt)
        result = MagicMock()
        if "count(" in compiled.lower():
            result.scalar.return_value = len(self._findings)
            return result
        # Page query — return the list as scalars.
        scalars = MagicMock()
        scalars.all.return_value = self._findings
        result.scalars.return_value = scalars
        return result


# ---------------------------------------------------------------------------
# Filter normalisation
# ---------------------------------------------------------------------------


def test_normalize_requires_org_id():
    with pytest.raises(ValueError, match="org_id"):
        _normalize_filters(FindingsListFilters(org_id=""))


def test_normalize_caps_limit_to_max():
    out = _normalize_filters(FindingsListFilters(org_id="acme", limit=10_000))
    assert out.limit == MAX_LIMIT


def test_normalize_defaults_limit_when_zero():
    out = _normalize_filters(FindingsListFilters(org_id="acme", limit=0))
    assert out.limit == DEFAULT_LIMIT


def test_normalize_truncates_q_to_max_length():
    long_q = "a" * (MAX_Q_LENGTH + 50)
    out = _normalize_filters(FindingsListFilters(org_id="acme", q=long_q))
    assert len(out.q) == MAX_Q_LENGTH


def test_normalize_rejects_invalid_severity():
    with pytest.raises(ValueError, match="severity"):
        _normalize_filters(FindingsListFilters(org_id="acme", severity=["nope"]))


def test_normalize_rejects_invalid_scanner():
    with pytest.raises(ValueError, match="scanner"):
        _normalize_filters(FindingsListFilters(org_id="acme", scanner=["iac"]))


def test_normalize_rejects_invalid_sort():
    with pytest.raises(ValueError, match="sort"):
        _normalize_filters(FindingsListFilters(org_id="acme", sort="bogus"))


def test_normalize_lowercases_severity():
    out = _normalize_filters(FindingsListFilters(org_id="acme", severity=["CRITICAL"]))
    assert out.severity == ["critical"]


# ---------------------------------------------------------------------------
# Where-clause construction
# ---------------------------------------------------------------------------


def test_where_clauses_always_includes_org_id():
    clauses = _build_where_clauses(FindingsListFilters(org_id="acme"))
    assert len(clauses) == 1  # just the org_id


def test_where_clauses_adds_one_per_filter():
    clauses = _build_where_clauses(
        FindingsListFilters(
            org_id="acme",
            severity=["critical"],
            scanner=["deps"],
            state=["open"],
            q="log4j",
            cve="CVE-2021-44228",
            repo="acme/api",
        )
    )
    # org + severity + scanner + state + cve + repo + q = 7
    assert len(clauses) == 7


def test_where_clauses_adds_repo_equality_when_only_repo_set():
    clauses = _build_where_clauses(FindingsListFilters(org_id="acme", repo="acme/api"))
    # org + repo = 2
    assert len(clauses) == 2


def test_normalize_strips_and_caps_repo():
    out = _normalize_filters(
        FindingsListFilters(org_id="acme", repo="  acme/api  ")
    )
    assert out.repo == "acme/api"

    long_repo = "x" * 600
    out = _normalize_filters(FindingsListFilters(org_id="acme", repo=long_repo))
    assert out.repo is not None and len(out.repo) <= 255


def test_normalize_treats_empty_repo_as_none():
    out = _normalize_filters(FindingsListFilters(org_id="acme", repo="   "))
    assert out.repo is None


# ---------------------------------------------------------------------------
# Cursor encoding round-trip
# ---------------------------------------------------------------------------


def test_cursor_round_trip():
    payload = {"rank": 4, "id": 12345}
    encoded = _encode_cursor(payload)
    decoded = _decode_cursor(encoded)
    assert decoded == payload


def test_cursor_decode_rejects_malformed():
    with pytest.raises(ValueError):
        _decode_cursor("not-a-real-cursor!!!")


# ---------------------------------------------------------------------------
# Public-shape serialisation
# ---------------------------------------------------------------------------


def test_finding_to_dict_dependencies_shape():
    f = _make_finding(
        id=42,
        tool="dependencies",
        severity="CRITICAL",
        detail={
            "title": "log4j RCE",
            "cve_id": "CVE-2021-44228",
            "package_name": "log4j",
            "package_version": "2.14.0",
        },
    )
    row = _finding_to_dict(f)
    assert row["id"] == "42"
    assert row["scanner"] == "deps"  # dependencies → deps shorthand
    assert row["severity"] == "critical"  # lowercased
    assert row["cve"] == "CVE-2021-44228"
    assert row["package"] == "log4j@2.14.0"
    assert row["file_path"] is None  # deps finding has no file_path


def test_finding_to_dict_sast_shape():
    f = _make_finding(
        id=7,
        tool="code_scanning",
        severity="high",
        detail={"title": "SQLi", "file_path": "app/views.py", "start_line": 42},
    )
    row = _finding_to_dict(f)
    assert row["scanner"] == "sast"
    assert row["file_path"] == "app/views.py"
    assert row["line"] == 42
    assert row["package"] is None


def test_finding_to_dict_secrets_shape():
    f = _make_finding(
        id=9,
        tool="secrets",
        severity="critical",
        detail={"title": "AWS key in config", "path": "config/prod.env", "line": 10},
    )
    row = _finding_to_dict(f)
    assert row["scanner"] == "secrets"
    assert row["file_path"] == "config/prod.env"
    assert row["line"] == 10


def test_finding_to_dict_container_shape():
    f = _make_finding(
        id=3,
        tool="container_scanning",
        severity="medium",
        detail={"package_name": "alpine", "package_version": "3.18", "cve": "CVE-2023-1234"},
    )
    row = _finding_to_dict(f)
    assert row["scanner"] == "container"
    assert row["package"] == "alpine@3.18"
    assert row["cve"] == "CVE-2023-1234"


def test_finding_to_dict_falls_back_to_identity_key_for_title():
    f = _make_finding(id=1, detail={})
    row = _finding_to_dict(f)
    assert row["title"] == "key-1"


# ---------------------------------------------------------------------------
# list_findings — page mechanics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_findings_empty_state():
    session = _FakeSession([])
    out = await list_findings(FindingsListFilters(org_id="acme-org"), session)
    assert out["findings"] == []
    assert out["next_cursor"] is None
    assert out["total_count"] == 0


@pytest.mark.asyncio
async def test_list_findings_single_scanner():
    findings = [_make_finding(id=i, tool="dependencies") for i in range(3)]
    session = _FakeSession(findings)
    out = await list_findings(FindingsListFilters(org_id="acme-org"), session)
    assert len(out["findings"]) == 3
    assert all(row["scanner"] == "deps" for row in out["findings"])
    assert out["total_count"] == 3
    assert out["next_cursor"] is None


@pytest.mark.asyncio
async def test_list_findings_multi_scanner_merge():
    findings = [
        _make_finding(id=1, tool="dependencies"),
        _make_finding(id=2, tool="container_scanning"),
        _make_finding(id=3, tool="code_scanning"),
        _make_finding(id=4, tool="secrets"),
    ]
    session = _FakeSession(findings)
    out = await list_findings(FindingsListFilters(org_id="acme-org"), session)
    scanners = {row["scanner"] for row in out["findings"]}
    assert scanners == {"deps", "container", "sast", "secrets"}


@pytest.mark.asyncio
async def test_list_findings_emits_next_cursor_when_more_rows():
    # 6 rows, limit 5 → next_cursor should be set
    findings = [_make_finding(id=i, severity="high") for i in range(6)]
    session = _FakeSession(findings)
    out = await list_findings(
        FindingsListFilters(org_id="acme-org", limit=5),
        session,
    )
    assert len(out["findings"]) == 5
    assert out["next_cursor"] is not None
    # Cursor should be decodable
    payload = _decode_cursor(out["next_cursor"])
    assert "id" in payload


@pytest.mark.asyncio
async def test_list_findings_no_cursor_when_exact_page():
    # 5 rows, limit 5 → no extra row, no next_cursor
    findings = [_make_finding(id=i) for i in range(5)]
    session = _FakeSession(findings)
    out = await list_findings(
        FindingsListFilters(org_id="acme-org", limit=5),
        session,
    )
    assert len(out["findings"]) == 5
    assert out["next_cursor"] is None


@pytest.mark.asyncio
async def test_list_findings_invalid_cursor_raises():
    session = _FakeSession([])
    with pytest.raises(ValueError, match="invalid cursor"):
        await list_findings(
            FindingsListFilters(org_id="acme-org", cursor="garbage"),
            session,
        )


@pytest.mark.asyncio
async def test_list_findings_invalid_severity_raises():
    session = _FakeSession([])
    with pytest.raises(ValueError):
        await list_findings(
            FindingsListFilters(org_id="acme-org", severity=["plaid"]),
            session,
        )


# ---------------------------------------------------------------------------
# Sort sanity — we can't observe ORDER BY against the fake session, but we
# can confirm the service builds a query without raising for each sort key.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("sort", ["severity", "created_at", "updated_at"])
async def test_list_findings_accepts_all_sort_keys(sort):
    session = _FakeSession([_make_finding(id=1)])
    out = await list_findings(
        FindingsListFilters(org_id="acme-org", sort=sort),
        session,
    )
    assert out["total_count"] == 1


@pytest.mark.asyncio
async def test_list_findings_severity_cursor_encodes_rank():
    findings = [_make_finding(id=i, severity="critical") for i in range(6)]
    session = _FakeSession(findings)
    out = await list_findings(
        FindingsListFilters(org_id="acme-org", limit=5, sort="severity"),
        session,
    )
    payload = _decode_cursor(out["next_cursor"])
    assert payload["rank"] == 4  # critical
    assert payload["id"] == 4  # the 5th row (id=4) is the last in the page


@pytest.mark.asyncio
async def test_list_findings_created_at_cursor_encodes_ts():
    findings = [_make_finding(id=i) for i in range(6)]
    session = _FakeSession(findings)
    out = await list_findings(
        FindingsListFilters(org_id="acme-org", limit=5, sort="created_at"),
        session,
    )
    payload = _decode_cursor(out["next_cursor"])
    assert "ts" in payload
    assert payload["id"] == 4


# ---------------------------------------------------------------------------
# summarize_findings
# ---------------------------------------------------------------------------


class _FakeSummarySession:
    """Async session double for summarize_findings — returns one labelled row."""

    def __init__(self, counts: dict[str, int]):
        self._counts = counts

    async def execute(self, stmt):  # noqa: ARG002 — stmt shape isn't asserted here
        result = MagicMock()
        row = MagicMock()
        for key, value in self._counts.items():
            setattr(row, key, value)
        result.one.return_value = row
        return result


@pytest.mark.asyncio
async def test_summarize_findings_returns_all_buckets():
    session = _FakeSummarySession(
        {
            "open": 87,
            "critical": 7,
            "high": 23,
            "medium": 38,
            "low": 19,
            "fixed_recent": 47,
            "dismissed": 14,
        }
    )
    out = await summarize_findings(org_id="acme-org", session=session)
    assert out == {
        "open": 87,
        "critical": 7,
        "high": 23,
        "medium": 38,
        "low": 19,
        "fixed_recent": 47,
        "dismissed": 14,
        "fixed_window_days": FIXED_WINDOW_DAYS,
    }


@pytest.mark.asyncio
async def test_summarize_findings_coerces_none_to_zero():
    # COUNT(*) FILTER can return NULL when nothing matches on some Postgres setups.
    session = _FakeSummarySession(
        {
            "open": None,
            "critical": None,
            "high": None,
            "medium": None,
            "low": None,
            "fixed_recent": None,
            "dismissed": None,
        }
    )
    out = await summarize_findings(org_id="acme-org", session=session)
    assert out["open"] == 0
    assert out["critical"] == 0
    assert out["dismissed"] == 0
    assert out["fixed_window_days"] == FIXED_WINDOW_DAYS
