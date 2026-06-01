"""Unit tests for the Go/No-Go decision service.

Exercises the heuristic without Postgres — a fake AsyncSession returns
canned Finding rows so we can verify the verdict, blocker list, and
rationale text for each branch.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.db.models import Finding
from src.decisions.service import (
    DEFAULT_BLOCK_ON,
    DecisionPolicy,
    DecisionService,
    parse_policy,
)


# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


def _make_finding(
    id: int = 1,
    tool: str = "dependencies",
    severity: str = "critical",
    state: str = "open",
    org: str = "acme-org",
    repo: str = "acme-org/api",
    detail: dict | None = None,
) -> Finding:
    f = Finding()
    f.id = id
    f.tool = tool
    f.org = org
    f.repo = repo
    f.identity_key = f"key-{id}"
    f.severity = severity
    f.state = state
    f.detail = detail if detail is not None else {"title": f"Finding {id}", "cve_id": "CVE-2026-0001"}
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f.created_at = base
    f.updated_at = base
    f.first_seen_at = base
    f.last_seen_at = base
    return f


class _FakeSession:
    """Returns the same list of Finding rows for every select() executed."""

    def __init__(self, findings: list[Finding]):
        self._findings = findings

    async def execute(self, _stmt):
        result = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = self._findings
        result.scalars.return_value = scalars
        return result


# ---------------------------------------------------------------------------
# parse_policy
# ---------------------------------------------------------------------------


def test_parse_policy_none_returns_default():
    policy = parse_policy(None)
    assert policy.block_on == DEFAULT_BLOCK_ON


def test_parse_policy_accepts_explicit_block_on_list():
    policy = parse_policy({"block_on": ["critical", "high"]})
    assert policy.block_on == ("critical", "high")


def test_parse_policy_accepts_single_string():
    policy = parse_policy({"block_on": "high"})
    assert policy.block_on == ("high",)


def test_parse_policy_lowercases_severities():
    policy = parse_policy({"block_on": ["CRITICAL", "High"]})
    assert policy.block_on == ("critical", "high")


def test_parse_policy_rejects_non_dict():
    with pytest.raises(ValueError, match="policy"):
        parse_policy([1, 2, 3])  # type: ignore[arg-type]


def test_parse_policy_rejects_invalid_severity():
    with pytest.raises(ValueError, match="invalid severity"):
        parse_policy({"block_on": ["bogus"]})


def test_parse_policy_rejects_non_string_entry():
    with pytest.raises(ValueError, match="strings"):
        parse_policy({"block_on": [42]})


def test_parse_policy_rejects_non_list_block_on():
    with pytest.raises(ValueError, match="must be a list"):
        parse_policy({"block_on": {"x": "y"}})


def test_parse_policy_falls_back_to_default_when_block_on_empty():
    policy = parse_policy({"block_on": []})
    assert policy.block_on == DEFAULT_BLOCK_ON


# ---------------------------------------------------------------------------
# DecisionService.evaluate — verdict logic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_requires_org_id():
    service = DecisionService()
    with pytest.raises(ValueError, match="org_id"):
        await service.evaluate(
            org_id="",
            repo=None,
            policy=DecisionPolicy(),
            session=_FakeSession([]),
        )


@pytest.mark.asyncio
async def test_evaluate_allow_when_no_findings():
    service = DecisionService()
    out = await service.evaluate(
        org_id="acme-org",
        repo=None,
        policy=DecisionPolicy(),
        session=_FakeSession([]),
    )
    assert out["decision"] == "allow"
    assert out["blockers"] == []
    assert out["source"] == "backend"
    assert "critical" in out["rationale"].lower()


@pytest.mark.asyncio
async def test_evaluate_block_when_critical_finding_present():
    service = DecisionService()
    out = await service.evaluate(
        org_id="acme-org",
        repo=None,
        policy=DecisionPolicy(),
        session=_FakeSession([_make_finding(id=1, severity="critical")]),
    )
    assert out["decision"] == "block"
    assert len(out["blockers"]) == 1
    blocker = out["blockers"][0]
    assert blocker["id"] == "1"
    assert blocker["severity"] == "critical"
    assert blocker["title"] == "Finding 1"


@pytest.mark.asyncio
async def test_evaluate_block_when_high_finding_and_policy_includes_high():
    service = DecisionService()
    out = await service.evaluate(
        org_id="acme-org",
        repo=None,
        policy=DecisionPolicy(block_on=("critical", "high")),
        session=_FakeSession([_make_finding(id=1, severity="high")]),
    )
    assert out["decision"] == "block"


@pytest.mark.asyncio
async def test_evaluate_rationale_lists_blocking_severities():
    service = DecisionService()
    out = await service.evaluate(
        org_id="acme-org",
        repo=None,
        policy=DecisionPolicy(block_on=("critical", "high")),
        session=_FakeSession([]),
    )
    assert "critical" in out["rationale"]
    assert "high" in out["rationale"]


# ---------------------------------------------------------------------------
# Blocker serialisation — public shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_blocker_falls_back_to_identity_key_for_title():
    service = DecisionService()
    out = await service.evaluate(
        org_id="acme-org",
        repo=None,
        policy=DecisionPolicy(),
        session=_FakeSession([_make_finding(id=99, severity="critical", detail={})]),
    )
    assert out["blockers"][0]["title"] == "key-99"


@pytest.mark.asyncio
async def test_evaluate_blocker_includes_cve_alias():
    service = DecisionService()
    findings = [
        _make_finding(
            id=1,
            severity="critical",
            detail={"title": "container CVE", "cve": "CVE-2024-9999"},
        )
    ]
    out = await service.evaluate(
        org_id="acme-org",
        repo=None,
        policy=DecisionPolicy(),
        session=_FakeSession(findings),
    )
    assert out["blockers"][0]["cve"] == "CVE-2024-9999"


# ---------------------------------------------------------------------------
# Cross-org isolation — runs against the real testcontainers Postgres so the
# per-org WHERE clause in service.py is exercised end-to-end. The _FakeSession
# above ignores SQL filters, so isolation has to be verified by a real DB
# round-trip; otherwise a regression in the org filter would slip through.
#
# Uses src.db.helpers.run_db (same pattern as test_correlation_state.py and
# test_finding_attribution_integration.py) so the test stays on the single
# background event loop that owns the engine's connection pool — this avoids
# the asyncpg "another operation is in progress" cross-loop error that the
# session-scoped engine triggers when called from pytest-asyncio's per-test
# loop.
# ---------------------------------------------------------------------------


_ISO_ORG_A = "iso-test-org-a"
_ISO_ORG_B = "iso-test-org-b"


def _seed_cross_org_findings():
    from sqlalchemy import delete as sa_delete
    from src.db.helpers import run_db

    async def _seed(session):
        await session.execute(
            sa_delete(Finding).where(Finding.org.in_([_ISO_ORG_A, _ISO_ORG_B]))
        )
        session.add(
            Finding(
                tool="dependencies",
                org=_ISO_ORG_A,
                repo=f"{_ISO_ORG_A}/api",
                identity_key="iso-a-critical",
                state="open",
                severity="critical",
                detail={"title": "org-a critical", "cve_id": "CVE-2099-AAAA"},
            )
        )
        session.add(
            Finding(
                tool="code_scanning",
                org=_ISO_ORG_B,
                repo=f"{_ISO_ORG_B}/web",
                identity_key="iso-b-critical",
                state="open",
                severity="critical",
                detail={"title": "org-b critical", "cve_id": "CVE-2099-BBBB"},
            )
        )
        session.add(
            Finding(
                tool="container_scanning",
                org=_ISO_ORG_B,
                repo=f"{_ISO_ORG_B}/web",
                identity_key="iso-b-high",
                state="open",
                severity="high",
                detail={"title": "org-b high"},
            )
        )
        await session.flush()

    run_db(_seed)


def _cleanup_isolation_rows():
    from sqlalchemy import delete as sa_delete
    from src.db.helpers import run_db

    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.org.in_([_ISO_ORG_A, _ISO_ORG_B]))
        )

    run_db(_del)


def _evaluate_against_db(org_id: str, policy: DecisionPolicy) -> dict:
    """Run DecisionService.evaluate against the real testcontainers session."""
    from src.db.helpers import run_db

    service = DecisionService()

    async def _eval(session):
        return await service.evaluate(
            org_id=org_id,
            repo=None,
            policy=policy,
            session=session,
        )

    return run_db(_eval)


def test_evaluate_isolates_blockers_per_org_against_real_db():
    """Blockers returned for org_a must never include org_b's findings."""
    _cleanup_isolation_rows()
    try:
        _seed_cross_org_findings()
        policy = DecisionPolicy(block_on=("critical", "high"))

        out_a = _evaluate_against_db(_ISO_ORG_A, policy)
        out_b = _evaluate_against_db(_ISO_ORG_B, policy)

        # org_a sees only its own single critical — never org_b's two findings.
        assert out_a["decision"] == "block"
        a_keys = {b["identity_key"] for b in out_a["blockers"]}
        assert a_keys == {"iso-a-critical"}
        assert all(b["repo"].startswith(_ISO_ORG_A) for b in out_a["blockers"])

        # org_b sees its own two findings — never org_a's.
        assert out_b["decision"] == "block"
        b_keys = {b["identity_key"] for b in out_b["blockers"]}
        assert b_keys == {"iso-b-critical", "iso-b-high"}
        assert all(b["repo"].startswith(_ISO_ORG_B) for b in out_b["blockers"])

        # Belt-and-braces: no identity-key overlap between the two verdicts.
        assert a_keys.isdisjoint(b_keys)
    finally:
        _cleanup_isolation_rows()


def test_evaluate_unknown_org_returns_allow_even_with_other_org_findings():
    """A bogus org_id must never inherit another org's blockers."""
    _cleanup_isolation_rows()
    try:
        _seed_cross_org_findings()
        out = _evaluate_against_db(
            "iso-test-org-nonexistent",
            DecisionPolicy(block_on=("critical", "high")),
        )
        assert out["decision"] == "allow"
        assert out["blockers"] == []
    finally:
        _cleanup_isolation_rows()
