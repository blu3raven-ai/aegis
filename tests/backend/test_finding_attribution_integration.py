"""Integration tests: new findings get attribution fields set when checkout is available.

Relies on the testcontainers Postgres fixture from conftest.py (_create_tables).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.git_attribution import CommitAttribution
from src.shared.lifecycle import ScanContext, apply_lifecycle, LifecycleHooks


class MinimalHooks(LifecycleHooks):
    """Minimal hooks for SAST-like findings with file/line location."""

    tool = "code_scanning"

    def compute_identity_key(self, raw: dict) -> str:
        return f"{raw.get('repo', '')}:{raw.get('file_path', '')}:{raw.get('line', 0)}"

    def initial_state(self, raw: dict) -> str:
        return "open"

    def extract_repo(self, raw: dict) -> str | None:
        return raw.get("repo")

    def extract_severity(self, raw: dict) -> str | None:
        return raw.get("severity", "medium")

    def extract_detail(self, raw: dict) -> dict:
        return {"filePath": raw.get("file_path", ""), "startLine": raw.get("line", 0)}

    def extract_file_location(self, raw: dict) -> tuple[str, int] | None:
        fp = raw.get("file_path", "")
        ln = raw.get("line", 0)
        if fp and ln:
            return fp, int(ln)
        return None


FAKE_ATTR = CommitAttribution(
    commit_sha="deadbeefdeadbeefdeadbeefdeadbeef00000001",
    author_email="dev@acme-org.example",
    author_name="Dev User",
    authored_at=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
    pr_url="https://github.com/acme-org/example-repo/pull/99",
)


def _clean_org(org: str) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == "code_scanning", Finding.org == org)
        )
    run_db(_del)


def _fetch_finding(org: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(Finding.tool == "code_scanning", Finding.org == org)
        )
        return result.scalars().first()
    return run_db(_q)


def test_attribution_set_on_new_finding():
    """When checkout_path is provided and blame succeeds, fields are set on insert."""
    org = "acme-org-attr-1"
    _clean_org(org)

    hooks = MinimalHooks()
    ctx = ScanContext(
        tool="code_scanning",
        org=org,
        run_id="run-001",
        checkout_path=Path("/fake/checkout"),
    )
    raw = {"repo": f"{org}/api", "file_path": "src/main.py", "line": 42, "severity": "high"}

    with patch("src.shared.lifecycle.attribute_to_commit", return_value=FAKE_ATTR):
        new_findings = apply_lifecycle(hooks, ctx, [raw])

    assert len(new_findings) == 1
    finding = _fetch_finding(org)
    assert finding is not None
    assert finding.introduced_by_commit_sha == "deadbeefdeadbeefdeadbeefdeadbeef00000001"
    assert finding.introduced_by_author == "dev@acme-org.example"
    assert finding.introduced_at is not None
    assert finding.introduced_by_pr_url == "https://github.com/acme-org/example-repo/pull/99"


def test_attribution_null_when_no_checkout():
    """Without checkout_path, attribution fields stay NULL."""
    org = "acme-org-attr-2"
    _clean_org(org)

    hooks = MinimalHooks()
    ctx = ScanContext(tool="code_scanning", org=org, run_id="run-002")
    raw = {"repo": f"{org}/svc", "file_path": "app.py", "line": 10, "severity": "low"}

    new_findings = apply_lifecycle(hooks, ctx, [raw])
    assert len(new_findings) == 1

    finding = _fetch_finding(org)
    assert finding is not None
    assert finding.introduced_by_commit_sha is None
    assert finding.introduced_by_author is None
    assert finding.introduced_at is None
    assert finding.introduced_by_pr_url is None


def test_attribution_null_when_blame_fails():
    """When blame subprocess fails, attribution stays NULL and scan succeeds."""
    org = "acme-org-attr-3"
    _clean_org(org)

    hooks = MinimalHooks()
    ctx = ScanContext(
        tool="code_scanning",
        org=org,
        run_id="run-003",
        checkout_path=Path("/fake/checkout"),
    )
    raw = {"repo": f"{org}/app", "file_path": "src/util.py", "line": 5, "severity": "medium"}

    with patch("src.shared.lifecycle.attribute_to_commit", return_value=None):
        new_findings = apply_lifecycle(hooks, ctx, [raw])

    assert len(new_findings) == 1
    finding = _fetch_finding(org)
    assert finding is not None
    assert finding.introduced_by_commit_sha is None


def test_attribution_not_overwritten_on_resurface():
    """Attribution is only set on first insert — resurface does not overwrite it."""
    org = "acme-org-attr-4"
    _clean_org(org)

    hooks = MinimalHooks()
    raw = {"repo": f"{org}/svc", "file_path": "main.py", "line": 1, "severity": "high"}

    # First scan: blame succeeds
    ctx1 = ScanContext(
        tool="code_scanning", org=org, run_id="run-004a",
        checkout_path=Path("/fake/checkout"),
    )
    with patch("src.shared.lifecycle.attribute_to_commit", return_value=FAKE_ATTR):
        apply_lifecycle(hooks, ctx1, [raw])

    # Mark finding as fixed so next scan resurfaces it
    async def _mark_fixed(session):
        result = await session.execute(
            select(Finding).where(Finding.tool == "code_scanning", Finding.org == org)
        )
        f = result.scalars().first()
        if f:
            f.state = "fixed"
    run_db(_mark_fixed)

    # Second scan: resurface — blame returns a DIFFERENT sha
    different_attr = CommitAttribution(
        commit_sha="cafebabecafebabecafebabecafebabe00000002",
        author_email="other@acme-org.example",
        author_name="Other User",
        authored_at=datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    ctx2 = ScanContext(
        tool="code_scanning", org=org, run_id="run-004b",
        checkout_path=Path("/fake/checkout"),
    )
    with patch("src.shared.lifecycle.attribute_to_commit", return_value=different_attr):
        apply_lifecycle(hooks, ctx2, [raw])

    finding = _fetch_finding(org)
    # Original attribution preserved — resurface goes through the `prev` branch which
    # does not call upsert_finding, so introduced_by_* columns are unchanged.
    assert finding.introduced_by_commit_sha == FAKE_ATTR.commit_sha
