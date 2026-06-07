"""Unit tests for the rules repo subject loader."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import Repo, ScanRun
from src.rules.repo_subject_loader import load_repo_subject


_ORG = "org-loader-a"
_REPO = "repo-1"


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(delete(ScanRun))
        await session.execute(delete(Repo))

    run_db(_del)
    yield
    run_db(_del)


def _seed_repo(
    *,
    org: str = _ORG,
    repo: str = _REPO,
    tier: str | None = "production",
    archived: bool = False,
    labels: list[str] | None = None,
    image_registry: str | None = "ghcr.io",
) -> int:
    async def _insert(session):
        r = Repo(
            org=org,
            repo=repo,
            tier=tier,
            archived=archived,
            labels=labels,
            image_registry=image_registry,
        )
        session.add(r)
        await session.flush()
        return r.id

    return run_db(_insert)


def _seed_scan_run(
    *,
    scan_id: str,
    tool: str,
    org: str = _ORG,
    status: str = "completed",
    finished_at: datetime | None = None,
) -> None:
    async def _insert(session):
        session.add(ScanRun(
            id=scan_id,
            tool=tool,
            org=org,
            status=status,
            finished_at=finished_at,
        ))

    run_db(_insert)


def _load(repo_id: int, *, now: datetime | None = None):
    snapshot_now = now if now is not None else datetime.now(timezone.utc)

    async def _run(session):
        repo_row = await session.get(Repo, repo_id)
        return await load_repo_subject(repo_row, session, now=snapshot_now)

    return run_db(_run)


def test_load_repo_subject_populates_all_fields_from_repo():
    repo_id = _seed_repo(
        tier="production",
        labels=["foo"],
        archived=False,
        image_registry="ghcr.io",
    )
    now = datetime.now(timezone.utc)
    ts_deps = now - timedelta(hours=2)
    ts_secrets = now - timedelta(hours=1)
    _seed_scan_run(scan_id="sr-deps", tool="dependencies", finished_at=ts_deps)
    _seed_scan_run(scan_id="sr-secrets", tool="secrets", finished_at=ts_secrets)

    subject = _load(repo_id, now=now)

    assert subject.repo_id == f"{_ORG}/{_REPO}"
    assert subject.repo_labels == ["foo"]
    assert subject.tier == "production"
    assert subject.archived is False
    assert subject.image_registry == "ghcr.io"
    # Ordering matches _SCANNER_TYPES ordering (dependencies before secrets).
    assert subject.scanners_with_coverage == ["dependencies", "secrets"]
    assert subject.last_scanned_at is not None
    assert abs((subject.last_scanned_at - ts_secrets).total_seconds()) < 1
    # Last scan was an hour ago — fewer than 1 day, so .days == 0.
    assert subject.last_scan_age_days == 0


def test_load_repo_subject_no_scans():
    repo_id = _seed_repo()

    subject = _load(repo_id)

    assert subject.scanners_with_coverage == []
    assert subject.last_scanned_at is None
    assert subject.last_scan_age_days is None


def test_load_repo_subject_archived_repo():
    repo_id = _seed_repo(archived=True)

    subject = _load(repo_id)

    assert subject.archived is True


def test_load_repo_subject_ignores_failed_scans():
    repo_id = _seed_repo()
    _seed_scan_run(
        scan_id="sr-failed",
        tool="dependencies",
        status="failed",
        finished_at=datetime.now(timezone.utc),
    )
    _seed_scan_run(
        scan_id="sr-running",
        tool="code_scanning",
        status="running",
        finished_at=None,
    )

    subject = _load(repo_id)

    assert subject.scanners_with_coverage == []
    assert subject.last_scanned_at is None
    assert subject.last_scan_age_days is None


def test_load_repo_subject_last_scan_age_days_computed_from_now():
    repo_id = _seed_repo()
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    ts = now - timedelta(days=10, hours=3)
    _seed_scan_run(scan_id="sr-deps", tool="dependencies", finished_at=ts)

    subject = _load(repo_id, now=now)

    assert subject.last_scan_age_days == 10
