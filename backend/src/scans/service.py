"""Pre-release scan service — submits user-triggered scan_runs and reads status."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.db.engine import get_session
from src.db.models import Repo, ScanRun

logger = logging.getLogger(__name__)

_DEFAULT_SCANNERS = ["dependencies", "code_scanning", "container_scanning", "secrets"]

_SCANNER_JOB_TYPES: dict[str, str] = {
    "dependencies":       "dependencies",
    "code_scanning":      "code_scanning",
    "container_scanning": "container_scanning",
    "secrets":            "secrets",
}


def _dispatch_scanner_jobs(
    scan_id: str,
    repo_id: str,
    commit_sha: str,
    scanners: list[str],
    org: str,
) -> None:
    """Create one runner job per scanner type after the ScanRun row is committed."""
    from src.runner.jobs import create_job
    from src.shared.config import get_token_for_org

    token = get_token_for_org(org) or ""
    # V1: assumes GitHub. Extend when GitLab/Bitbucket source connections are supported.
    repo_url = f"https://github.com/{repo_id}"

    for scanner in scanners:
        job_type = _SCANNER_JOB_TYPES.get(scanner)
        if not job_type:
            logger.warning("submit_scan: unknown scanner type %r — skipping", scanner)
            continue

        run_id = f"{scan_id}:{scanner}"
        env: dict[str, str] = {
            "GIT_TOKEN":   token,
            "GIT_REPOS":   repo_url,
            "ORG_LABEL":   org,
            "RUN_ID":      run_id,
            "COMMIT_SHA":  commit_sha,
            "REPO_ID":     repo_id,
            "CONCURRENCY": "4",
        }
        if scanner == "secrets":
            env["SCAN_DEPTH"] = "deep"

        create_job(job_type=job_type, org=org, run_id=run_id, env_vars=env)
        logger.info("Dispatched %s runner job for scan %s (repo %s)", scanner, scan_id, repo_id)


@dataclass
class ScanSubmission:
    scan_id: str
    repo_id: str
    commit_sha: str
    scanner_types: list[str]
    status: str
    submitted_at: datetime
    submitted_by: str


@dataclass
class ScanDetail:
    scan_id: str
    repo_id: str
    commit_sha: str
    scanner_types: list[str]
    status: str
    submitted_at: datetime
    submitted_by: str
    started_at: datetime | None
    finished_at: datetime | None
    finding_counts: dict[str, int] | None
    error: str | None
    # Surfaced so the UI can label archived rows when a deep-link lands on one.
    # The detail endpoint intentionally still returns archived scans (so direct
    # links survive), unlike list endpoints which hide them by default.
    archived: bool = False


def _parse_submitted_at(meta: dict[str, Any]) -> datetime:
    # submit_scan always writes submitted_at; this fallback handles legacy/foreign
    # scan_runs that pre-date this code path (e.g. scheduled scans read by /scans/{id}).
    raw = meta.get("submitted_at")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


async def submit_scan(
    asset_id: str,
    commit_sha: str,
    scanner_types: list[str] | None,
    user_id: str,
) -> ScanSubmission | None:
    """Insert a queued scan_run for a user-triggered pre-release scan.

    Returns None if no Repo row exists for the given asset_id.
    """
    scanners = scanner_types or _DEFAULT_SCANNERS
    scan_id = f"scan-{uuid.uuid4()}"
    submitted_at = datetime.now(timezone.utc)

    async with get_session() as session:
        from src.db.models import Asset
        repo = (await session.execute(
            select(Repo).where(Repo.asset_id == asset_id)
        )).scalar_one_or_none()
        if repo is None:
            return None

        # Derive runner dispatch params from the Asset.external_ref.
        # Format is "github:<owner>/<name>".
        asset_row = (await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one_or_none()
        if asset_row is None:
            return None

        ext_ref = asset_row.external_ref or ""
        # external_ref: "github:owner/name"
        if ":" in ext_ref:
            _, path = ext_ref.split(":", 1)
        else:
            path = ext_ref
        parts = path.split("/", 1)
        owner = parts[0] if parts else ""
        name = parts[1] if len(parts) > 1 else ""
        repo_id = f"{owner}/{name}"
        org = owner  # org_label for runner job dispatch

        metadata = {
            "commit_sha": commit_sha,
            "repo_id": repo_id,
            "org_label": org,
            "scanner_types": scanners,
            "submitted_by": user_id,
            "submitted_at": submitted_at.isoformat(),
            "source": "user",
        }

        # tool="pre_release" identifies this row as a user-triggered scan envelope;
        # produced findings carry their own tool values ("dependencies", etc.) and feed posture.
        row = ScanRun(
            id=scan_id,
            tool="pre_release",
            asset_id=asset_id,
            status="queued",
            started_at=None,
            finished_at=None,
            progress=None,
            error=None,
            metadata_json=metadata,
        )
        session.add(row)
        await session.commit()
        _dispatch_scanner_jobs(scan_id, repo_id, commit_sha, scanners, org)

        return ScanSubmission(
            scan_id=scan_id,
            repo_id=repo_id,
            commit_sha=commit_sha,
            scanner_types=scanners,
            status="queued",
            submitted_at=submitted_at,
            submitted_by=user_id,
        )


async def get_scan(scan_id: str, asset_id: str) -> ScanDetail | None:
    """Read a scan_run, returning None if absent or not associated with the given asset.

    Callers that cannot provide an asset_id (e.g. the /scans/{id} read endpoint
    which resolves auth via org) may pass asset_id=None to skip the asset filter
    and rely solely on the org-level gate already applied at the router.
    """
    async with get_session() as session:
        stmt = select(ScanRun).where(ScanRun.id == scan_id)
        if asset_id:
            stmt = stmt.where(ScanRun.asset_id == asset_id)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return None

        meta: dict[str, Any] = row.metadata_json or {}
        progress: dict[str, Any] = row.progress or {}

        return ScanDetail(
            scan_id=row.id,
            repo_id=meta.get("repo_id", ""),
            commit_sha=meta.get("commit_sha", ""),
            scanner_types=meta.get("scanner_types", []),
            status=row.status,
            submitted_at=_parse_submitted_at(meta),
            submitted_by=meta.get("submitted_by", ""),
            started_at=row.started_at,
            finished_at=row.finished_at,
            finding_counts=progress.get("finding_counts"),
            error=row.error,
            archived=bool(row.archived),
        )
