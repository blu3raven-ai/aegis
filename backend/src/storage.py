from __future__ import annotations


from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, or_, and_, select

from src.db.helpers import run_db
from src.db.models import Asset, ScanRun, Finding, Decision
from src.shared.archived_filter import exclude_archived, include_archived
from src.shared.paths import (
    dt_to_iso as _dt_to_iso,
    now_iso,
)
from src.secrets.store import (
    ensure_secret_identity,
    default_secret_run_progress,
    build_secrets_snapshot as _build_secrets_snapshot,
    combine_secrets_snapshots as _combine_secrets_snapshots,
)


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _asset_to_repo_dict(asset: Asset | None) -> dict[str, str]:
    """Render an Asset row as the {name, full_name} shape API responses expect.

    `display_name` is the canonical "owner/repo" form (e.g. "acme/foo") for
    repo assets; for image assets it's "image:tag". Either way, `name` is the
    last segment after the final "/".
    """
    if asset is None:
        return {"name": "", "full_name": ""}
    full = asset.display_name or ""
    name = full.rsplit("/", 1)[-1] if full else ""
    return {"name": name, "full_name": full}


def _run_to_dict(run: ScanRun) -> dict[str, Any]:
    """Convert ScanRun model to the dict format callers expect."""
    meta = run.metadata_json or {}
    duration_seconds: int | None = None
    if run.started_at and run.finished_at:
        duration_seconds = max(0, int((run.finished_at - run.started_at).total_seconds()))
    return {
        "id": run.id,
        "org": meta.get("org_label", ""),  # org_label stored in metadata after Plan D
        "status": run.status or "queued",
        "createdAt": _dt_to_iso(run.started_at) or meta.get("createdAt", now_iso()),
        "startedAt": _dt_to_iso(run.started_at),
        "finishedAt": _dt_to_iso(run.finished_at),
        "durationSeconds": duration_seconds,
        "findingsCount": meta.get("findingsCount", 0),
        "repositories": meta.get("repositories", []),
        "counts": meta.get("counts", {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}),
        "error": run.error,
        "logTail": meta.get("logTail", []),
        "progress": run.progress or meta.get("progress", {
            "expectedRepos": None, "scannedRepos": 0, "finishedRepos": 0,
            "percent": 0, "currentRepo": None, "stage": "queued",
        }),
        # Pass through any extra metadata fields
        **{k: v for k, v in meta.items() if k not in {
            "createdAt", "findingsCount", "repositories", "counts", "logTail", "progress",
        }},
    }


# Dependencies Run CRUD — stored in scan_runs table (tool='dependencies_scanning')

def create_dependencies_run(org_key: str, run_id: str) -> dict[str, Any]:
    run_dict: dict[str, Any] = {
        "id": run_id,
        "org": org_key,
        "status": "queued",
        "createdAt": now_iso(),
        "startedAt": None,
        "finishedAt": None,
        "findingsCount": 0,
        "repositories": [],
        "counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "error": None,
        "logTail": [],
        "progress": {
            "expectedRepos": None,
            "scannedRepos": 0,
            "finishedRepos": 0,
            "percent": 0,
            "currentRepo": None,
            "stage": "queued",
        },
    }

    async def _query(session):
        session.add(ScanRun(
            id=run_id,
            tool="dependencies_scanning",
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
                "org_label": org_key,
                "createdAt": run_dict["createdAt"],
                "findingsCount": 0,
                "repositories": [],
                "counts": run_dict["counts"],
                "logTail": [],
            },
        ))

    run_db(_query)
    return run_dict


def update_dependencies_run(org_key: str, run_id: str, patch: dict[str, Any]) -> None:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            return
        meta = dict(run.metadata_json or {})

        if "status" in patch:
            run.status = patch["status"]
        if "error" in patch:
            run.error = patch["error"]
        if "finishedAt" in patch:
            try:
                run.finished_at = datetime.fromisoformat(patch["finishedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "startedAt" in patch:
            try:
                run.started_at = datetime.fromisoformat(patch["startedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if "progress" in patch and isinstance(patch["progress"], dict):
            existing_progress = run.progress or {}
            existing_percent = existing_progress.get("percent", 0) if isinstance(existing_progress.get("percent"), (int, float)) else 0
            patch_percent = patch["progress"].get("percent", existing_percent) if isinstance(patch["progress"].get("percent"), (int, float)) else existing_percent
            run.progress = {**existing_progress, **patch["progress"], "percent": max(existing_percent, patch_percent)}
        elif "progress" in patch:
            run.progress = patch["progress"]

        skip_keys = {"status", "error", "finishedAt", "startedAt", "progress", "id", "org"}
        for key, value in patch.items():
            if key not in skip_keys:
                meta[key] = value
        run.metadata_json = meta

    run_db(_query)


def list_dependencies_runs(org_key: str) -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "dependencies_scanning",
                ScanRun.metadata_json["org_label"].astext == org_key,
            )
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# Dependencies Findings — read from unified Finding table

def read_dependencies_findings(*, asset_ids: list[str], include_archived_rows: bool = False) -> list[dict[str, Any]]:
    if not asset_ids:
        return []
    async def _query(session):
        stmt = (
            select(Finding, Decision, Asset)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.asset_id == Finding.asset_id)
                & (Decision.identity_key == Finding.identity_key),
            )
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.tool == "dependencies_scanning", Finding.asset_id.in_(asset_ids))
        )
        if include_archived_rows:
            stmt = include_archived(stmt)
        else:
            stmt = exclude_archived(stmt, Finding)
        result = await session.execute(stmt)
        return [_finding_to_dependencies_alert(f, d, a) for f, d, a in result.all()]
    return run_db(_query)


def _finding_to_dependencies_alert(
    f: Finding, decision: Decision | None = None, asset: Asset | None = None,
) -> dict[str, Any]:
    from src.shared.finding_detail_blob import hydrate_detail
    detail = hydrate_detail(f)
    return {
        "state": f.state,
        "first_seen_at": _dt_to_iso(f.first_seen_at),
        "fixed_at": _dt_to_iso(f.fixed_at),
        "created_at": detail.get("publishedAt") or _dt_to_iso(f.first_seen_at) or _dt_to_iso(f.created_at),
        "updated_at": _dt_to_iso(f.updated_at),
        "dismissed_at": _dt_to_iso(decision.decided_at) if decision else None,
        "dismissed_by": decision.decided_by if decision else None,
        "dismissed_reason": decision.reason if decision else None,
        "dismissed_comment": decision.comment if decision else None,
        "state_changed_at": _dt_to_iso(f.updated_at),
        # Commit attribution (§5.6)
        "introduced_by_commit_sha": getattr(f, "introduced_by_commit_sha", None),
        "introduced_by_author": getattr(f, "introduced_by_author", None),
        "introduced_at": _dt_to_iso(getattr(f, "introduced_at", None)),
        "introduced_by_pr_url": getattr(f, "introduced_by_pr_url", None),
        "current_version": detail.get("currentVersion"),
        "repository": _asset_to_repo_dict(asset),
        "dependency": {
            "package": {"name": detail.get("packageName", ""), "ecosystem": detail.get("ecosystem", "")},
            "manifest_path": detail.get("manifestPath", ""),
        },
        "security_advisory": {
            "ghsa_id": detail.get("advisoryId", ""),
            "cve_id": f.cve_id,
            "summary": detail.get("summary", ""),
            "description": detail.get("description", ""),
            "severity": f.severity or "",
            "cvss": {"score": detail.get("cvssScore"), "vector_string": detail.get("cvssVector")},
            "published_at": detail.get("publishedAt", ""),
            "updated_at": detail.get("advisoryUpdatedAt", ""),
            "html_url": detail.get("advisoryUrl") or "",
            "references": detail.get("references", []),
        },
        "security_vulnerability": {
            "package": {"name": detail.get("packageName", ""), "ecosystem": detail.get("ecosystem", "")},
            "severity": f.severity or "",
            "vulnerable_version_range": detail.get("vulnerableVersionRange", ""),
            "first_patched_version": {"identifier": detail["patchedVersion"]} if detail.get("patchedVersion") else None,
        },
        "source": detail.get("source", "git"),
        "scanner": detail.get("scanner", "osv"),
        "manifest_snippet": detail.get("manifestSnippet"),
        "manifest_match_line": detail.get("manifestMatchLine"),
        "matched_by": detail.get("matchedBy", []),
    }


def empty_dependencies_snapshot(org: str) -> dict[str, Any]:
    return {
        "meta": {"org": org.lower(), "schemaVersion": 1, "lastRefreshedAt": ""},
        "alerts": [],
        "analytics": {
            "counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "severityDistribution": [
                {"severity": "critical", "count": 0, "percentage": 0},
                {"severity": "high", "count": 0, "percentage": 0},
                {"severity": "medium", "count": 0, "percentage": 0},
                {"severity": "low", "count": 0, "percentage": 0},
            ],
            "ageBuckets": [],
            "topRepositories": [],
            "remediation": {"totalFixed": 0, "avgDays": 0, "medianDays": 0, "fixedLast30d": 0},
            "repositoryCoverage": {"total": 0, "affected": 0, "unaffected": 0, "percentage": 0},
            "riskScore": {"score": 0, "rating": "none", "summary": ""},
        },
    }

# ContainerScanning Run CRUD — stored in scan_runs table (tool='container_scanning')

def create_container_scanning_run(org_key: str, run_id: str) -> dict[str, Any]:
    run_dict: dict[str, Any] = {
        "id": run_id,
        "org": org_key,
        "status": "queued",
        "createdAt": now_iso(),
        "startedAt": None,
        "finishedAt": None,
        "findingsCount": 0,
        "repositories": [],
        "counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "error": None,
        "logTail": [],
        "progress": {
            "expectedRepos": None,
            "scannedRepos": 0,
            "finishedRepos": 0,
            "percent": 0,
            "currentRepo": None,
            "stage": "queued",
        },
    }

    async def _query(session):
        session.add(ScanRun(
            id=run_id,
            tool="container_scanning",
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
                "org_label": org_key,
                "createdAt": run_dict["createdAt"],
                "findingsCount": 0,
                "repositories": [],
                "counts": run_dict["counts"],
                "logTail": [],
            },
        ))

    run_db(_query)
    return run_dict


def update_container_scanning_run(org_key: str, run_id: str, patch: dict[str, Any]) -> None:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            return
        meta = dict(run.metadata_json or {})

        if "status" in patch:
            run.status = patch["status"]
        if "error" in patch:
            run.error = patch["error"]
        if "finishedAt" in patch:
            try:
                run.finished_at = datetime.fromisoformat(patch["finishedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "startedAt" in patch:
            try:
                run.started_at = datetime.fromisoformat(patch["startedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if "progress" in patch and isinstance(patch["progress"], dict):
            existing_progress = run.progress or {}
            existing_percent = existing_progress.get("percent", 0) if isinstance(existing_progress.get("percent"), (int, float)) else 0
            patch_percent = patch["progress"].get("percent", existing_percent) if isinstance(patch["progress"].get("percent"), (int, float)) else existing_percent
            run.progress = {**existing_progress, **patch["progress"], "percent": max(existing_percent, patch_percent)}
        elif "progress" in patch:
            run.progress = patch["progress"]

        skip_keys = {"status", "error", "finishedAt", "startedAt", "progress", "id", "org"}
        for key, value in patch.items():
            if key not in skip_keys:
                meta[key] = value
        run.metadata_json = meta

    run_db(_query)


def list_container_scanning_runs(org_key: str) -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "container_scanning",
                ScanRun.metadata_json["org_label"].astext == org_key,
            )
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# ContainerScanning Findings — read from unified Finding table

def read_container_scanning_findings(*, asset_ids: list[str], include_archived_rows: bool = False) -> list[dict[str, Any]]:
    if not asset_ids:
        return []
    async def _query(session):
        stmt = (
            select(Finding, Decision)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.asset_id == Finding.asset_id)
                & (Decision.identity_key == Finding.identity_key),
            )
            .where(Finding.tool == "container_scanning", Finding.asset_id.in_(asset_ids))
        )
        if include_archived_rows:
            stmt = include_archived(stmt)
        else:
            stmt = exclude_archived(stmt, Finding)
        result = await session.execute(stmt)
        return [_finding_to_dependencies_alert(f, d) for f, d in result.all()]
    return run_db(_query)


def empty_container_scanning_snapshot(org: str) -> dict[str, Any]:
    return {
        "meta": {"org": org.lower(), "schemaVersion": 1, "lastRefreshedAt": ""},
        "alerts": [],
        "analytics": {
            "counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "severityDistribution": [
                {"severity": "critical", "count": 0, "percentage": 0},
                {"severity": "high", "count": 0, "percentage": 0},
                {"severity": "medium", "count": 0, "percentage": 0},
                {"severity": "low", "count": 0, "percentage": 0},
            ],
            "ageBuckets": [],
            "topRepositories": [],
            "remediation": {"totalFixed": 0, "avgDays": 0, "medianDays": 0, "fixedLast30d": 0},
            "repositoryCoverage": {"total": 0, "affected": 0, "unaffected": 0, "percentage": 0},
            "riskScore": {"score": 0, "rating": "none", "summary": ""},
        },
    }


# Secret runs — stored in scan_runs table (tool='secret_scanning')

def _secret_run_to_dict(run: ScanRun) -> dict[str, Any]:
    meta = run.metadata_json or {}
    return {
        "id": run.id,
        "organization": meta.get("org_label", ""),
        "status": run.status or "queued",
        "createdAt": meta.get("createdAt", _dt_to_iso(run.started_at) or now_iso()),
        "startedAt": _dt_to_iso(run.started_at),
        "finishedAt": _dt_to_iso(run.finished_at),
        "lastHeartbeatAt": meta.get("lastHeartbeatAt"),
        "lastProgressAt": meta.get("lastProgressAt"),
        "lastStatusTransitionAt": meta.get("lastStatusTransitionAt"),
        "reconciled": meta.get("reconciled", False),
        "reconciliationReason": meta.get("reconciliationReason"),
        "findingsCount": meta.get("findingsCount", 0),
        "error": run.error,
        "logTail": meta.get("logTail", []),
        "progress": run.progress or default_secret_run_progress(),
        **{k: v for k, v in meta.items() if k not in {
            "createdAt", "lastHeartbeatAt", "lastProgressAt", "lastStatusTransitionAt",
            "reconciled", "reconciliationReason", "findingsCount", "logTail", "progress",
        }},
    }



def create_secret_run(org: str, run_id: str) -> dict[str, Any]:
    run_dict: dict[str, Any] = {
        "id": run_id,
        "organization": org.lower(),
        "status": "queued",
        "createdAt": now_iso(),
        "startedAt": None,
        "finishedAt": None,
        "lastHeartbeatAt": None,
        "lastProgressAt": None,
        "lastStatusTransitionAt": None,
        "reconciled": False,
        "reconciliationReason": None,
        "findingsCount": 0,
        "error": None,
        "logTail": [],
        "progress": default_secret_run_progress(),
    }

    async def _query(session):
        session.add(ScanRun(
            id=run_id,
            tool="secret_scanning",
            status="queued",
            progress=run_dict["progress"],
            metadata_json={
                "org_label": org.lower(),
                "createdAt": run_dict["createdAt"],
                "findingsCount": 0,
                "logTail": [],
            },
        ))

    run_db(_query)
    return run_dict


def read_secret_run(org: str, run_id: str) -> dict[str, Any] | None:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            return None
        return _secret_run_to_dict(run)

    return run_db(_query)


def update_secret_run(org: str, run_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            # Create it
            run = ScanRun(id=run_id, tool="secret_scanning", status="queued",
                          metadata_json={"org_label": org.lower()})
            session.add(run)

        meta = dict(run.metadata_json or {})

        if "status" in patch:
            run.status = patch["status"]
        if "error" in patch:
            run.error = patch["error"]
        if "finishedAt" in patch:
            try:
                run.finished_at = datetime.fromisoformat(patch["finishedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "startedAt" in patch:
            try:
                run.started_at = datetime.fromisoformat(patch["startedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if "progress" in patch and isinstance(patch["progress"], dict):
            existing_progress = run.progress or {}
            existing_percent = existing_progress.get("percent", 0) if isinstance(existing_progress.get("percent"), (int, float)) else 0
            patch_percent = patch["progress"].get("percent", existing_percent) if isinstance(patch["progress"].get("percent"), (int, float)) else existing_percent
            run.progress = {**existing_progress, **patch["progress"], "percent": max(existing_percent, patch_percent)}
        elif "progress" in patch:
            run.progress = patch["progress"]

        skip_keys = {"status", "error", "finishedAt", "startedAt", "progress", "id", "organization", "org"}
        for key, value in patch.items():
            if key not in skip_keys:
                meta[key] = value
        run.metadata_json = meta

        return _secret_run_to_dict(run)

    return run_db(_query)


def list_secret_runs(org: str) -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "secret_scanning",
                ScanRun.metadata_json["org_label"].astext == org.lower(),
            )
            .order_by(
                case(
                    (ScanRun.status.in_(["queued", "running", "ingesting"]), 0),
                    else_=1,
                ).asc(),
                ScanRun.started_at.desc().nullslast(),
            )
        )
        return [_secret_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# Secret findings — read from unified Finding table (tool='secret_scanning')

def _finding_to_secret_dict(f: Finding, decision: Decision | None = None) -> dict[str, Any]:
    from src.shared.finding_detail_blob import hydrate_detail
    detail = hydrate_detail(f)
    review_status = f.review_status or "new"
    result = {
        **detail,
        "organization": detail.get("org", ""),  # org_label stored in detail for secrets
        "reviewStatus": review_status,
        "secretIdentity": f.identity_key or detail.get("secretIdentity", ""),
        "severity": f.severity or "",
        "state": f.state,
        # Commit attribution (§5.6)
        "introduced_by_commit_sha": getattr(f, "introduced_by_commit_sha", None),
        "introduced_by_author": getattr(f, "introduced_by_author", None),
        "introduced_at": _dt_to_iso(getattr(f, "introduced_at", None)),
        "introduced_by_pr_url": getattr(f, "introduced_by_pr_url", None),
    }
    if decision:
        result["dismissed_at"] = _dt_to_iso(decision.decided_at)
        result["dismissed_by"] = decision.decided_by
        result["dismissed_reason"] = decision.reason
    return result


def read_latest_findings(org: str | None = None, *, asset_ids: list[str] | None = None, include_archived_rows: bool = False) -> list[dict[str, Any]]:
    """Read secret findings from the DB. Secrets have asset_id=NULL; no org filter after Plan D."""
    async def _query(session):
        stmt = (
            select(Finding, Decision)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                # Secrets have NULL asset_id; use IS NOT DISTINCT FROM semantics
                # because NULL = NULL evaluates to NULL (not TRUE) in SQL.
                & or_(
                    and_(Decision.asset_id.is_(None), Finding.asset_id.is_(None)),
                    Decision.asset_id == Finding.asset_id,
                )
                & (Decision.identity_key == Finding.identity_key),
            )
            .where(Finding.tool == "secret_scanning")
        )
        if asset_ids is not None:
            stmt = stmt.where(Finding.asset_id.in_(asset_ids))
        # Secrets are emitted with asset_id=NULL by design (they aren't bound
        # to a specific repo asset). Per-source isolation is deferred until a
        # secrets-specific identity model exists.
        if include_archived_rows:
            stmt = include_archived(stmt)
        else:
            stmt = exclude_archived(stmt, Finding)
        result = await session.execute(stmt)
        return [_finding_to_secret_dict(f, d) for f, d in result.all()]

    return run_db(_query)


def build_secrets_snapshot(org: str, findings: list[dict[str, Any]], last_run_id: str | None) -> dict[str, Any]:
    return _build_secrets_snapshot(org, findings, last_run_id, now_iso)


def read_secrets_snapshot(org: str) -> dict[str, Any] | None:
    """Build a snapshot from DB findings."""
    findings = read_latest_findings(org)
    if not findings:
        return None
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "secret_scanning",
                ScanRun.metadata_json["org_label"].astext == org.lower(),
            )
            .order_by(ScanRun.started_at.desc().nullslast())
            .limit(1)
        )
        run = result.scalars().first()
        return run.id if run else None

    last_run_id = run_db(_query)
    return build_secrets_snapshot(org, findings, last_run_id)


def combine_secrets_snapshots(orgs: list[str], snapshots: list[dict[str, Any] | None]) -> dict[str, Any]:
    return _combine_secrets_snapshots(orgs, snapshots, ensure_secret_identity)


# Code Scanning Run CRUD — stored in scan_runs table (tool='code_scanning')

def create_code_scanning_run(org_key: str, run_id: str) -> dict[str, Any]:
    run_dict: dict[str, Any] = {
        "id": run_id,
        "org": org_key,
        "status": "queued",
        "createdAt": now_iso(),
        "startedAt": None,
        "finishedAt": None,
        "findingsCount": 0,
        "error": None,
        "logTail": [],
        "progress": {
            "expectedRepos": None,
            "scannedRepos": 0,
            "finishedRepos": 0,
            "percent": 0,
            "currentRepo": None,
            "stage": "queued",
        },
    }

    async def _query(session):
        session.add(ScanRun(
            id=run_id,
            tool="code_scanning",
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
                "org_label": org_key,
                "createdAt": run_dict["createdAt"],
                "findingsCount": 0,
                "logTail": [],
            },
        ))

    run_db(_query)
    return run_dict


def update_code_scanning_run(org_key: str, run_id: str, patch: dict[str, Any]) -> None:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            return
        meta = dict(run.metadata_json or {})

        if "status" in patch:
            run.status = patch["status"]
        if "error" in patch:
            run.error = patch["error"]
        if "finishedAt" in patch:
            try:
                run.finished_at = datetime.fromisoformat(patch["finishedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "startedAt" in patch:
            try:
                run.started_at = datetime.fromisoformat(patch["startedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if "progress" in patch and isinstance(patch["progress"], dict):
            existing_progress = run.progress or {}
            existing_percent = existing_progress.get("percent", 0) if isinstance(existing_progress.get("percent"), (int, float)) else 0
            patch_percent = patch["progress"].get("percent", existing_percent) if isinstance(patch["progress"].get("percent"), (int, float)) else existing_percent
            run.progress = {**existing_progress, **patch["progress"], "percent": max(existing_percent, patch_percent)}
        elif "progress" in patch:
            run.progress = patch["progress"]

        skip_keys = {"status", "error", "finishedAt", "startedAt", "progress", "id", "org"}
        for key, value in patch.items():
            if key not in skip_keys:
                meta[key] = value
        run.metadata_json = meta

    run_db(_query)


def list_code_scanning_runs(org_key: str) -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "code_scanning",
                ScanRun.metadata_json["org_label"].astext == org_key,
            )
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


def create_iac_run(org_key: str, run_id: str) -> dict[str, Any]:
    run_dict: dict[str, Any] = {
        "id": run_id,
        "org": org_key,
        "status": "queued",
        "createdAt": now_iso(),
        "startedAt": None,
        "finishedAt": None,
        "findingsCount": 0,
        "error": None,
        "logTail": [],
        "progress": {
            "expectedRepos": None,
            "scannedRepos": 0,
            "finishedRepos": 0,
            "percent": 0,
            "currentRepo": None,
            "stage": "queued",
        },
    }

    async def _query(session):
        session.add(ScanRun(
            id=run_id,
            tool="iac_scanning",
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
                "org_label": org_key,
                "createdAt": run_dict["createdAt"],
                "findingsCount": 0,
                "logTail": [],
            },
        ))

    run_db(_query)
    return run_dict


def update_iac_run(org_key: str, run_id: str, patch: dict[str, Any]) -> None:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            return
        meta = dict(run.metadata_json or {})

        if "status" in patch:
            run.status = patch["status"]
        if "error" in patch:
            run.error = patch["error"]
        if "finishedAt" in patch:
            try:
                run.finished_at = datetime.fromisoformat(patch["finishedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "startedAt" in patch:
            try:
                run.started_at = datetime.fromisoformat(patch["startedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if "progress" in patch and isinstance(patch["progress"], dict):
            existing_progress = run.progress or {}
            existing_percent = existing_progress.get("percent", 0) if isinstance(existing_progress.get("percent"), (int, float)) else 0
            patch_percent = patch["progress"].get("percent", existing_percent) if isinstance(patch["progress"].get("percent"), (int, float)) else existing_percent
            run.progress = {**existing_progress, **patch["progress"], "percent": max(existing_percent, patch_percent)}
        elif "progress" in patch:
            run.progress = patch["progress"]

        skip_keys = {"status", "error", "finishedAt", "startedAt", "progress", "id", "org"}
        for key, value in patch.items():
            if key not in skip_keys:
                meta[key] = value
        run.metadata_json = meta

    run_db(_query)


def list_iac_runs(org_key: str) -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "iac_scanning",
                ScanRun.metadata_json["org_label"].astext == org_key,
            )
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


def create_agent_run(org_key: str, run_id: str) -> dict[str, Any]:
    run_dict: dict[str, Any] = {
        "id": run_id,
        "org": org_key,
        "status": "queued",
        "createdAt": now_iso(),
        "startedAt": None,
        "finishedAt": None,
        "findingsCount": 0,
        "error": None,
        "logTail": [],
        "progress": {
            "expectedRepos": None,
            "scannedRepos": 0,
            "finishedRepos": 0,
            "percent": 0,
            "currentRepo": None,
            "stage": "queued",
        },
    }

    async def _query(session):
        session.add(ScanRun(
            id=run_id,
            tool="agent_scanning",
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
                "org_label": org_key,
                "createdAt": run_dict["createdAt"],
                "findingsCount": 0,
                "logTail": [],
            },
        ))

    run_db(_query)
    return run_dict


def update_agent_run(org_key: str, run_id: str, patch: dict[str, Any]) -> None:
    async def _query(session):
        run = await session.get(ScanRun, run_id)
        if not run:
            return
        meta = dict(run.metadata_json or {})

        if "status" in patch:
            run.status = patch["status"]
        if "error" in patch:
            run.error = patch["error"]
        if "finishedAt" in patch:
            try:
                run.finished_at = datetime.fromisoformat(patch["finishedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "startedAt" in patch:
            try:
                run.started_at = datetime.fromisoformat(patch["startedAt"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if "progress" in patch and isinstance(patch["progress"], dict):
            existing_progress = run.progress or {}
            existing_percent = existing_progress.get("percent", 0) if isinstance(existing_progress.get("percent"), (int, float)) else 0
            patch_percent = patch["progress"].get("percent", existing_percent) if isinstance(patch["progress"].get("percent"), (int, float)) else existing_percent
            run.progress = {**existing_progress, **patch["progress"], "percent": max(existing_percent, patch_percent)}
        elif "progress" in patch:
            run.progress = patch["progress"]

        skip_keys = {"status", "error", "finishedAt", "startedAt", "progress", "id", "org"}
        for key, value in patch.items():
            if key not in skip_keys:
                meta[key] = value
        run.metadata_json = meta

    run_db(_query)


def list_agent_runs(org_key: str) -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(
            select(ScanRun)
            .where(
                ScanRun.tool == "agent_scanning",
                ScanRun.metadata_json["org_label"].astext == org_key,
            )
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# Code Scanning Findings — read from unified Finding table

def read_code_scanning_findings(*, asset_ids: list[str], include_archived_rows: bool = False) -> list[dict[str, Any]]:
    if not asset_ids:
        return []
    async def _query(session):
        stmt = (
            select(Finding, Decision, Asset)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.asset_id == Finding.asset_id)
                & (Decision.identity_key == Finding.identity_key),
            )
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.tool == "code_scanning", Finding.asset_id.in_(asset_ids))
        )
        if include_archived_rows:
            stmt = include_archived(stmt)
        else:
            stmt = exclude_archived(stmt, Finding)
        result = await session.execute(stmt)
        return [_finding_to_code_scanning_dict(f, d, a) for f, d, a in result.all()]
    return run_db(_query)


def _finding_to_code_scanning_dict(
    f: Finding, decision: Decision | None = None, asset: Asset | None = None,
) -> dict[str, Any]:
    from src.shared.finding_detail_blob import hydrate_detail
    detail = hydrate_detail(f)
    result: dict[str, Any] = {
        "state": f.state,
        "first_seen_at": _dt_to_iso(f.first_seen_at),
        "fixed_at": _dt_to_iso(f.fixed_at),
        "dismissed_at": _dt_to_iso(decision.decided_at) if decision else None,
        "dismissed_by": decision.decided_by if decision else None,
        "dismissed_reason": decision.reason if decision else None,
        "repo_full_name": (asset.display_name if asset is not None else ""),
        "rule_id": detail.get("ruleId", ""),
        "rule_name": f.rule_name or "",
        "file_path": f.file_path or "",
        "start_line": detail.get("startLine", 0),
        "end_line": detail.get("endLine", 0),
        "severity": f.severity or "",
        "confidence": detail.get("confidence", ""),
        "category": detail.get("category", ""),
        "cwe": detail.get("cwe", []),
        "message": detail.get("message", ""),
        "snippet": detail.get("snippet", ""),
        "fix_suggestion": detail.get("fixSuggestion"),
        "repo_html_url": detail.get("repoHtmlUrl", ""),
        "language": detail.get("language", ""),
        "file_class": detail.get("fileClass", ""),
        # Commit attribution (§5.6)
        "introduced_by_commit_sha": getattr(f, "introduced_by_commit_sha", None),
        "introduced_by_author": getattr(f, "introduced_by_author", None),
        "introduced_at": _dt_to_iso(getattr(f, "introduced_at", None)),
        "introduced_by_pr_url": getattr(f, "introduced_by_pr_url", None),
        # Engine attribution (column is SOT) + merged rule ids
        "engine": getattr(f, "engine", None),
        "rule_ids": detail.get("ruleIds"),
        # Verifier outputs (columns are SOT)
        "verdict": getattr(f, "verdict", None),
        "evidence": getattr(f, "evidence", None),
        "exploit_chain": getattr(f, "exploit_chain", None),
        "verification_metadata": getattr(f, "verification_metadata", None),
    }
    # Optional large fields
    for key in ("code_flows", "code_window", "imports", "reachability"):
        val = detail.get(key)
        if val:
            result[key] = val
    return result


def empty_code_scanning_snapshot(org: str) -> dict[str, Any]:
    return {
        "meta": {"org": org.lower(), "lastRefreshedAt": "", "runId": None},
        "findings": [],
        "analytics": {
            "counts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "severityDistribution": [
                {"severity": "critical", "count": 0, "percentage": 0},
                {"severity": "high", "count": 0, "percentage": 0},
                {"severity": "medium", "count": 0, "percentage": 0},
                {"severity": "low", "count": 0, "percentage": 0},
            ],
            "topRules": [],
            "topRepositories": [],
        },
    }
