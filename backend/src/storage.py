from __future__ import annotations


from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import case, select

from src.db.helpers import run_db
from src.db.models import ScanRun, Finding, Decision
from src.shared.paths import (
    dt_to_iso as _dt_to_iso,
    normalize_org,
    now_iso,
)
from src.secrets.store import (
    SECRET_VALUE_KEYS,
    VALID_REVIEW_STATUSES,
    build_secret_identity,
    ensure_secret_identity,
    normalize_decision_value,
    secret_decision_key,
    secret_identity_value,
    secret_key_decision_key,
    default_secret_run_progress,
    build_secrets_snapshot as _build_secrets_snapshot,
    combine_secrets_snapshots as _combine_secrets_snapshots,
    empty_secrets_snapshot,
)


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _run_to_dict(run: ScanRun) -> dict[str, Any]:
    """Convert ScanRun model to the dict format callers expect."""
    meta = run.metadata_json or {}
    duration_seconds: int | None = None
    if run.started_at and run.finished_at:
        duration_seconds = max(0, int((run.finished_at - run.started_at).total_seconds()))
    return {
        "id": run.id,
        "org": run.org,
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


# ---------------------------------------------------------------------------
# Dependencies Run CRUD — stored in scan_runs table (tool='dependencies')
# ---------------------------------------------------------------------------

def create_dependencies_run(org_key: str, run_id: str) -> dict[str, Any]:
    now = _now_dt()
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
            tool="dependencies",
            org=org_key,
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
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
            .where(ScanRun.tool == "dependencies", ScanRun.org == org_key)
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# ---------------------------------------------------------------------------
# Dependencies Findings — read from unified Finding table
# ---------------------------------------------------------------------------

def read_dependencies_findings(org: str) -> list[dict[str, Any]]:
    async def _query(session):
        org_key = normalize_org(org)
        # Single query with LEFT JOIN — avoids two full table scans + Python dict join
        stmt = (
            select(Finding, Decision)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.org == Finding.org)
                & (Decision.identity_key == Finding.identity_key),
            )
            .where(Finding.tool == "dependencies", Finding.org == org_key)
        )
        result = await session.execute(stmt)
        return [_finding_to_dependencies_alert(f, d) for f, d in result.all()]
    return run_db(_query)


def _finding_to_dependencies_alert(f: Finding, decision: Decision | None = None) -> dict[str, Any]:
    detail = f.detail or {}
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
        "current_version": detail.get("currentVersion"),
        "repository": {"name": (f.repo or "").rsplit("/", 1)[-1], "full_name": f.repo or ""},
        "dependency": {
            "package": {"name": detail.get("packageName", ""), "ecosystem": detail.get("ecosystem", "")},
            "manifest_path": detail.get("manifestPath", ""),
        },
        "security_advisory": {
            "ghsa_id": detail.get("advisoryId", ""),
            "cve_id": detail.get("cveId"),
            "summary": detail.get("summary", ""),
            "description": detail.get("description", ""),
            "severity": f.severity or "",
            "cvss": {"score": detail.get("cvssScore"), "vector_string": detail.get("cvssVector")},
            "published_at": detail.get("publishedAt", ""),
            "updated_at": detail.get("advisoryUpdatedAt", ""),
            "html_url": detail.get("advisoryUrl", ""),
            "references": detail.get("references", []),
        },
        "security_vulnerability": {
            "package": {"name": detail.get("packageName", ""), "ecosystem": detail.get("ecosystem", "")},
            "severity": f.severity or "",
            "vulnerable_version_range": detail.get("vulnerableVersionRange", ""),
            "first_patched_version": {"identifier": detail["patchedVersion"]} if detail.get("patchedVersion") else None,
        },
        "source": detail.get("source", "git"),
        "scanner": detail.get("scanner", "grype"),
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

# ---------------------------------------------------------------------------
# ContainerScanning Run CRUD — stored in scan_runs table (tool='container_scanning')
# ---------------------------------------------------------------------------

def create_container_scanning_run(org_key: str, run_id: str) -> dict[str, Any]:
    now = _now_dt()
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
            org=org_key,
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
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
            .where(ScanRun.tool == "container_scanning", ScanRun.org == org_key)
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# ---------------------------------------------------------------------------
# ContainerScanning Findings — read from unified Finding table
# ---------------------------------------------------------------------------

def read_container_scanning_findings(org: str) -> list[dict[str, Any]]:
    async def _query(session):
        org_key = normalize_org(org)
        stmt = (
            select(Finding, Decision)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.org == Finding.org)
                & (Decision.identity_key == Finding.identity_key),
            )
            .where(Finding.tool == "container_scanning", Finding.org == org_key)
        )
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


# ---------------------------------------------------------------------------
# Secret runs — stored in scan_runs table (tool='secrets')
# ---------------------------------------------------------------------------

def _secret_run_to_dict(run: ScanRun) -> dict[str, Any]:
    meta = run.metadata_json or {}
    return {
        "id": run.id,
        "organization": run.org,
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
    now = _now_dt()
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
            tool="secrets",
            org=org.lower(),
            status="queued",
            progress=run_dict["progress"],
            metadata_json={
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
            run = ScanRun(id=run_id, tool="secrets", org=org.lower(), status="queued")
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
            .where(ScanRun.tool == "secrets", ScanRun.org == org.lower())
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


# ---------------------------------------------------------------------------
# Secret findings — read from unified Finding table (tool='secrets')
# ---------------------------------------------------------------------------

def _finding_to_secret_dict(f: Finding, decision: Decision | None = None) -> dict[str, Any]:
    detail = f.detail or {}
    review_status = "new"
    if f.state == "dismissed":
        review_status = "false_positive"
    elif f.state == "fixed":
        review_status = "action_taken"
    result = {
        **detail,
        "organization": f.org or "",
        "reviewStatus": review_status,
        "secretIdentity": f.identity_key or detail.get("secretIdentity", ""),
        "severity": f.severity or "",
        "state": f.state,
    }
    if decision:
        result["dismissed_at"] = _dt_to_iso(decision.decided_at)
        result["dismissed_by"] = decision.decided_by
        result["dismissed_reason"] = decision.reason
    return result


def read_latest_findings(org: str) -> list[dict[str, Any]]:
    """Read all secret findings for an org from the DB."""
    async def _query(session):
        org_key = normalize_org(org)
        stmt = (
            select(Finding, Decision)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.org == Finding.org)
                & (Decision.identity_key == Finding.identity_key),
            )
            .where(Finding.tool == "secrets", Finding.org == org_key)
        )
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
            .where(ScanRun.tool == "secrets", ScanRun.org == org.lower())
            .order_by(ScanRun.started_at.desc().nullslast())
            .limit(1)
        )
        run = result.scalars().first()
        return run.id if run else None

    last_run_id = run_db(_query)
    return build_secrets_snapshot(org, findings, last_run_id)


def combine_secrets_snapshots(orgs: list[str], snapshots: list[dict[str, Any] | None]) -> dict[str, Any]:
    return _combine_secrets_snapshots(orgs, snapshots, ensure_secret_identity)


# ---------------------------------------------------------------------------
# Code Scanning Run CRUD — stored in scan_runs table (tool='code_scanning')
# ---------------------------------------------------------------------------

def create_code_scanning_run(org_key: str, run_id: str) -> dict[str, Any]:
    now = _now_dt()
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
            org=org_key,
            status="queued",
            started_at=None,
            progress=run_dict["progress"],
            metadata_json={
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
            .where(ScanRun.tool == "code_scanning", ScanRun.org == org_key)
            .order_by(ScanRun.started_at.desc().nullslast())
        )
        return [_run_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


# ---------------------------------------------------------------------------
# Code Scanning Findings — read from unified Finding table
# ---------------------------------------------------------------------------

def read_code_scanning_findings(org: str) -> list[dict[str, Any]]:
    async def _query(session):
        org_key = normalize_org(org)
        stmt = (
            select(Finding, Decision)
            .outerjoin(
                Decision,
                (Decision.tool == Finding.tool)
                & (Decision.org == Finding.org)
                & (Decision.identity_key == Finding.identity_key),
            )
            .where(Finding.tool == "code_scanning", Finding.org == org_key)
        )
        result = await session.execute(stmt)
        return [_finding_to_code_scanning_dict(f, d) for f, d in result.all()]
    return run_db(_query)


def _finding_to_code_scanning_dict(f: Finding, decision: Decision | None = None) -> dict[str, Any]:
    detail = f.detail or {}
    result: dict[str, Any] = {
        "state": f.state,
        "first_seen_at": _dt_to_iso(f.first_seen_at),
        "fixed_at": _dt_to_iso(f.fixed_at),
        "dismissed_at": _dt_to_iso(decision.decided_at) if decision else None,
        "dismissed_by": decision.decided_by if decision else None,
        "dismissed_reason": decision.reason if decision else None,
        "repo_full_name": f.repo or "",
        "rule_id": detail.get("ruleId", ""),
        "rule_name": detail.get("ruleName", ""),
        "file_path": detail.get("filePath", ""),
        "start_line": detail.get("startLine", 0),
        "end_line": detail.get("endLine", 0),
        "severity": f.severity or "",
        "confidence": detail.get("confidence", ""),
        "category": detail.get("category", ""),
        "cwe": detail.get("cwe", []),
        "message": detail.get("message", ""),
        "snippet": detail.get("snippet", ""),
        "fix_suggestion": detail.get("fixSuggestion"),
        "ai_review": detail.get("aiReview"),
        # AI review context fields
        "language": detail.get("language", ""),
        "file_class": detail.get("fileClass", ""),
    }
    # Optional large fields
    for key in ("code_flows", "code_window", "imports", "reachability"):
        val = detail.get(key)
        if val:
            result[key] = val
    return result


def patch_finding_detail(tool: str, org: str, identity_key: str, patch: dict[str, Any]) -> None:
    """Merge keys into a finding's detail JSONB. Used for AI review results etc."""
    async def _query(session):
        result = await session.execute(
            select(Finding).where(
                Finding.tool == tool,
                Finding.org == normalize_org(org),
                Finding.identity_key == identity_key,
            )
        )
        finding = result.scalars().first()
        if finding:
            detail = dict(finding.detail or {})
            detail.update(patch)
            finding.detail = detail
            finding.updated_at = _now_dt()

    run_db(_query)


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
