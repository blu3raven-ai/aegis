"""Secret scanning utility functions — identity hashing, decision keys, snapshot building.

Pure functions with no file or database I/O. All persistence is handled by
src.storage (which uses PostgreSQL via run_db).
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable


def default_secret_run_progress() -> dict[str, Any]:
    return {
        "expectedRepos": None,
        "scannedRepos": 0,
        "finishedRepos": 0,
        "percent": 0,
        "currentRepo": None,
        "currentClassifying": None,
        "stage": "queued",
    }


VALID_REVIEW_STATUSES = {"new", "confirmed", "false_positive", "action_taken"}
SECRET_VALUE_KEYS = ["Secret", "Raw", "RawV2", "secret", "Match", "match", "Redacted"]


def secret_identity_value(finding: dict[str, Any]) -> str | None:
    raw = finding.get("raw") if isinstance(finding.get("raw"), dict) else {}
    for key in SECRET_VALUE_KEYS:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    snippet = finding.get("secretSnippet")
    return snippet.strip() if isinstance(snippet, str) and snippet.strip() else None


def build_secret_identity(finding: dict[str, Any]) -> str | None:
    value = secret_identity_value(finding)
    org = str(finding.get("organization") or "").strip().lower()
    if not value or not org:
        return None
    return hashlib.sha256(f"{org}::{value.strip()}".encode("utf-8")).hexdigest()


def ensure_secret_identity(finding: dict[str, Any]) -> dict[str, Any]:
    if finding.get("secretIdentity"):
        return finding
    return {**finding, "secretIdentity": build_secret_identity(finding)}


def secret_key_decision_key(org: str, secret_identity: str) -> str:
    return "::".join(["v3", "secret", org.strip().lower(), secret_identity])


def normalize_decision_value(value: Any) -> str:
    return str(value or "").strip().lower()


def secret_decision_key(target: dict[str, Any]) -> str:
    scoped_keys = ["repository", "source", "detector", "filePath", "line", "commit"]
    if all(key not in target for key in scoped_keys):
        return str(target.get("fingerprint") or "")
    return "::".join(
        [
            "v2",
            normalize_decision_value(target.get("repository")),
            normalize_decision_value(target.get("source")),
            normalize_decision_value(target.get("detector")),
            normalize_decision_value(target.get("filePath")),
            "" if target.get("line") is None else str(target.get("line")),
            normalize_decision_value(target.get("commit")),
            str(target.get("fingerprint") or ""),
        ]
    )


def build_secrets_snapshot(org: str, findings: list[dict[str, Any]], last_run_id: str | None, now_iso: Callable[[], str]) -> dict[str, Any]:
    repositories = {str(finding.get("repository") or "").lower() for finding in findings}
    source_counts: dict[str, int] = {}
    counts = {"newCount": 0, "confirmedCount": 0, "falsePositiveCount": 0, "actionTakenCount": 0}
    for finding in findings:
        source = str(finding.get("source") or "unknown").lower()
        source_counts[source] = source_counts.get(source, 0) + 1
        status = finding.get("reviewStatus")
        if status == "confirmed":
            counts["confirmedCount"] += 1
        elif status == "false_positive":
            counts["falsePositiveCount"] += 1
        elif status == "action_taken":
            counts["actionTakenCount"] += 1
        else:
            counts["newCount"] += 1
    return {
        "meta": {"organization": org.lower(), "lastUpdatedAt": now_iso(), "lastRunId": last_run_id},
        "stats": {
            "total": len(findings),
            "repositoriesAffected": len(repositories),
            "sources": len(source_counts),
            **counts,
        },
        "sourceBreakdown": [
            {"source": source, "count": count}
            for source, count in sorted(source_counts.items(), key=lambda item: -item[1])
        ],
        "findings": findings,
    }


def empty_secrets_snapshot(org: str) -> dict[str, Any]:
    return {
        "meta": {"organization": org, "lastUpdatedAt": "", "lastRunId": None},
        "stats": {
            "total": 0,
            "repositoriesAffected": 0,
            "sources": 0,
            "newCount": 0,
            "confirmedCount": 0,
            "falsePositiveCount": 0,
            "actionTakenCount": 0,
        },
        "sourceBreakdown": [],
        "findings": [],
    }


def combine_secrets_snapshots(orgs: list[str], snapshots: list[dict[str, Any] | None], ensure_secret_identity: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    latest_updated_at = ""
    for snapshot in snapshots:
        if not snapshot:
            continue
        findings.extend(ensure_secret_identity(item) for item in snapshot.get("findings") or [])
        updated_at = ((snapshot.get("meta") or {}).get("lastUpdatedAt") or "")
        if updated_at > latest_updated_at:
            latest_updated_at = updated_at

    repositories = {f"{str(item.get('organization', '')).lower()}/{str(item.get('repository', '')).lower()}" for item in findings}
    sources = {str(item.get("source", "")).lower() for item in findings if item.get("source")}
    source_counts: dict[str, int] = {}
    counts = {"newCount": 0, "confirmedCount": 0, "falsePositiveCount": 0, "actionTakenCount": 0}
    for finding in findings:
        source = str(finding.get("source") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        status = finding.get("reviewStatus")
        if status == "confirmed":
            counts["confirmedCount"] += 1
        elif status == "false_positive":
            counts["falsePositiveCount"] += 1
        elif status == "action_taken":
            counts["actionTakenCount"] += 1
        else:
            counts["newCount"] += 1

    return {
        "meta": {"organization": ",".join(orgs), "lastUpdatedAt": latest_updated_at, "lastRunId": None},
        "stats": {
            "total": len(findings),
            "repositoriesAffected": len({value for value in repositories if value != "/"}),
            "sources": len(sources),
            **counts,
        },
        "sourceBreakdown": [
            {"source": source, "count": count}
            for source, count in sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        "findings": findings,
    }
