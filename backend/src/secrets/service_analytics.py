from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any, Callable

from src.shared.paths import parse_org_values
from src.storage import (
    combine_secrets_snapshots,
    empty_secrets_snapshot,
    list_secret_runs,
    read_secrets_snapshot,
)


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_snapshot(orgs: list[str]) -> dict[str, Any] | None:
    """Load and combine snapshots for one or more orgs. Shared helper used by all analytics functions."""
    if len(orgs) == 1:
        return read_secrets_snapshot(orgs[0])
    return combine_secrets_snapshots(orgs, [read_secrets_snapshot(org) for org in orgs])


def _extract_findings(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    findings = snapshot.get("findings") if isinstance(snapshot, dict) else []
    return findings if isinstance(findings, list) else []


def snapshot_payload(orgs: list[str]) -> dict[str, Any]:
    if len(orgs) == 1:
        snapshot = read_secrets_snapshot(orgs[0])
        if not snapshot:
            return {"empty": True, "snapshot": empty_secrets_snapshot(orgs[0])}
        findings = _extract_findings(snapshot)
        snapshot["remediation"] = compute_remediation_metrics(findings)
        snapshot["repositoryCoverage"] = compute_repository_coverage(findings, snapshot)
        return {"empty": False, "snapshot": snapshot}

    snapshot = combine_secrets_snapshots(orgs, [read_secrets_snapshot(org) for org in orgs])
    findings = _extract_findings(snapshot)
    snapshot["remediation"] = compute_remediation_metrics(findings)
    snapshot["repositoryCoverage"] = compute_repository_coverage(findings, snapshot)
    return {"empty": len(findings) == 0, "snapshot": snapshot}


def compute_remediation_metrics(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute resolution velocity metrics from finding timestamps."""
    now = datetime.now(timezone.utc)
    resolution_days: list[float] = []
    fixed_last_30d = 0
    total_fixed = 0

    for finding in findings:
        status = finding.get("reviewStatus")
        if status not in ("false_positive", "action_taken"):
            continue
        total_fixed += 1

        resolved_at = _parse_iso_datetime(finding.get("resolvedAt"))
        detected_at = _parse_iso_datetime(finding.get("detectedAt"))

        if resolved_at and detected_at:
            days = max(0, (resolved_at - detected_at).total_seconds() / 86400)
            resolution_days.append(round(days, 1))

        if resolved_at and (now - resolved_at).days <= 30:
            fixed_last_30d += 1

    return {
        "medianDays": round(statistics.median(resolution_days), 1) if resolution_days else None,
        "avgDays": round(statistics.mean(resolution_days), 1) if resolution_days else None,
        "fixedLast30d": fixed_last_30d,
        "totalFixed": total_fixed,
    }


def compute_repository_coverage(findings: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compute repository coverage from findings and snapshot stats."""
    all_repos = {str(f.get("repository") or "").lower() for f in findings if str(f.get("repository") or "").strip()}
    affected = {
        str(f.get("repository") or "").lower()
        for f in findings
        if f.get("reviewStatus") not in ("false_positive", "action_taken")
        and str(f.get("repository") or "").strip()
    }
    total_repos = len(all_repos) or 0
    affected_count = len(affected)
    return {
        "percentage": round((affected_count / total_repos) * 100) if total_repos else 0,
        "affected": affected_count,
        "unaffected": max(0, total_repos - affected_count),
    }


def _queue_identity(finding: dict[str, Any]) -> str:
    return str(finding.get("secretIdentity") or finding.get("fingerprint") or "")


def _confidence_weight(confidence: float | None) -> int:
    if confidence is None:
        return 0
    if confidence >= 0.85:
        return 30
    if confidence >= 0.75:
        return 20
    if confidence >= 0.4:
        return 10
    return 0


def build_review_queue_payload(orgs: list[str]) -> dict[str, Any]:
    snapshot = load_snapshot(orgs)
    findings = _extract_findings(snapshot)
    if not findings:
        return {"empty": True, "queue": []}

    now_dt = datetime.now(timezone.utc)
    detector_totals: dict[str, int] = {}
    detector_false_positives: dict[str, int] = {}
    repo_confirmed_counts: dict[str, int] = {}
    identity_occurrences: dict[str, int] = {}
    identity_first_detected: dict[str, datetime] = {}

    for finding in findings:
        detector = str(finding.get("detector") or "").strip()
        if detector:
            detector_totals[detector] = detector_totals.get(detector, 0) + 1
            if finding.get("reviewStatus") == "false_positive":
                detector_false_positives[detector] = detector_false_positives.get(detector, 0) + 1

        repo_key = f"{str(finding.get('organization') or '').lower()}/{str(finding.get('repository') or '').lower()}"
        if finding.get("reviewStatus") == "confirmed":
            repo_confirmed_counts[repo_key] = repo_confirmed_counts.get(repo_key, 0) + 1

        identity = _queue_identity(finding)
        if identity:
            identity_occurrences[identity] = identity_occurrences.get(identity, 0) + 1
            detected_at = _parse_iso_datetime(finding.get("detectedAt"))
            if detected_at and (identity not in identity_first_detected or detected_at < identity_first_detected[identity]):
                identity_first_detected[identity] = detected_at

    queue: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("reviewStatus") != "new":
            continue
        detector = str(finding.get("detector") or "").strip()
        repo_key = f"{str(finding.get('organization') or '').lower()}/{str(finding.get('repository') or '').lower()}"
        identity = _queue_identity(finding)
        oldest_dt = identity_first_detected.get(identity)
        secret_age_days = max(0, (now_dt - oldest_dt).days) if oldest_dt else None
        detector_total = detector_totals.get(detector, 0)
        detector_noise_rate = (
            round((detector_false_positives.get(detector, 0) / detector_total) * 100)
            if detector_total
            else 0
        )
        occurrence_count = identity_occurrences.get(identity, 1)
        repo_history_count = repo_confirmed_counts.get(repo_key, 0)
        _history = finding.get("classificationHistory") or []
        _active_confidence = float(_history[-1].get("confidence") or 0) if _history else None
        risk_score = (repo_history_count * 100) + (occurrence_count * 10) + _confidence_weight(_active_confidence)
        queue.append(
            {
                **finding,
                "occurrenceCount": occurrence_count,
                "repoHistorySignal": {"confirmedCount": repo_history_count},
                "detectorNoiseRate": detector_noise_rate,
                "secretAgeDays": secret_age_days,
                "riskScore": risk_score,
            }
        )

    queue.sort(
        key=lambda item: (
            -int(item.get("riskScore") or 0),
            str(item.get("organization") or "").lower(),
            str(item.get("repository") or "").lower(),
            str(item.get("fingerprint") or ""),
        )
    )
    return {"empty": len(queue) == 0, "queue": queue}


def build_insights_payload(
    orgs: list[str],
    *,
    source_filter: str | None = None,
    organization_filter: str | None = None,
) -> dict[str, Any]:
    parsed_orgs = parse_org_values(orgs)
    if not parsed_orgs:
        return {"triagePriority": [], "trend": []}
    snapshot = load_snapshot(parsed_orgs)
    findings = _extract_findings(snapshot)
    if source_filter:
        source_value = source_filter.strip().lower()
        findings = [
            finding for finding in findings
            if isinstance(finding, dict) and str(finding.get("source") or "").strip().lower() == source_value
        ]
    if organization_filter:
        organization_value = organization_filter.strip().lower()
        findings = [
            finding for finding in findings
            if isinstance(finding, dict) and str(finding.get("organization") or "").strip().lower() == organization_value
        ]

    repo_metrics: dict[str, dict[str, Any]] = {}
    detected_by_month: dict[str, int] = {}
    resolved_by_month: dict[str, int] = {}
    false_positive_by_month: dict[str, int] = {}
    triaged_by_month: dict[str, int] = {}
    confirmed_by_month: dict[str, int] = {}
    for finding in findings:
        organization = str(finding.get("organization") or "")
        repository = str(finding.get("repository") or "")
        repo_key = f"{organization.lower()}/{repository.lower()}"
        status = str(finding.get("reviewStatus") or "new")
        detected_at = str(finding.get("detectedAt") or "")
        month = detected_at[:7] if len(detected_at) >= 7 else "unknown"
        run_id = str(finding.get("runId") or "")

        metrics = repo_metrics.setdefault(
            repo_key,
            {
                "organization": organization,
                "repository": repository,
                "unreviewedCount": 0,
                "confirmedCount": 0,
                "runIds": set(),
                "lastSeenDate": "",
            },
        )
        if status == "new":
            metrics["unreviewedCount"] += 1
        elif status == "confirmed":
            metrics["confirmedCount"] += 1
        if run_id:
            metrics["runIds"].add(run_id)
        if detected_at > metrics["lastSeenDate"]:
            metrics["lastSeenDate"] = detected_at

        if month != "unknown" and status != "false_positive":
            detected_by_month[month] = detected_by_month.get(month, 0) + 1
        if status == "action_taken":
            resolved_at = str(finding.get("resolvedAt") or "")
            resolved_month = resolved_at[:7] if len(resolved_at) >= 7 else month
            if resolved_month != "unknown":
                resolved_by_month[resolved_month] = resolved_by_month.get(resolved_month, 0) + 1
                triaged_by_month[resolved_month] = triaged_by_month.get(resolved_month, 0) + 1
        elif status == "confirmed" and month != "unknown":
            confirmed_by_month[month] = confirmed_by_month.get(month, 0) + 1
        elif status == "false_positive" and month != "unknown":
            false_positive_by_month[month] = false_positive_by_month.get(month, 0) + 1

    triage_priority = []
    for metrics in repo_metrics.values():
        repeat_offender = len(metrics["runIds"]) >= 3
        urgency_score = (metrics["unreviewedCount"] * 3) + (metrics["confirmedCount"] * 2) + (5 if repeat_offender else 0)
        triage_priority.append(
            {
                "organization": metrics["organization"],
                "repository": metrics["repository"],
                "unreviewedCount": metrics["unreviewedCount"],
                "confirmedCount": metrics["confirmedCount"],
                "repeatOffender": repeat_offender,
                "lastSeenDate": metrics["lastSeenDate"] or None,
                "urgencyScore": urgency_score,
            }
        )

    triage_priority.sort(
        key=lambda item: (
            -int(item["urgencyScore"]),
            str(item["organization"]).lower(),
            str(item["repository"]).lower(),
        )
    )
    all_months = sorted(set(detected_by_month) | set(resolved_by_month) | set(false_positive_by_month) | set(triaged_by_month) | set(confirmed_by_month))
    trend: list[dict[str, Any]] = []
    cumulative_unresolved = 0
    cumulative_resolved = 0
    cumulative_false_positive = 0
    cumulative_confirmed = 0
    for month in all_months:
        newly_detected = detected_by_month.get(month, 0)
        resolved = resolved_by_month.get(month, 0)
        false_positive = false_positive_by_month.get(month, 0)
        triaged = triaged_by_month.get(month, 0)
        confirmed = confirmed_by_month.get(month, 0)
        cumulative_unresolved += newly_detected - resolved
        cumulative_resolved += resolved
        cumulative_false_positive += false_positive
        cumulative_confirmed += confirmed
        trend.append(
            {
                "month": month,
                "newlyDetected": newly_detected,
                "resolved": resolved,
                "triaged": triaged,
                "falsePositive": false_positive,
                "endOfMonth": {
                    "unresolved": cumulative_unresolved,
                    "resolved": cumulative_resolved,
                    "falsePositive": cumulative_false_positive,
                    "confirmed": cumulative_confirmed,
                },
            }
        )
    return {"triagePriority": triage_priority, "trend": trend}


def _duration_seconds(started_at: str | None, finished_at: str | None) -> int | None:
    start = _parse_iso_datetime(started_at)
    end = _parse_iso_datetime(finished_at)
    if not start or not end:
        return None
    return max(0, int((end - start).total_seconds()))


def _scanner_status(count: int, baseline: float) -> str:
    if count == 0:
        return "red"
    if baseline > 0 and count < (baseline * 0.5):
        return "amber"
    return "green"


def build_health_payload(
    orgs: list[str],
    *,
    read_checkpoints: Callable[[str], dict[str, dict[str, Any]]],
    stale_after_days: int = 7,
) -> dict[str, Any]:
    snapshot = load_snapshot(orgs)
    findings = _extract_findings(snapshot)
    now_dt = datetime.now(timezone.utc)

    all_runs: list[dict[str, Any]] = []
    combined_checkpoints: dict[str, dict[str, Any]] = {}
    for org in orgs:
        all_runs.extend(list_secret_runs(org))
        for repo, checkpoint in read_checkpoints(org).items():
            combined_checkpoints[repo] = checkpoint

    all_runs.sort(key=lambda run: str(run.get("createdAt") or ""), reverse=True)
    recent_runs = all_runs[:20]

    findings_by_run: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        run_id = str(finding.get("runId") or "")
        if not run_id:
            continue
        findings_by_run.setdefault(run_id, []).append(finding)

    run_history = [
        {
            **run,
            "durationSeconds": _duration_seconds(run.get("startedAt"), run.get("finishedAt")),
            "distinctFindingsCount": len({
                str(f.get("fingerprint") or f.get("id") or "")
                for f in findings_by_run.get(str(run.get("id") or ""), [])
                if f.get("fingerprint") or f.get("id")
            }),
        }
        for run in recent_runs
    ]

    coverage_gaps: list[dict[str, Any]] = []
    snapshot_repos = {str(finding.get("repository") or "").strip() for finding in findings if str(finding.get("repository") or "").strip()}
    for repo in sorted(snapshot_repos):
        if repo not in combined_checkpoints:
            coverage_gaps.append({"repository": repo, "reason": "missing_checkpoint", "lastScannedAt": None})
    for repo, checkpoint in sorted(combined_checkpoints.items()):
        last_scanned_at = checkpoint.get("lastScannedAt") if isinstance(checkpoint, dict) else None
        scanned_dt = _parse_iso_datetime(last_scanned_at if isinstance(last_scanned_at, str) else None)
        if now_dt and scanned_dt and (now_dt - scanned_dt).days > stale_after_days:
            coverage_gaps.append({"repository": repo, "reason": "stale", "lastScannedAt": last_scanned_at})
    coverage_gaps.sort(
        key=lambda item: (
            0 if item.get("reason") == "stale" else 1,
            str(item.get("repository") or "").lower(),
        )
    )

    raw_hit_rates: list[dict[str, Any]] = []
    betterleaks_total = 0
    trufflehog_total = 0
    counted_runs = 0
    for run in run_history:
        run_findings = findings_by_run.get(str(run.get("id") or ""), [])
        betterleaks_count = sum(1 for finding in run_findings if str(finding.get("source") or "").lower() == "betterleaks")
        trufflehog_count = sum(1 for finding in run_findings if str(finding.get("source") or "").lower() == "trufflehog")
        betterleaks_total += betterleaks_count
        trufflehog_total += trufflehog_count
        counted_runs += 1
        raw_hit_rates.append(
            {
                "runId": run.get("id"),
                "organization": run.get("organization"),
                "createdAt": run.get("createdAt"),
                "betterleaksCount": betterleaks_count,
                "trufflehogCount": trufflehog_count,
            }
        )

    betterleaks_baseline = (betterleaks_total / counted_runs) if counted_runs else 0
    trufflehog_baseline = (trufflehog_total / counted_runs) if counted_runs else 0
    scanner_hit_rates = [
        {
            **item,
            "betterleaksStatus": _scanner_status(int(item["betterleaksCount"]), betterleaks_baseline),
            "trufflehogStatus": _scanner_status(int(item["trufflehogCount"]), trufflehog_baseline),
        }
        for item in raw_hit_rates
    ]

    return {
        "empty": len(run_history) == 0 and len(coverage_gaps) == 0 and len(scanner_hit_rates) == 0,
        "runHistory": run_history,
        "coverageGaps": coverage_gaps,
        "scannerHitRates": scanner_hit_rates,
    }
