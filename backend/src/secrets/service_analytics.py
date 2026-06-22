from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any


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
