"""Helper utilities for the aegis triage subcommand.

Parsing, filtering, and display helpers are isolated here so the command
module stays focused on CLI wiring and the helpers stay easily testable
without Click.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any


# ---------------------------------------------------------------------------
# ID parsing
# ---------------------------------------------------------------------------

def parse_finding_ids(raw: str) -> list[str]:
    """Split a comma-separated finding-ID string, strip whitespace from each.

    >>> parse_finding_ids("F-1, F-2 , F-3")
    ['F-1', 'F-2', 'F-3']
    """
    return [fid.strip() for fid in raw.split(",") if fid.strip()]


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([hdw])$", re.IGNORECASE)

_UNIT_DAYS: dict[str, float] = {
    "h": 1 / 24,
    "d": 1.0,
    "w": 7.0,
}


def parse_duration(raw: str) -> int:
    """Convert a human duration string to whole days (rounded up).

    Supported units: h (hours), d (days), w (weeks).

    Examples:
        "30d"  -> 30
        "1w"   -> 7
        "1h"   -> 1   (rounds up to 1 day; smallest meaningful snooze unit)
        "2.5w" -> 18  (ceil of 17.5)

    Raises ValueError for unrecognised formats.
    """
    m = _DURATION_RE.match(raw.strip())
    if not m:
        raise ValueError(
            f"Cannot parse duration '{raw}'. "
            "Use a number followed by h (hours), d (days), or w (weeks), e.g. 30d, 1w, 12h."
        )
    amount, unit = float(m.group(1)), m.group(2).lower()
    fractional_days = amount * _UNIT_DAYS[unit]
    # Always round up — snoozing for less than a full day makes no sense
    return max(1, int(-(-fractional_days // 1)))  # math.ceil without import


# ---------------------------------------------------------------------------
# Timestamp-based filtering
# ---------------------------------------------------------------------------

def _parse_finding_created_at(finding: dict[str, Any]) -> datetime | None:
    """Extract a timezone-aware created_at from a finding dict.

    Handles both ISO-8601 strings and epoch integers, and tolerates missing
    or malformed values gracefully.
    """
    raw = finding.get("created_at") or finding.get("createdAt")
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def apply_filters(
    findings: list[dict[str, Any]],
    *,
    since: str | None = None,
) -> list[str]:
    """Return finding IDs from *findings* that pass all supplied filters.

    Currently supports:
      since — include only findings created more than <since> ago
              (e.g. "90d" keeps findings older than 90 days).

    The function always returns IDs, not full finding dicts, because bulk
    triage operations only need the identifier.
    """
    result_ids: list[str] = []
    cutoff: datetime | None = None

    if since is not None:
        days = parse_duration(since)
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    for f in findings:
        fid = f.get("id") or f.get("number") or f.get("alert_number")
        if not fid:
            continue

        if cutoff is not None:
            created = _parse_finding_created_at(f)
            # If we cannot determine age, include the finding conservatively.
            if created is not None and created > cutoff:
                continue  # too recent — skip

        result_ids.append(str(fid))

    return result_ids


# ---------------------------------------------------------------------------
# Summary formatting
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def _get_severity(finding: dict[str, Any]) -> str:
    from aegis_cli.client import _extract_severity  # local import avoids circular
    sev = _extract_severity(finding)
    return sev.lower() if sev else "unknown"


def format_summary(findings: list[dict[str, Any]]) -> str:
    """Return a one-line severity breakdown string.

    Example: "critical: 2  high: 5  medium: 3  low: 1"
    """
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = _get_severity(f)
        counts[sev] = counts.get(sev, 0) + 1

    parts = [
        f"{sev}: {counts[sev]}"
        for sev in _SEVERITY_ORDER
        if counts.get(sev, 0) > 0
    ]
    return "  ".join(parts) if parts else "0 findings"


# ---------------------------------------------------------------------------
# Confirmation prompt
# ---------------------------------------------------------------------------

def confirm_bulk_action(targets: list[str], *, action: str) -> bool:
    """Print a count summary and prompt the user to confirm the bulk action.

    Returns True if the user confirms, False otherwise.
    Uses Click's confirm() so it respects --yes flag at the call site.
    """
    import click

    count = len(targets)
    click.echo(f"About to {action} {count} finding(s): {', '.join(targets[:5])}"
               + (" …" if count > 5 else ""))
    return click.confirm(f"Proceed with {action}?", default=False)
