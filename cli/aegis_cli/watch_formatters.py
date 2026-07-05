"""Output formatters for `aegis watch`.

Two formats are supported: a pretty single-line representation suitable
for an interactive terminal, and a JSON-Lines representation suitable
for piping into jq or saving to disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from aegis_cli.output import _SEVERITY_COLORS

# Event types that represent a finding lifecycle transition.  Anything
# outside this set is filtered out by the CLI before formatting.
FINDING_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "finding.created",
        "finding.severity_changed",
        "finding.merged",
        "finding.closed",
    }
)


def _short_event_label(event_type: str) -> str:
    """Render the event type with a 7-char fixed prefix for column alignment."""
    short = event_type.removeprefix("finding.")
    return short[:8].upper()


def _extract_payload(message_data: dict[str, Any]) -> dict[str, Any]:
    """SSE bridge wraps the event in {event_id, payload}. Unwrap when present."""
    payload = message_data.get("payload")
    if isinstance(payload, dict):
        return payload
    return message_data


def format_pretty(event_type: str, message_data: dict[str, Any]) -> str:
    """Render a single SSE message as a Rich-markup line.

    Layout:  HH:MM:SS  EVENT       SEV       SCANNER         FINDING_ID
    """
    payload = _extract_payload(message_data)
    severity = (payload.get("severity") or "").lower()
    color = _SEVERITY_COLORS.get(severity, "")
    sev_text = f"[{color}]{severity.upper() or '-':<8}[/{color}]" if color else f"{severity.upper() or '-':<8}"

    scanner = (payload.get("scanner_type") or "").lower()
    finding_id = payload.get("finding_id") or "-"
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")

    return f"[dim]{ts}[/dim]  [bold]{_short_event_label(event_type):<8}[/bold]  {sev_text}  {scanner:<14}  {finding_id}"


def format_json(event_type: str, message_data: dict[str, Any]) -> str:
    """Render the event as a single-line JSON object for piping."""
    payload = _extract_payload(message_data)
    record = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "event_type": event_type,
        "event_id": message_data.get("event_id"),
        "finding_id": payload.get("finding_id"),
        "severity": payload.get("severity"),
        "scanner_type": payload.get("scanner_type"),
    }
    return json.dumps(record, separators=(",", ":"), default=str)


def matches_filters(
    event_type: str,
    message_data: dict[str, Any],
    *,
    severities: set[str] | None,
    scanners: set[str] | None,
    orgs: set[str] | None,
) -> bool:
    """Return True if the event passes every active filter.

    A None filter is interpreted as "any value passes".  Empty filter
    sets are treated the same as None to keep the call sites simple.
    """
    if event_type not in FINDING_EVENT_TYPES:
        return False

    payload = _extract_payload(message_data)

    if severities:
        sev = (payload.get("severity") or "").lower()
        if sev not in severities:
            return False
    if scanners:
        sc = (payload.get("scanner_type") or "").lower()
        if sc not in scanners:
            return False
    if orgs:
        org = payload.get("org_id") or payload.get("org") or message_data.get("org")
        if not org or org not in orgs:
            return False

    return True
