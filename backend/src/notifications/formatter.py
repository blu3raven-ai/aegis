"""Event → sender-specific payload formatters.

Each format_for_* function accepts the raw event dict and returns a dict
ready to pass to the corresponding sender.

Slack payloads use Block Kit (blocks + fallback text).
Webhook payloads are a structured JSON envelope.
Email payloads carry "subject" and "body" text keys.
"""
from __future__ import annotations

from typing import Any

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":large_blue_circle:",
    "info": ":white_circle:",
}

_EVENT_TITLES: dict[str, str] = {
    "finding.created": "New finding",
    "finding.severity_changed": "Finding severity changed",
    "intel.exploit_availability_changed": "Exploit availability changed",
    "intel.anomaly_detected": "Anomaly detected",
    "intel.cve_published": "CVE published",
}


def _event_title(event_type: str) -> str:
    return _EVENT_TITLES.get(event_type, event_type.replace(".", " ").title())


def _severity_from_payload(payload: dict[str, Any]) -> str:
    return (
        payload.get("severity")
        or payload.get("new_severity")
        or payload.get("old_severity")
        or "info"
    )


def _summary_line(event: dict[str, Any]) -> str:
    """Single-line human summary of any event, used across all formats."""
    et = event.get("event_type", "")
    payload = event.get("payload", {})
    org = event.get("org_id", "")

    if et in ("finding.created", "finding.severity_changed"):
        title = payload.get("title") or payload.get("rule_name") or payload.get("cve_id") or "finding"
        sev = _severity_from_payload(payload)
        return f"[{org}] {_event_title(et)}: {title} ({sev})"

    if et == "intel.exploit_availability_changed":
        cve = payload.get("cve_id", "")
        new = payload.get("new_availability", "")
        return f"[{org}] Exploit availability changed for {cve} → {new}"

    if et == "intel.anomaly_detected":
        scanner = payload.get("scanner_type", "unknown")
        mult = payload.get("multiplier", "")
        return f"[{org}] Anomaly: {scanner} findings spike ×{mult}"

    if et == "intel.cve_published":
        cve = payload.get("cve_id", "")
        sev = payload.get("severity", "")
        return f"[{org}] CVE published: {cve} ({sev})"

    return f"[{org}] {_event_title(et)}"


# ── Slack Block Kit ───────────────────────────────────────────────────────────


def format_for_slack(event: dict[str, Any]) -> dict[str, Any]:
    et = event.get("event_type", "")
    payload = event.get("payload", {})
    org = event.get("org_id", "")
    sev = _severity_from_payload(payload)
    emoji = _SEVERITY_EMOJI.get(sev, ":white_circle:")
    title = _event_title(et)
    summary = _summary_line(event)

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": summary},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"org: *{org}* | event: `{et}` | id: `{event.get('event_id', '')}`",
                }
            ],
        },
    ]

    # Add relevant payload fields as key-value fields block
    fields = _payload_fields(et, payload)
    if fields:
        blocks.insert(
            2,
            {
                "type": "section",
                "fields": [{"type": "mrkdwn", "text": f"*{k}*\n{v}"} for k, v in fields.items()],
            },
        )

    return {"text": summary, "blocks": blocks}


def _payload_fields(event_type: str, payload: dict[str, Any]) -> dict[str, str]:
    """Extracts the most useful payload fields for display per event type."""
    out: dict[str, str] = {}
    if event_type == "finding.created":
        if payload.get("tool"):
            out["Tool"] = payload["tool"]
        if payload.get("severity"):
            out["Severity"] = payload["severity"]
    elif event_type == "finding.severity_changed":
        old = payload.get("old_severity", "")
        new = payload.get("new_severity", "")
        if old or new:
            out["Severity change"] = f"{old} → {new}"
    elif event_type == "intel.exploit_availability_changed":
        if payload.get("cve_id"):
            out["CVE"] = payload["cve_id"]
        if payload.get("new_availability"):
            out["Availability"] = payload["new_availability"]
    elif event_type == "intel.anomaly_detected":
        if payload.get("scanner_type"):
            out["Scanner"] = payload["scanner_type"]
        if payload.get("multiplier"):
            out["Multiplier"] = f"×{payload['multiplier']}"
        if payload.get("window_count"):
            out["Count"] = str(payload["window_count"])
    return out


# ── Generic webhook JSON envelope ─────────────────────────────────────────────


def format_for_webhook(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "aegis",
        "event_id": event.get("event_id", ""),
        "event_type": event.get("event_type", ""),
        "org_id": event.get("org_id", ""),
        "timestamp_utc": event.get("timestamp_utc", ""),
        "summary": _summary_line(event),
        "payload": event.get("payload", {}),
    }


# ── Email text ────────────────────────────────────────────────────────────────


def format_for_email(event: dict[str, Any]) -> dict[str, Any]:
    et = event.get("event_type", "")
    org = event.get("org_id", "")
    summary = _summary_line(event)
    payload = event.get("payload", {})
    fields = _payload_fields(et, payload)

    subject = f"[Aegis] {_event_title(et)} — {org}"
    lines = [summary, "", "Details:"]
    for k, v in fields.items():
        lines.append(f"  {k}: {v}")
    lines += [
        "",
        f"Event ID: {event.get('event_id', '')}",
        f"Event type: {et}",
        f"Organisation: {org}",
        f"Timestamp: {event.get('timestamp_utc', '')}",
    ]

    return {"subject": subject, "body": "\n".join(lines)}
