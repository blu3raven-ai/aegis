"""Notification emitter — creates DB records and publishes SSE events.

Central place for all notification emission. Call these functions from
event hook points (scan complete, runner offline, source sync, etc.).
"""
from __future__ import annotations

import html
import logging
from typing import Any

from src.notifications.store import emit_notification, emit_notification_to_all
from src.shared.event_bus import Event, get_event_bus

logger = logging.getLogger(__name__)

from src.shared.ttl_cache import TtlCache

_user_cache = TtlCache(ttl_seconds=30)

TOOL_LABELS = {
    "dependencies": "Dependencies",
    "code_scanning": "Code Scanning",
    "secrets": "Secrets",
    "container_scanning": "Containers",
}


def _get_active_user_ids() -> list[str]:
    """Get all active user IDs for broadcast notifications. Cached 30s."""
    cached = _user_cache.get("active_users")
    if cached is not None:
        return cached

    from src.db.helpers import run_db
    from src.db.models import User
    from sqlalchemy import select

    async def _query(session):
        result = await session.execute(
            select(User.id).where(User.status == "active")
        )
        return [row[0] for row in result.all()]

    ids = run_db(_query)
    _user_cache.set("active_users", ids)
    return ids


def _get_admin_user_ids() -> list[str]:
    """Get admin/owner user IDs for admin-only notifications. Cached 30s."""
    cached = _user_cache.get("admin_users")
    if cached is not None:
        return cached

    from src.db.helpers import run_db
    from src.db.models import User
    from sqlalchemy import select

    async def _query(session):
        result = await session.execute(
            select(User.id).where(
                User.status == "active",
                User.role.in_(["owner", "admin"]),
            )
        )
        return [row[0] for row in result.all()]

    ids = run_db(_query)
    _user_cache.set("admin_users", ids)
    return ids


def _publish_notification_sse(notif: dict[str, Any], require_admin: bool = False) -> None:
    """Publish a notification.new SSE event."""
    get_event_bus().publish_sync(Event(
        event_type="notification.new",
        data={
            "id": notif.get("id", ""),
            "title": notif.get("title", ""),
            "severity": notif.get("severity", "info"),
            "category": notif.get("category", ""),
            "message": notif.get("message", ""),
        },
        require_admin=require_admin,
    ))


# ── Scan lifecycle ────────────────────────────────────────────────────────────


def notify_scan_completed(
    tool: str,
    org: str,
    run_id: str,
    counts: dict[str, int] | None = None,
) -> None:
    """Emit notification when a scan completes successfully."""
    label = TOOL_LABELS.get(tool, tool)
    counts = counts or {}
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    total = counts.get("total", 0)

    if critical > 0:
        severity = "critical"
        summary = f"{critical} critical, {high} high"
    elif high > 0:
        severity = "warning"
        summary = f"{high} high"
    else:
        severity = "success"
        summary = f"{total} findings"

    title = f"{label} scan completed"
    message = f"{label} scan for {org} completed — {summary}"
    link = f"/{_tool_to_path(tool)}/dashboard"

    try:
        user_ids = _get_active_user_ids()
        emit_notification_to_all(
            user_ids,
            notification_type="scan.completed",
            category="scan",
            severity=severity,
            title=title,
            message=message,
            context={"tool": tool, "org": org, "runId": run_id, "counts": counts},
            link=link,
        )
        _publish_notification_sse({"title": title, "severity": severity, "category": "scan", "message": message})
    except Exception:
        logger.warning("Failed to emit scan completed notification", exc_info=True)


def notify_scan_failed(tool: str, org: str, run_id: str, error: str) -> None:
    """Emit notification when a scan fails."""
    label = TOOL_LABELS.get(tool, tool)
    title = f"{label} scan failed"
    message = f"{label} scan for {org} failed: {html.escape(error[:200])}"
    link = f"/{_tool_to_path(tool)}/dashboard"

    try:
        user_ids = _get_active_user_ids()
        emit_notification_to_all(
            user_ids,
            notification_type="scan.failed",
            category="scan",
            severity="error",
            title=title,
            message=message,
            context={"tool": tool, "org": org, "runId": run_id, "error": error[:500]},
            link=link,
        )
        _publish_notification_sse({"title": title, "severity": "error", "category": "scan", "message": message})
    except Exception:
        logger.warning("Failed to emit scan failed notification", exc_info=True)


# ── Finding alerts ────────────────────────────────────────────────────────────


def notify_new_critical_findings(
    tool: str,
    org: str,
    findings: list[dict[str, Any]],
) -> None:
    """Emit notification for new critical/high findings discovered during a scan."""
    critical = [f for f in findings if _finding_severity(f) == "critical"]
    high = [f for f in findings if _finding_severity(f) == "high"]

    if not critical and not high:
        return

    label = TOOL_LABELS.get(tool, tool)
    count = len(critical) + len(high)
    severity = "critical" if critical else "warning"

    if critical and high:
        title = f"{len(critical)} critical + {len(high)} high findings"
    elif critical:
        title = f"{len(critical)} new critical finding{'s' if len(critical) > 1 else ''}"
    else:
        title = f"{len(high)} new high finding{'s' if len(high) > 1 else ''}"

    # Show top finding as detail
    top = (critical or high)[0]
    pkg = _finding_label(top)
    detail = f" — {pkg}" if pkg else ""
    message = f"{label} scan for {org}: {title}{detail}"
    link = f"/{_tool_to_path(tool)}/dashboard"

    try:
        user_ids = _get_active_user_ids()
        emit_notification_to_all(
            user_ids,
            notification_type="finding.new",
            category="finding",
            severity=severity,
            title=title,
            message=message,
            context={"tool": tool, "org": org, "count": count},
            link=link,
        )
        _publish_notification_sse({"title": title, "severity": severity, "category": "finding", "message": message})
    except Exception:
        logger.warning("Failed to emit new findings notification", exc_info=True)


# ── System: Runner ────────────────────────────────────────────────────────────


def notify_runner_offline(runner_id: str, runner_name: str) -> None:
    """Emit notification when a runner goes offline."""
    title = f"Runner '{runner_name}' went offline"
    message = f"Runner '{runner_name}' has not sent a heartbeat and is now offline."

    try:
        admin_ids = _get_admin_user_ids()
        emit_notification_to_all(
            admin_ids,
            notification_type="runner.offline",
            category="system",
            severity="warning",
            title=title,
            message=message,
            context={"runnerId": runner_id, "runnerName": runner_name},
            link="/settings/runners",
        )
        _publish_notification_sse(
            {"title": title, "severity": "warning", "category": "system", "message": message},
            require_admin=True,
        )
    except Exception:
        logger.warning("Failed to emit runner offline notification", exc_info=True)


# ── System: Source sync ───────────────────────────────────────────────────────


def notify_source_synced(
    connection_id: str,
    connection_name: str,
    success: bool,
    message: str,
    discovered_count: int | None = None,
) -> None:
    """Emit notification when a source sync completes or fails."""
    if success:
        title = f"Source '{connection_name}' synced"
        detail = f" — {discovered_count} items discovered" if discovered_count else ""
        body = f"{connection_name} synced successfully{detail}"
        severity = "success"
    else:
        title = f"Source '{connection_name}' sync failed"
        body = f"{connection_name}: {message[:200]}"
        severity = "error"

    try:
        admin_ids = _get_admin_user_ids()
        emit_notification_to_all(
            admin_ids,
            notification_type="source.synced",
            category="system",
            severity=severity,
            title=title,
            message=body,
            context={"connectionId": connection_id, "success": success},
            link="/settings/sources/code-repositories",
        )
        _publish_notification_sse(
            {"title": title, "severity": severity, "category": "system", "message": body},
            require_admin=True,
        )
    except Exception:
        logger.warning("Failed to emit source sync notification", exc_info=True)


# ── Settings ──────────────────────────────────────────────────────────────────


def notify_settings_changed(tool: str, actor: str) -> None:
    """Emit notification when tool settings are changed."""
    label = TOOL_LABELS.get(tool, tool)
    title = f"{label} settings updated"
    message = f"{label} settings were updated by {actor}"
    link = f"/{_tool_to_path(tool)}/dashboard?tab=settings"

    try:
        user_ids = _get_admin_user_ids()
        emit_notification_to_all(
            user_ids,
            notification_type="settings.changed",
            category="settings",
            severity="info",
            title=title,
            message=message,
            context={"tool": tool, "actor": actor},
            link=link,
        )
        _publish_notification_sse({"title": title, "severity": "info", "category": "settings", "message": message})
    except Exception:
        logger.warning("Failed to emit settings changed notification", exc_info=True)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _tool_to_path(tool: str) -> str:
    return {
        "dependencies": "dependencies",
        "code_scanning": "code",
        "secrets": "secrets",
        "container_scanning": "containers",
    }.get(tool, tool)


def _finding_severity(f: dict[str, Any]) -> str:
    # SCA/Container findings: security_advisory.severity
    adv = f.get("security_advisory") or {}
    sev = adv.get("severity")
    if sev:
        return sev
    # SAST findings: severity field directly
    sev = f.get("severity")
    if sev:
        return sev
    # Secret findings: no severity in raw dict — default to "high"
    # (verified secrets are treated as critical by the lifecycle hook)
    if f.get("detector") or f.get("secretIdentity"):
        classification = f.get("classificationHistory") or []
        for entry in classification:
            if isinstance(entry, dict) and entry.get("value") == "verified_secret":
                return "critical"
        return "high"
    return ""


def _finding_label(f: dict[str, Any]) -> str:
    """Human-readable label for a finding — works across all scanner types."""
    # SCA/Container: package name
    dep = f.get("dependency") or {}
    pkg = dep.get("package") or {}
    name = pkg.get("name") or f.get("package_name")
    if name:
        return name
    # SAST: rule name or ID
    rule = f.get("rule_name") or f.get("rule_id") or f.get("ruleId")
    if rule:
        return rule
    # Secrets: detector name
    detector = f.get("detector") or f.get("DetectorName")
    if detector:
        return detector
    return ""
