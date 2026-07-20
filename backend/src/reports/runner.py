"""Background runner for scheduled reports.

Invoked by scheduler._tick once per minute. Loads enabled schedules, runs the
ones whose schedule matches the current minute, and delivers via the existing
notification destinations.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import NotificationDestination, Report, ScheduledReport

logger = logging.getLogger(__name__)


def _build_payload(*, schedule: ScheduledReport, report: Report, download_url: str | None) -> dict[str, Any]:
    subject = f"[Aegis] Scheduled report: {schedule.name}"
    if download_url:
        body = (
            f"Your scheduled report '{schedule.name}' is ready.\n\n"
            f"Download: {download_url}\n\n"
            f"Expires: {report.expires_at.isoformat() if report.expires_at else 'unknown'}"
        )
    else:
        body = (
            f"Scheduled report '{schedule.name}' generation completed, but no download "
            "URL is available. Contact an admin."
        )
    return {"subject": subject, "body": body, "text": body}


def _send_to_destination(dest: NotificationDestination, payload: dict, schedule: ScheduledReport, report: Report) -> dict:
    from src.notifications.senders.email import EmailSender
    from src.notifications.senders.slack import SlackSender
    from src.notifications.senders.webhook import GenericWebhookSender

    senders = {
        "email": EmailSender(),
        "slack": SlackSender(),
        "webhook": GenericWebhookSender(),
    }
    sender = senders.get(dest.destination_type)
    if sender is None:
        return {"status": "failed", "error": f"unsupported destination_type {dest.destination_type!r}"}

    result = sender.send(payload, dest.config)
    return {
        "status": "delivered" if result.success else "failed",
        "response_code": result.response_code,
        "error": result.error,
    }


def _deliver(schedule: ScheduledReport, report: Report, download_url: str | None) -> None:
    """Fan out delivery to each enabled destination. Failures are logged, not raised."""
    from src.notifications.destination import record_delivery

    payload = _build_payload(schedule=schedule, report=report, download_url=download_url)

    async def _query(session: AsyncSession) -> list[NotificationDestination]:
        if not schedule.destination_ids:
            return []
        rows = (await session.execute(
            select(NotificationDestination).where(
                NotificationDestination.id.in_(schedule.destination_ids),
                NotificationDestination.enabled.is_(True),
            )
        )).scalars().all()
        return list(rows)

    destinations = run_db(_query)
    event_id = f"scheduled_report:{schedule.id}:{report.id}"
    for dest in destinations:
        outcome = _send_to_destination(dest, payload, schedule, report)
        try:
            record_delivery(
                destination_id=dest.id,
                event_id=event_id,
                event_type="scheduled_report.delivered",
                status=outcome["status"],
                payload_summary=payload["subject"],
                response_code=outcome.get("response_code"),
                error=outcome.get("error"),
            )
        except Exception:
            logger.exception("Failed to record delivery for schedule=%s dest=%s", schedule.id, dest.id)


def _load_enabled_schedules() -> list[ScheduledReport]:
    async def _query(session: AsyncSession) -> list[ScheduledReport]:
        rows = (await session.execute(
            select(ScheduledReport).where(ScheduledReport.enabled.is_(True))
        )).scalars().all()
        return list(rows)

    return run_db(_query)


def _mark_run(schedule_id: int, *, status: str, error: str | None, now: datetime) -> None:
    async def _query(session: AsyncSession) -> None:
        sr = await session.get(ScheduledReport, schedule_id)
        if sr is None:
            return
        sr.last_run_at = now
        sr.last_run_status = status
        sr.last_run_error = error

    run_db(_query)


def _disable_schedule(schedule_id: int) -> None:
    async def _query(session: AsyncSession) -> None:
        sr = await session.get(ScheduledReport, schedule_id)
        if sr is None:
            return
        sr.enabled = False

    run_db(_query)


def _creator_live_scope(created_by: str) -> list[str]:
    """Re-resolve the creator's current asset grants at dispatch time.

    Extracted so tests can patch it without a live grant table. Empty for a
    disabled/removed creator or one with no remaining grants (fail-closed).
    """
    from src.authz.enforcement.scope import get_user_asset_ids
    from src.authz.roles.service import role_kind_from_id
    from src.db.models import User

    async def _resolve(session):
        creator = await session.get(User, created_by)
        if creator is None or creator.status != "active":
            return []
        return await get_user_asset_ids(
            session,
            {"user_id": created_by, "role": role_kind_from_id(creator.role_id)},
        )

    return run_db(_resolve)


def _ran_within_last_minute(schedule: ScheduledReport, now: datetime) -> bool:
    """Skip re-running a schedule that fired within the previous 55 seconds.

    Belt-and-suspenders against overlapping minute windows from delayed ticks.
    """
    if schedule.last_run_at is None:
        return False
    return (now - schedule.last_run_at).total_seconds() < 55


def run_due_schedules(*, now: datetime | None = None) -> int:
    """Find enabled schedules matching ``now``, generate + deliver each.

    Returns the number of schedules attempted (success + failure both count).
    """
    from src.reports.service import generate_report, get_download_url
    from src.scheduler import _matches_schedule

    now = now or datetime.now(timezone.utc)
    schedules = _load_enabled_schedules()

    attempted = 0
    for sr in schedules:
        if not _matches_schedule(sr.schedule_type, sr.schedule_value, now):
            continue
        if _ran_within_last_minute(sr, now):
            continue

        attempted += 1
        try:
            filters = dict(sr.filters or {})
            asset_ids = list(filters.pop("asset_ids", []))
            # Re-resolve the creator's live asset scope at dispatch time and
            # intersect with the snapshot frozen at schedule creation. A user
            # whose grants were revoked (or who was disabled) must not keep
            # receiving reports on assets they can no longer see.
            live_scope = set(_creator_live_scope(sr.created_by))
            asset_ids = [aid for aid in asset_ids if aid in live_scope]
            if not asset_ids:
                # Creator lost all grants on the scheduled assets — skip and
                # disable so it doesn't keep firing no-op runs.
                _mark_run(sr.id, status="skipped:revoked", error=None, now=now)
                _disable_schedule(sr.id)
                continue

            report = generate_report(
                report_type=sr.report_type,
                fmt=sr.format,
                title=sr.name,
                filters=filters or None,
                created_by=sr.created_by,
                asset_ids=asset_ids,
            )
            download_url = get_download_url(report)
            _deliver(sr, report, download_url)
            _mark_run(sr.id, status="success", error=None, now=now)
        except Exception as exc:
            logger.exception("Scheduled report %s failed", sr.id)
            _mark_run(sr.id, status="failed", error=str(exc)[:500], now=now)

    return attempted
