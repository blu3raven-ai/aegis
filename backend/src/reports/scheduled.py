"""Service layer for scheduled_reports CRUD."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import NotificationDestination, ScheduledReport


_ALLOWED_REPORT_TYPES = {"findings", "posture"}
_ALLOWED_FORMATS = {"pdf", "csv", "json"}
_ALLOWED_SCHEDULE_TYPES = {"simple", "cron"}


class ScheduledReportNotFound(Exception):
    pass


def _validate_create_payload(payload: dict) -> dict:
    if payload.get("report_type") not in _ALLOWED_REPORT_TYPES:
        raise ValueError("report_type must be 'findings' or 'posture'")
    if payload.get("format") not in _ALLOWED_FORMATS:
        raise ValueError("format must be one of pdf, csv, json")
    if payload["report_type"] == "posture" and payload["format"] == "csv":
        raise ValueError("posture reports do not support csv format")
    if payload.get("schedule_type") not in _ALLOWED_SCHEDULE_TYPES:
        raise ValueError("schedule_type must be 'simple' or 'cron'")
    if not (payload.get("schedule_value") or "").strip():
        raise ValueError("schedule_value is required")
    if not (payload.get("name") or "").strip():
        raise ValueError("name is required")
    return payload


def _serialize(sr: ScheduledReport) -> dict[str, Any]:
    return {
        "id": sr.id,
        "name": sr.name,
        "report_type": sr.report_type,
        "format": sr.format,
        "schedule_type": sr.schedule_type,
        "schedule_value": sr.schedule_value,
        "filters": sr.filters or {},
        "destination_ids": list(sr.destination_ids or []),
        "created_by": sr.created_by,
        "enabled": sr.enabled,
        "last_run_at": sr.last_run_at.isoformat() if sr.last_run_at else None,
        "last_run_status": sr.last_run_status,
        "last_run_error": sr.last_run_error,
        "created_at": sr.created_at.isoformat(),
        "updated_at": sr.updated_at.isoformat(),
    }


def create_schedule(payload: dict, *, created_by: str, asset_ids: list[str]) -> dict:
    _validate_create_payload(payload)

    async def _query(session: AsyncSession) -> dict:
        dest_ids = payload.get("destination_ids") or []
        if dest_ids:
            rows = (await session.execute(
                select(NotificationDestination.id).where(NotificationDestination.id.in_(dest_ids))
            )).scalars().all()
            missing = set(dest_ids) - set(rows)
            if missing:
                raise ValueError(f"unknown destination_ids: {sorted(missing)}")

        # Freeze the creator's asset scope so the scheduler tick can fan out
        # without re-resolving auth.
        filters = dict(payload.get("filters") or {})
        filters["asset_ids"] = list(asset_ids)

        sr = ScheduledReport(
            name=payload["name"].strip(),
            report_type=payload["report_type"],
            format=payload["format"],
            schedule_type=payload["schedule_type"],
            schedule_value=payload["schedule_value"].strip(),
            filters=filters,
            destination_ids=list(dest_ids),
            created_by=created_by,
            enabled=payload.get("enabled", True),
        )
        session.add(sr)
        await session.flush()
        return _serialize(sr)

    return run_db(_query)


def list_schedules() -> list[dict]:
    async def _query(session: AsyncSession) -> list[dict]:
        rows = (await session.execute(
            select(ScheduledReport).order_by(ScheduledReport.created_at.desc())
        )).scalars().all()
        return [_serialize(r) for r in rows]

    return run_db(_query)


def get_schedule(schedule_id: int) -> dict | None:
    async def _query(session: AsyncSession) -> dict | None:
        sr = await session.get(ScheduledReport, schedule_id)
        return _serialize(sr) if sr else None

    return run_db(_query)


def update_schedule(schedule_id: int, patch: dict) -> dict:
    """Partial update. Pass any subset of mutable fields."""
    mutable = {
        "name", "report_type", "format", "schedule_type", "schedule_value",
        "filters", "destination_ids", "enabled",
    }
    invalid = set(patch) - mutable
    if invalid:
        raise ValueError(f"cannot update fields: {sorted(invalid)}")

    async def _query(session: AsyncSession) -> dict:
        sr = await session.get(ScheduledReport, schedule_id)
        if sr is None:
            raise ScheduledReportNotFound(str(schedule_id))

        if "destination_ids" in patch:
            dest_ids = patch["destination_ids"]
            if dest_ids:
                rows = (await session.execute(
                    select(NotificationDestination.id).where(NotificationDestination.id.in_(dest_ids))
                )).scalars().all()
                missing = set(dest_ids) - set(rows)
                if missing:
                    raise ValueError(f"unknown destination_ids: {sorted(missing)}")
            sr.destination_ids = list(dest_ids)

        for field in mutable - {"destination_ids"}:
            if field in patch:
                value = patch[field]
                if field in ("name", "schedule_value") and isinstance(value, str):
                    value = value.strip()
                setattr(sr, field, value)

        sr.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _serialize(sr)

    return run_db(_query)


def delete_schedule(schedule_id: int) -> bool:
    async def _query(session: AsyncSession) -> bool:
        sr = await session.get(ScheduledReport, schedule_id)
        if sr is None:
            return False
        await session.delete(sr)
        return True

    return run_db(_query)
