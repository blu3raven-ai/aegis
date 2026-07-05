"""SLA service: policy CRUD, breach computation, recompute, and breach summary."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Finding, FindingSlaStatus, SlaPolicy as SlaPolicyRow
from src.sla.policy import DEFAULT_POLICIES, SlaPolicy, VALID_SEVERITIES

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _policy_to_dict(row: SlaPolicyRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "severity": row.severity,
        "deadline_days": row.deadline_days,
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


class SlaService:
    # ── Policy CRUD ──────────────────────────────────────────────────────────

    def get_policies(self) -> list[dict[str, Any]]:
        """Return all four severity policies.

        Defaults are returned in-memory for any severity without a persisted
        row; upsert happens on first PUT.
        """
        async def _q(session):
            result = await session.execute(
                select(SlaPolicyRow).order_by(SlaPolicyRow.severity)
            )
            return result.scalars().all()

        rows = run_db(_q)
        existing = {r.severity: r for r in rows}
        out = []
        for default in DEFAULT_POLICIES:
            if default.severity in existing:
                out.append(_policy_to_dict(existing[default.severity]))
            else:
                out.append({
                    "id": None,
                    "severity": default.severity,
                    "deadline_days": default.deadline_days,
                    "enabled": default.enabled,
                    "created_at": None,
                    "updated_at": None,
                })
        return out

    def update_policy(self, severity: str, deadline_days: int, enabled: bool) -> dict[str, Any]:
        """Upsert a single SLA policy row for the given severity."""
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        if deadline_days <= 0:
            raise ValueError("deadline_days must be greater than 0")

        now = _utcnow()

        async def _q(session):
            result = await session.execute(
                select(SlaPolicyRow).where(SlaPolicyRow.severity == severity)
            )
            row = result.scalar_one_or_none()
            if row is None:
                row = SlaPolicyRow(
                    severity=severity,
                    deadline_days=deadline_days,
                    enabled=enabled,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.deadline_days = deadline_days
                row.enabled = enabled
                row.updated_at = now
            await session.commit()
            await session.refresh(row)
            return row

        row = run_db(_q)
        return _policy_to_dict(row)

    # ── Breach computation ────────────────────────────────────────────────────

    def compute_finding_status(self, finding: Finding, policy: SlaPolicy | None) -> dict[str, Any]:
        """Compute breach status for a single finding given its SLA policy.

        Returns a dict that mirrors the FindingSlaStatus schema.
        A None policy (disabled / missing) means no deadline — never breached.
        """
        now = _utcnow()
        if policy is None or not policy.enabled:
            return {
                "finding_id": finding.id,
                "deadline_at": None,
                "breached": False,
                "breach_age_days": None,
                "computed_at": now,
            }

        first_seen = finding.first_seen_at
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)

        deadline_at = first_seen + timedelta(days=policy.deadline_days)
        breached = now > deadline_at
        breach_age_days = max(0, (now - deadline_at).days) if breached else None

        return {
            "finding_id": finding.id,
            "deadline_at": deadline_at,
            "breached": breached,
            "breach_age_days": breach_age_days,
            "computed_at": now,
        }

    def recompute(self, *, asset_ids: list[str]) -> int:
        """Recompute SLA breach status. Returns count of status rows written."""
        if not asset_ids:
            return 0

        policies = self._load_policies_map()

        async def _fetch(session):
            stmt = (
                select(Finding)
                .where(
                    Finding.state.not_in(["fixed", "dismissed"]),
                    Finding.asset_id.in_(asset_ids),
                )
            )
            result = await session.execute(stmt)
            return result.scalars().all()

        findings = run_db(_fetch)

        statuses = []
        for finding in findings:
            sev = (finding.severity or "").lower()
            policy = policies.get(sev)
            status = self.compute_finding_status(finding, policy)
            statuses.append(status)

        if not statuses:
            return 0

        now = _utcnow()

        async def _upsert(session):
            for s in statuses:
                existing = await session.get(FindingSlaStatus, s["finding_id"])
                if existing is None:
                    row = FindingSlaStatus(
                        finding_id=s["finding_id"],
                        deadline_at=s["deadline_at"],
                        breached=s["breached"],
                        breach_age_days=s["breach_age_days"],
                        computed_at=now,
                    )
                    session.add(row)
                else:
                    existing.deadline_at = s["deadline_at"]
                    existing.breached = s["breached"]
                    existing.breach_age_days = s["breach_age_days"]
                    existing.computed_at = now
            await session.commit()

        run_db(_upsert)
        return len(statuses)

    def get_breach_summary(self, *, asset_ids: list[str]) -> dict[str, Any]:
        """Aggregate open/breached counts per severity."""
        rows: list = []
        if asset_ids:
            async def _q(session):
                stmt = (
                    select(Finding.severity, FindingSlaStatus.breached)
                    .join(FindingSlaStatus, FindingSlaStatus.finding_id == Finding.id)
                    .where(
                        Finding.state.not_in(["fixed", "dismissed"]),
                        Finding.asset_id.in_(asset_ids),
                    )
                )
                result = await session.execute(stmt)
                return result.all()

            rows = run_db(_q)

        counts: dict[str, dict[str, int]] = {
            sev: {"open": 0, "breached": 0}
            for sev in ("critical", "high", "medium", "low")
        }
        for severity, breached in rows:
            sev = (severity or "unknown").lower()
            if sev not in counts:
                continue
            counts[sev]["open"] += 1
            if breached:
                counts[sev]["breached"] += 1

        summary: dict[str, Any] = {}
        for sev, c in counts.items():
            open_count = c["open"]
            breached_count = c["breached"]
            pct = round(breached_count / open_count, 4) if open_count > 0 else 0.0
            summary[sev] = {
                "open": open_count,
                "breached": breached_count,
                "breached_pct": pct,
            }
        return summary

    def summary_by_asset_ids(self, asset_ids: list[str]) -> dict[str, Any]:
        return self.get_breach_summary(asset_ids=asset_ids)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load_policies_map(self) -> dict[str, SlaPolicy]:
        """Load enabled policies as a severity → SlaPolicy dict.

        Falls back to DEFAULT_POLICIES for any severity not in the DB.
        """
        rows_data = self.get_policies()
        result: dict[str, SlaPolicy] = {}
        for d in rows_data:
            result[d["severity"]] = SlaPolicy(
                severity=d["severity"],
                deadline_days=d["deadline_days"],
                enabled=d["enabled"],
            )
        return result


_service = SlaService()


def get_sla_service() -> SlaService:
    return _service
