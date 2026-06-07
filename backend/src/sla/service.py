"""SLA service: policy CRUD, breach computation, org recompute, and breach summary.

Org identity matches the rest of the codebase — a plain string slug stored on
each Finding. The service works directly with run_db for synchronous callers
(e.g. the scheduler) and returns plain dicts so routers can serialise freely.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, delete

from src.db.helpers import run_db
from src.db.models import Finding, FindingSlaStatus, SlaPolicy as SlaPolicyRow
from src.sla.policy import DEFAULT_POLICIES, SlaPolicy, VALID_SEVERITIES

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _policy_to_dict(row: SlaPolicyRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "org_id": row.org_id,
        "severity": row.severity,
        "deadline_days": row.deadline_days,
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


class SlaService:
    # ── Policy CRUD ──────────────────────────────────────────────────────────

    def get_policies(self, org_id: str) -> list[dict[str, Any]]:
        """Return all four severity policies for the org.

        If a policy row doesn't exist yet (e.g. org was created before Phase 47),
        a default policy is returned in-memory and silently upserted.
        """
        async def _q(session):
            result = await session.execute(
                select(SlaPolicyRow)
                .where(SlaPolicyRow.org_id == org_id)
                .order_by(SlaPolicyRow.severity)
            )
            return result.scalars().all()

        rows = run_db(_q)
        existing = {r.severity: r for r in rows}
        out = []
        for default in DEFAULT_POLICIES:
            if default.severity in existing:
                out.append(_policy_to_dict(existing[default.severity]))
            else:
                # Return default shape without persisting — upsert happens on first PUT
                out.append({
                    "id": None,
                    "org_id": org_id,
                    "severity": default.severity,
                    "deadline_days": default.deadline_days,
                    "enabled": default.enabled,
                    "created_at": None,
                    "updated_at": None,
                })
        return out

    def update_policy(self, org_id: str, severity: str, deadline_days: int, enabled: bool) -> dict[str, Any]:
        """Upsert a single SLA policy row for the given org + severity."""
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        if deadline_days <= 0:
            raise ValueError("deadline_days must be greater than 0")

        now = _utcnow()

        async def _q(session):
            result = await session.execute(
                select(SlaPolicyRow)
                .where(SlaPolicyRow.org_id == org_id, SlaPolicyRow.severity == severity)
            )
            row = result.scalar_one_or_none()
            if row is None:
                row = SlaPolicyRow(
                    org_id=org_id,
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

    def recompute_org(
        self, org_id: str | None = None, *, asset_ids: list[str] | None = None
    ) -> int:
        """Recompute SLA breach status for all active findings in the org.

        'Active' means state not in ('fixed', 'dismissed'). Returns count of
        status rows written.
        """
        if asset_ids is None and org_id is None:
            raise ValueError("either org_id or asset_ids is required")

        if org_id is not None:
            policies = self._load_policies_map(org_id)
        else:
            # No org-level policy lookup when scoping by asset_ids; use defaults.
            from src.sla.policy import DEFAULT_POLICIES
            policies = {
                p.severity: p for p in DEFAULT_POLICIES
            }

        async def _fetch(session):
            stmt = select(Finding).where(Finding.state.not_in(["fixed", "dismissed"]))
            if asset_ids is not None:
                if not asset_ids:
                    return []
                stmt = stmt.where(Finding.asset_id.in_(asset_ids))
            else:
                # Org-only callers no longer have a scope after Plan D; fail closed.
                return []
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

    def get_breach_summary(
        self, org_id: str | None = None, *, asset_ids: list[str] | None = None
    ) -> dict[str, Any]:
        """Aggregate open/breached counts per severity for the dashboard widget.

        Returns:
            {
              "critical": {"open": 12, "breached": 3, "breached_pct": 0.25},
              "high": {...},
              "medium": {...},
              "low": {...},
            }
        """
        if asset_ids is None and org_id is None:
            raise ValueError("either org_id or asset_ids is required")

        async def _q(session):
            stmt = (
                select(Finding.severity, FindingSlaStatus.breached)
                .join(FindingSlaStatus, FindingSlaStatus.finding_id == Finding.id)
                .where(Finding.state.not_in(["fixed", "dismissed"]))
            )
            if asset_ids is not None:
                if not asset_ids:
                    return []
                stmt = stmt.where(Finding.asset_id.in_(asset_ids))
            else:
                # Org-only callers no longer have a scope after Plan D; fail closed.
                return []
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
        """Aggregate open/breached counts per severity scoped by asset_ids."""
        async def _q(session):
            result = await session.execute(
                select(Finding.severity, FindingSlaStatus.breached)
                .join(FindingSlaStatus, FindingSlaStatus.finding_id == Finding.id)
                .where(
                    Finding.asset_id.in_(asset_ids),
                    Finding.state.not_in(["fixed", "dismissed"]),
                )
            )
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

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load_policies_map(self, org_id: str) -> dict[str, SlaPolicy]:
        """Load enabled policies as a severity → SlaPolicy dict.

        Falls back to DEFAULT_POLICIES for any severity not in the DB.
        """
        rows_data = self.get_policies(org_id)
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
