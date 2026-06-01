"""Unified finding lifecycle engine.

Decision table always wins — lifecycle never overwrites a human dismissal.
"""
from __future__ import annotations

import abc
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from src.db.helpers import run_db
from src.db.models import Finding, Decision
from src.shared.finding_queries import (
    insert_event,
    read_decisions_for_org,
    read_findings,
    update_finding_state,
    upsert_decision,
    upsert_finding,
    delete_decision,
)
from src.shared.paths import normalize_org
from src.shared.git_attribution import attribute_to_commit

VALID_DISMISS_REASONS: frozenset[str] = frozenset([
    "Fix started",
    "Risk is tolerable",
    "Alert is inaccurate",
    "Vulnerable code is not used",
])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LifecycleHooks(abc.ABC):
    """Scanner-specific hooks for the shared lifecycle engine."""

    tool: str  # 'dependencies', 'code_scanning', 'secrets', 'container_scanning'

    @abc.abstractmethod
    def compute_identity_key(self, raw: dict) -> str: ...

    @abc.abstractmethod
    def initial_state(self, raw: dict) -> str: ...

    @abc.abstractmethod
    def extract_repo(self, raw: dict) -> str | None: ...

    @abc.abstractmethod
    def extract_severity(self, raw: dict) -> str | None: ...

    @abc.abstractmethod
    def extract_detail(self, raw: dict) -> dict: ...

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return True

    def has_fix(self, raw: dict) -> bool:
        return False

    def extract_file_location(self, raw: dict) -> tuple[str, int] | None:
        """Return (file_path, line) for git blame attribution, or None if not applicable.

        Override in hooks for scanners that produce line-level findings. The
        default returns None, which skips attribution for that scanner.
        """
        return None


class ScanContext:

    def __init__(self, tool: str, org: str, run_id: str, **kwargs: Any):
        self.tool = tool
        self.org = normalize_org(org)
        self.run_id = run_id
        self.extra = kwargs


# PostgreSQL JSONB rejects null bytes and surrogate pairs
def _sanitize_for_pg(obj: Any) -> Any:
    if isinstance(obj, str):
        s = obj.replace("\x00", "")
        s = re.sub(r"[\ud800-\udfff]", "", s)
        return s
    if isinstance(obj, dict):
        return {_sanitize_for_pg(k): _sanitize_for_pg(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_pg(v) for v in obj]
    return obj

def _run_attribution(
    hooks: LifecycleHooks,
    raw: dict,
    checkout_path: Any,
) -> "tuple[str | None, str | None, Any, str | None]":
    """Attempt commit attribution for a new finding; return 4-tuple of attribution fields.

    Never raises — any failure returns (None, None, None, None) so the
    calling scan continues unimpeded.
    """
    if checkout_path is None:
        return None, None, None, None
    location = hooks.extract_file_location(raw)
    if location is None:
        return None, None, None, None
    file_path, line = location
    if not file_path or not line:
        return None, None, None, None
    try:
        from pathlib import Path as _Path
        attr = attribute_to_commit(_Path(checkout_path), file_path, line)
        if attr is None:
            return None, None, None, None
        return attr.commit_sha, attr.author_email, attr.authored_at, attr.pr_url
    except Exception:
        logger.debug("commit attribution failed", exc_info=True)
        return None, None, None, None


def apply_lifecycle(
    hooks: LifecycleHooks,
    ctx: ScanContext,
    current_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Diff current scan against DB state and apply transitions. Returns new findings."""
    new_findings: list[dict[str, Any]] = []
    checkout_path = ctx.extra.get("checkout_path")

    async def _run(session: AsyncSession) -> None:
        now = _utcnow()

        prev_findings = await read_findings(session, ctx.tool, ctx.org)
        prev_map: dict[str, Finding] = {f.identity_key: f for f in prev_findings}
        decision_map = await read_decisions_for_org(session, ctx.tool, ctx.org)
        curr_keys: set[str] = set()

        for raw in current_findings:
            key = hooks.compute_identity_key(raw)
            if not key:
                continue
            curr_keys.add(key)

            prev = prev_map.get(key)
            decision = decision_map.get(key)
            repo = hooks.extract_repo(raw)
            severity = hooks.extract_severity(raw)
            detail = _sanitize_for_pg(hooks.extract_detail(raw))

            if decision and decision.status == "dismissed":
                if prev:
                    prev.detail = detail
                    flag_modified(prev, "detail")
                    prev.severity = severity
                    prev.last_seen_at = now
                    prev.updated_at = now
                else:
                    f = await upsert_finding(
                        session, tool=ctx.tool, org=ctx.org, repo=repo,
                        identity_key=key, state="dismissed", severity=severity,
                        detail=detail, first_seen_at=now,
                    )
                    await insert_event(
                        session, finding_id=f.id, tool=ctx.tool, org=ctx.org,
                        identity_key=key, from_state=None, to_state="dismissed",
                        triggered_by="scan", actor=ctx.run_id,
                    )
                continue

            if prev:
                old_state = prev.state

                if old_state == "fixed":
                    new_state = hooks.initial_state(raw)
                    await update_finding_state(session, prev, new_state)
                    prev.detail = detail
                    flag_modified(prev, "detail")
                    prev.severity = severity
                    prev.last_seen_at = now
                    await insert_event(
                        session, finding_id=prev.id, tool=ctx.tool, org=ctx.org,
                        identity_key=key, from_state="fixed", to_state=new_state,
                        triggered_by="scan", actor=ctx.run_id,
                    )

                elif old_state == "deferred" and hooks.has_fix(raw):
                    await update_finding_state(session, prev, "open")
                    prev.detail = detail
                    flag_modified(prev, "detail")
                    prev.severity = severity
                    prev.last_seen_at = now
                    await insert_event(
                        session, finding_id=prev.id, tool=ctx.tool, org=ctx.org,
                        identity_key=key, from_state="deferred", to_state="open",
                        triggered_by="scan", actor=ctx.run_id,
                    )

                else:
                    prev.detail = detail
                    flag_modified(prev, "detail")
                    prev.severity = severity
                    prev.last_seen_at = now
                    prev.updated_at = now

            else:
                new_state = hooks.initial_state(raw)
                sha, author, authored_at, pr_url = _run_attribution(
                    hooks, raw, checkout_path
                )
                f = await upsert_finding(
                    session, tool=ctx.tool, org=ctx.org, repo=repo,
                    identity_key=key, state=new_state, severity=severity,
                    detail=detail, first_seen_at=now,
                    introduced_by_commit_sha=sha,
                    introduced_by_author=author,
                    introduced_at=authored_at,
                    introduced_by_pr_url=pr_url,
                )
                await insert_event(
                    session, finding_id=f.id, tool=ctx.tool, org=ctx.org,
                    identity_key=key, from_state=None, to_state=new_state,
                    triggered_by="scan", actor=ctx.run_id,
                )
                new_findings.append(raw)

        # Findings absent from current scan may be fixed
        for key, prev in prev_map.items():
            if key in curr_keys:
                continue

            decision = decision_map.get(key)
            if decision and decision.status == "dismissed":
                continue

            if prev.state in ("open", "deferred"):
                if not hooks.should_mark_fixed(key, prev.detail, **ctx.extra):
                    continue
                old_state = prev.state
                await update_finding_state(session, prev, "fixed", fixed_at=now)
                await insert_event(
                    session, finding_id=prev.id, tool=ctx.tool, org=ctx.org,
                    identity_key=key, from_state=old_state, to_state="fixed",
                    triggered_by="scan", actor=ctx.run_id,
                )

    run_db(_run)
    return new_findings


def dismiss_finding(
    tool: str,
    org: str,
    identity_key: str,
    reason: str,
    user_id: str,
    comment: str | None = None,
) -> None:
    """Dismiss a finding."""
    if reason not in VALID_DISMISS_REASONS:
        raise ValueError(f"Invalid dismiss reason {reason!r}")

    org = normalize_org(org)

    async def _run(session: AsyncSession) -> None:
        now = _utcnow()

        await upsert_decision(
            session, tool=tool, org=org, identity_key=identity_key,
            status="dismissed", reason=reason, comment=comment, decided_by=user_id,
        )

        result = await session.execute(
            select(Finding).where(
                Finding.tool == tool,
                Finding.org == org,
                Finding.identity_key == identity_key,
            )
        )
        finding = result.scalars().first()
        if finding and finding.state != "dismissed":
            old_state = finding.state
            finding.state = "dismissed"
            finding.updated_at = now
            await insert_event(
                session, finding_id=finding.id, tool=tool, org=org,
                identity_key=identity_key, from_state=old_state, to_state="dismissed",
                triggered_by="user", actor=user_id,
                metadata={"reason": reason, "comment": comment},
            )

    run_db(_run)


def reopen_finding(tool: str, org: str, identity_key: str, user_id: str) -> None:
    """Reopen a dismissed finding."""
    org = normalize_org(org)

    async def _run(session: AsyncSession) -> None:
        now = _utcnow()

        await delete_decision(session, tool, org, identity_key)

        result = await session.execute(
            select(Finding).where(
                Finding.tool == tool,
                Finding.org == org,
                Finding.identity_key == identity_key,
            )
        )
        finding = result.scalars().first()
        if finding and finding.state == "dismissed":
            finding.state = "open"
            finding.updated_at = now
            await insert_event(
                session, finding_id=finding.id, tool=tool, org=org,
                identity_key=identity_key, from_state="dismissed", to_state="open",
                triggered_by="user", actor=user_id,
            )

    run_db(_run)


def bulk_dismiss(
    tool: str,
    org: str,
    identity_keys: list[str],
    reason: str,
    user_id: str,
    comment: str | None = None,
) -> int:
    """Dismiss multiple findings in one transaction. Returns count updated."""
    if reason not in VALID_DISMISS_REASONS:
        raise ValueError(f"Invalid dismiss reason {reason!r}")

    org = normalize_org(org)
    updated = 0

    async def _run(session: AsyncSession) -> int:
        nonlocal updated
        now = _utcnow()

        for key in identity_keys:
            await upsert_decision(
                session, tool=tool, org=org, identity_key=key,
                status="dismissed", reason=reason, comment=comment, decided_by=user_id,
            )

            result = await session.execute(
                select(Finding).where(
                    Finding.tool == tool,
                    Finding.org == org,
                    Finding.identity_key == key,
                )
            )
            finding = result.scalars().first()
            if finding and finding.state != "dismissed":
                old_state = finding.state
                finding.state = "dismissed"
                finding.updated_at = now
                await insert_event(
                    session, finding_id=finding.id, tool=tool, org=org,
                    identity_key=key, from_state=old_state, to_state="dismissed",
                    triggered_by="user", actor=user_id,
                    metadata={"reason": reason, "comment": comment},
                )
                updated += 1
        return updated

    run_db(_run)
    return updated
