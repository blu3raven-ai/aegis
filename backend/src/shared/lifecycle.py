"""Unified finding lifecycle engine.

Decision table always wins — lifecycle never overwrites a human dismissal
or an auto-rule dismissal. Auto-rule dismissals are written by the
auto-dismiss matcher (src.rules.auto_dismiss_matcher) during ingestion,
gated by org-wide kill switch and per-rule rate alarms.
"""
from __future__ import annotations

import abc
import logging
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from src.db.helpers import run_db
from src.db.models import Asset, Finding, Decision
from src.shared.finding_queries import (
    insert_event,
    read_decisions_for_asset,
    update_finding_state,
    upsert_decision,
    upsert_finding,
    delete_decision,
)
from src.assets.service import upsert_asset
from src.shared.paths import normalize_org
from src.shared.home_views_refresher import request_home_views_refresh

from src.rules.auto_dismiss_matcher import check_auto_dismiss_rules
from src.rules.rate_alarm import AUTO_DISMISS_EVENT_TRIGGERED_BY, auto_dismiss_event_actor
from src.rules_engine.subjects import RuleFindingSubject

logger = logging.getLogger(__name__)

VALID_DISMISS_REASONS: frozenset[str] = frozenset([
    "Fix started",
    "Risk is tolerable",
    "Alert is inaccurate",
    "Vulnerable code is not used",
    "Auto-dismissed by rule",
])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _maybe_set_engine(prev: Any, engine: str | None) -> None:
    # Preserve the existing engine column when this scan's raw entry has no
    # engine signal — never overwrite a known engine with NULL.
    if engine is not None:
        prev.engine = engine


def _apply_detail(prev: Any, tool: str, detail: dict) -> None:
    """Split detail, put fat to MinIO, set lean JSONB + blob key on the row.

    Mirrors the upsert_finding write path: empty fat clears any prior blob;
    non-empty fat overwrites the stable per-id blob.
    """
    from src.shared.finding_detail_blob import (
        split_detail,
        put_detail_blob,
        delete_detail_blob,
    )
    from src.shared.finding_queryable_fields import extract_queryable_fields

    # Extract typed-column values from full detail BEFORE split runs.
    queryable = extract_queryable_fields(detail)
    prev.cve_id = queryable["cve_id"]
    prev.file_path = queryable["file_path"]
    prev.title = queryable["title"]
    prev.rule_name = queryable["rule_name"]
    prev.package_name = queryable["package_name"]

    lean, fat = split_detail(tool, detail)
    prev.detail = lean
    flag_modified(prev, "detail")
    if fat:
        prev.detail_blob_key = put_detail_blob(prev.id, fat)
    elif prev.detail_blob_key:
        delete_detail_blob(prev.detail_blob_key)
        prev.detail_blob_key = None


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

    def extract_engine(self, raw: dict) -> str | None:
        """Engine that produced this finding. Defaults to None for tools without an engine concept."""
        return None

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

    def canonical_external_ref(
        self, ctx: "ScanContext", raw: dict[str, Any],
    ) -> tuple[str, str] | None:
        """Return (external_ref, asset_type) for the asset this raw finding belongs to.

        Override in per-tool hooks:
        - dependencies/code_scanning build a repo_ref(ctx.source_type, ctx.org, repo)
        - containers build an image_ref from the raw image reference
        - secrets return None — secrets are org-scoped and have no per-finding asset

        Returning None signals to apply_lifecycle that this finding has no asset
        and Finding.asset_id should be left NULL.
        """
        raise NotImplementedError(
            "Each LifecycleHooks subclass must implement canonical_external_ref"
        )


class ScanContext:

    def __init__(
        self, tool: str, org: str, run_id: str,
        source_type: str,
        **kwargs: Any,
    ):
        self.tool = tool
        self.org = normalize_org(org)
        self.run_id = run_id
        self.source_type = source_type
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

def _build_subject_for_new_finding(
    *, tool: str, severity: str | None, repo: str | None, detail: Any
) -> RuleFindingSubject:
    # Repo joins and KEV/EPSS enrichment are deliberately not done on the
    # hot path; defaults mirror sla_evaluator's stance and keep the matcher
    # predicate space narrow enough to reason about at ingest time.
    detail_dict = detail if isinstance(detail, dict) else {}
    return RuleFindingSubject(
        finding_id=0,
        severity=(severity or "").lower(),
        scanner=tool or "",
        repo_id=repo or "",
        repo_labels=[],
        repo_archived=False,
        cve_id=detail_dict.get("cve_id"),
        cwe_id=detail_dict.get("cwe_id"),
        kev_matched=False,
        epss_score=None,
        file_path=detail_dict.get("file_path"),
        age_days=0,
    )


def apply_lifecycle(
    hooks: LifecycleHooks,
    ctx: ScanContext,
    current_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Diff current scan against DB state and apply transitions. Returns new findings."""
    new_findings: list[dict[str, Any]] = []

    async def _run(session: AsyncSession) -> None:
        now = _utcnow()

        # Prefetch findings for this tool, scoped to assets that belong to
        # ctx.org under ctx.source_type. Avoids loading every finding across
        # every tenant on multi-org installations.
        # Secrets have asset_id=NULL and are loaded unconditionally below.
        if ctx.source_type and ctx.org:
            ref_prefix = f"{ctx.source_type}:{ctx.org}/"
            scoped_asset_ids = (
                await session.execute(
                    select(Asset.id).where(Asset.external_ref.like(f"{ref_prefix}%"))
                )
            ).scalars().all()
            prev_findings = (
                await session.execute(
                    select(Finding).where(
                        Finding.tool == ctx.tool,
                        Finding.asset_id.in_(scoped_asset_ids) if scoped_asset_ids else False,
                    )
                )
            ).scalars().all() if scoped_asset_ids else []
        else:
            prev_findings = []
        # Secrets findings have asset_id=NULL and aren't covered by the
        # scoped prefetch — include them separately for tools that emit them.
        secret_prev = (
            await session.execute(
                select(Finding).where(
                    Finding.tool == ctx.tool,
                    Finding.asset_id.is_(None),
                )
            )
        ).scalars().all()
        prev_findings = list(prev_findings) + list(secret_prev)
        prev_map: dict[str, Finding] = {f.identity_key: f for f in prev_findings}
        # Decisions are now keyed by asset_id; load lazily per asset in the loop below.
        # For the initial pass we start with an empty map and populate on demand.
        decision_map: dict[str, Decision] = {}
        _loaded_decision_assets: set[str | None] = set()
        curr_keys: set[str] = set()

        for raw in current_findings:
            key = hooks.compute_identity_key(raw)
            if not key:
                continue
            curr_keys.add(key)

            prev = prev_map.get(key)
            repo = hooks.extract_repo(raw)
            severity = hooks.extract_severity(raw)
            engine = hooks.extract_engine(raw)
            detail = _sanitize_for_pg(hooks.extract_detail(raw))

            # Resolve the canonical asset for this finding. Returns None for
            # org-scoped tools (secrets); those findings keep asset_id NULL.
            ref_result = hooks.canonical_external_ref(ctx, raw)
            if ref_result is None:
                asset_id = None
            else:
                external_ref, asset_type = ref_result
                asset_id = await upsert_asset(
                    session,
                    type=asset_type,
                    source="source_connection",
                    external_ref=external_ref,
                    display_name=external_ref,
                    source_ref=None,
                )

            # Load decisions for this asset on first encounter (lazy by asset).
            if asset_id not in _loaded_decision_assets:
                _loaded_decision_assets.add(asset_id)
                asset_decisions = await read_decisions_for_asset(session, ctx.tool, asset_id)
                decision_map.update(asset_decisions)

            decision = decision_map.get(key)

            if decision and decision.status == "dismissed":
                if prev:
                    _apply_detail(prev, ctx.tool, detail)
                    prev.severity = severity
                    prev.asset_id = asset_id
                    _maybe_set_engine(prev, engine)
                    prev.last_seen_at = now
                    prev.updated_at = now
                else:
                    f = await upsert_finding(
                        session, tool=ctx.tool, asset_id=asset_id,
                        org=ctx.org, repo=repo,
                        identity_key=key, state="dismissed", severity=severity,
                        detail=detail, first_seen_at=now, engine=engine,
                    )
                    await insert_event(
                        session, finding_id=f.id,
                        from_state=None, to_state="dismissed",
                        triggered_by="scan", actor=ctx.run_id,
                    )
                continue

            if prev:
                old_state = prev.state

                if old_state == "fixed":
                    new_state = hooks.initial_state(raw)
                    await update_finding_state(session, prev, new_state)
                    _apply_detail(prev, ctx.tool, detail)
                    prev.severity = severity
                    prev.asset_id = asset_id
                    _maybe_set_engine(prev, engine)
                    prev.last_seen_at = now
                    await insert_event(
                        session, finding_id=prev.id,
                        from_state="fixed", to_state=new_state,
                        triggered_by="scan", actor=ctx.run_id,
                    )

                elif old_state == "deferred" and hooks.has_fix(raw):
                    await update_finding_state(session, prev, "open")
                    _apply_detail(prev, ctx.tool, detail)
                    prev.severity = severity
                    prev.asset_id = asset_id
                    _maybe_set_engine(prev, engine)
                    prev.last_seen_at = now
                    await insert_event(
                        session, finding_id=prev.id,
                        from_state="deferred", to_state="open",
                        triggered_by="scan", actor=ctx.run_id,
                    )

                else:
                    _apply_detail(prev, ctx.tool, detail)
                    prev.severity = severity
                    prev.asset_id = asset_id
                    _maybe_set_engine(prev, engine)
                    prev.last_seen_at = now
                    prev.updated_at = now

            else:
                new_state = hooks.initial_state(raw)

                subject = _build_subject_for_new_finding(
                    tool=ctx.tool, severity=severity, repo=repo, detail=detail,
                )
                auto_match = await check_auto_dismiss_rules(
                    session, subject=subject,
                    tool=ctx.tool, identity_key=key, asset_id=asset_id,
                )
                if auto_match is not None:
                    f = await upsert_finding(
                        session, tool=ctx.tool, asset_id=asset_id,
                        org=ctx.org, repo=repo,
                        identity_key=key, state="dismissed", severity=severity,
                        detail=detail, first_seen_at=now, engine=engine,
                    )
                    await insert_event(
                        session, finding_id=f.id,
                        from_state=None, to_state="dismissed",
                        triggered_by=AUTO_DISMISS_EVENT_TRIGGERED_BY,
                        actor=auto_dismiss_event_actor(auto_match.rule_id),
                        metadata=auto_match.matched_conditions_snapshot,
                    )
                    # Same-scan duplicate identity_keys would otherwise re-enter
                    # this branch and hit the matcher's existing-Decision early
                    # return, then fall through to a regular open insert. Refresh
                    # decision_map so those duplicates take the dismissed branch.
                    if asset_id is not None:
                        fresh = (await session.execute(
                            select(Decision).where(
                                Decision.tool == ctx.tool,
                                Decision.asset_id == asset_id,
                                Decision.identity_key == key,
                            )
                        )).scalars().first()
                    else:
                        fresh = (await session.execute(
                            select(Decision).where(
                                Decision.tool == ctx.tool,
                                Decision.asset_id.is_(None),
                                Decision.identity_key == key,
                            )
                        )).scalars().first()
                    if fresh is not None:
                        decision_map[key] = fresh
                    continue

                f = await upsert_finding(
                    session, tool=ctx.tool, asset_id=asset_id,
                    org=ctx.org, repo=repo,
                    identity_key=key, state=new_state, severity=severity,
                    detail=detail, first_seen_at=now, engine=engine,
                )
                await insert_event(
                    session, finding_id=f.id,
                    from_state=None, to_state=new_state,
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
                    session, finding_id=prev.id,
                    from_state=old_state, to_state="fixed",
                    triggered_by="scan", actor=ctx.run_id,
                )

        # Score is derived from severity + KEV + EPSS — recompute once per
        # scan pass so freshly ingested rows pick up the current feed state.
        from src.findings.risk_score import recompute_finding_risk_scores
        await recompute_finding_risk_scores(session, org=ctx.org)

    run_db(_run)
    request_home_views_refresh()
    return new_findings


def dismiss_finding(
    tool: str,
    identity_key: str,
    reason: str,
    user_id: str,
    comment: str | None = None,
    *,
    asset_id: str | None = None,
    org: str | None = None,
) -> None:
    """Dismiss a finding.

    Callers must supply either asset_id (preferred, asset-scoped path) or org
    (legacy org-scoped path). asset_id takes precedence when both are given.
    """
    if reason not in VALID_DISMISS_REASONS:
        raise ValueError(f"Invalid dismiss reason {reason!r}")
    if not asset_id and not org:
        raise ValueError("dismiss_finding requires asset_id or org")

    async def _run(session: AsyncSession) -> None:
        now = _utcnow()

        await upsert_decision(
            session, tool=tool, asset_id=asset_id, identity_key=identity_key,
            status="dismissed", reason=reason, comment=comment, decided_by=user_id,
        )

        stmt = select(Finding).where(
            Finding.tool == tool,
            Finding.identity_key == identity_key,
        )
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        else:
            stmt = stmt.where(Finding.asset_id.is_(None))

        result = await session.execute(stmt)
        finding = result.scalars().first()
        if finding and finding.state != "dismissed":
            old_state = finding.state
            finding.state = "dismissed"
            finding.updated_at = now
            await insert_event(
                session, finding_id=finding.id,
                from_state=old_state, to_state="dismissed",
                triggered_by="user", actor=user_id,
                metadata={"reason": reason, "comment": comment},
            )

    run_db(_run)
    request_home_views_refresh()


def reopen_finding(
    tool: str,
    identity_key: str,
    user_id: str,
    *,
    asset_id: str | None = None,
    org: str | None = None,
) -> None:
    """Reopen a dismissed finding.

    Callers must supply either asset_id (preferred, asset-scoped path) or org
    (legacy org-scoped path). asset_id takes precedence when both are given.
    """
    if not asset_id and not org:
        raise ValueError("reopen_finding requires asset_id or org")

    async def _run(session: AsyncSession) -> None:
        now = _utcnow()

        await delete_decision(session, tool, identity_key=identity_key, asset_id=asset_id)

        stmt = select(Finding).where(
            Finding.tool == tool,
            Finding.identity_key == identity_key,
        )
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        else:
            stmt = stmt.where(Finding.asset_id.is_(None))

        result = await session.execute(stmt)
        finding = result.scalars().first()
        if finding and finding.state == "dismissed":
            finding.state = "open"
            finding.updated_at = now
            await insert_event(
                session, finding_id=finding.id,
                from_state="dismissed", to_state="open",
                triggered_by="user", actor=user_id,
            )

    run_db(_run)
    request_home_views_refresh()


async def bulk_dismiss_in_session(
    session: AsyncSession,
    tool: str,
    identity_keys: list[str],
    reason: str,
    user_id: str,
    comment: str | None = None,
    *,
    asset_ids: list[str] | None = None,
    org: str | None = None,
    secrets: bool = False,
) -> int:
    """Atomic core of bulk_dismiss — operates inside the caller's session.

    Lets a single endpoint call cover many (tool, asset_id) groups under one
    transaction so a mid-loop failure rolls everything back together.

    Callers must supply one of:
    - asset_ids=[...] — asset-scoped path (preferred)
    - secrets=True — secrets path (asset_id IS NULL)
    - org=... — legacy org-scoped path (deprecated; falls through to secrets path)
    """
    if reason not in VALID_DISMISS_REASONS:
        raise ValueError(f"Invalid dismiss reason {reason!r}")
    if not asset_ids and not org and not secrets:
        raise ValueError("bulk_dismiss requires asset_ids, org, or secrets=True")

    now = _utcnow()
    updated = 0

    for key in identity_keys:
        # For asset-scoped dismiss, write one decision per asset_id.
        # For secrets (no asset_ids), write a single asset_id=NULL decision.
        decision_asset_id = asset_ids[0] if asset_ids and len(asset_ids) == 1 else None
        await upsert_decision(
            session, tool=tool, asset_id=decision_asset_id, identity_key=key,
            status="dismissed", reason=reason, comment=comment, decided_by=user_id,
        )

        stmt = select(Finding).where(
            Finding.tool == tool,
            Finding.identity_key == key,
        )
        if asset_ids:
            stmt = stmt.where(Finding.asset_id.in_(asset_ids))
        else:
            stmt = stmt.where(Finding.asset_id.is_(None))

        result = await session.execute(stmt)
        finding = result.scalars().first()
        if finding and finding.state != "dismissed":
            old_state = finding.state
            finding.state = "dismissed"
            finding.updated_at = now
            await insert_event(
                session, finding_id=finding.id,
                from_state=old_state, to_state="dismissed",
                triggered_by="user", actor=user_id,
                metadata={"reason": reason, "comment": comment},
            )
            updated += 1
    return updated


def bulk_dismiss(
    tool: str,
    identity_keys: list[str],
    reason: str,
    user_id: str,
    comment: str | None = None,
    *,
    asset_ids: list[str] | None = None,
    org: str | None = None,
    secrets: bool = False,
) -> int:
    """Dismiss multiple findings in one transaction. Returns count updated.

    Sync wrapper for callers outside the request loop. The async core lives in
    `bulk_dismiss_in_session` so async callers can compose many groups under a
    single transaction.

    Callers must supply one of:
    - asset_ids=[...] — asset-scoped path (preferred)
    - secrets=True — secrets path (asset_id IS NULL)
    - org=... — legacy org-scoped path (deprecated; falls through to secrets path)
    """
    updated = 0

    async def _run(session: AsyncSession) -> int:
        nonlocal updated
        updated = await bulk_dismiss_in_session(
            session, tool, identity_keys, reason, user_id, comment,
            asset_ids=asset_ids, org=org, secrets=secrets,
        )
        return updated

    run_db(_run)
    request_home_views_refresh()
    return updated
