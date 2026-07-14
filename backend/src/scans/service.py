"""Pre-release scan service — submits user-triggered scan_runs and reads status."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update

from src.db.engine import get_session
from src.db.models import ScanRun
from src.pr_feedback.git_pr_providers import resolve_pr_provider

logger = logging.getLogger(__name__)

# Default scanners for a git/repo source. Container scanning targets images, not
# repos (a repo job supplies no image refs), so it is NOT a repo scanner — it
# lives in _IMAGE_SCANNERS and image scans request it explicitly.
_DEFAULT_SCANNERS = ["dependencies_scanning", "code_scanning", "secret_scanning", "iac_scanning", "agent_scanning"]

_SCANNER_JOB_TYPES: dict[str, str] = {
    "dependencies_scanning": "dependencies_scanning",
    "code_scanning":         "code_scanning",
    "container_scanning":    "container_scanning",
    "secret_scanning":       "secret_scanning",
    "iac_scanning":          "iac_scanning",
    "agent_scanning":        "agent_scanning",
}


def _dispatch_scanner_jobs(
    scan_id: str,
    repo_id: str,
    commit_sha: str,
    scanners: list[str],
    org: str,
    *,
    base_sha: str | None = None,
    scan_scope: str = "full_tree",
    source_type: str | None = None,
    repo_url: str | None = None,
    accepted_risks_json: str = "[]",
) -> None:
    """Create one runner job per scanner type after the ScanRun row is committed.

    `source_type` is carried in env_vars as SOURCE_TYPE so ingest can resolve
    each finding's repo asset (without it, ingest can't attach findings). When
    `repo_url` is omitted the caller has not resolved a provider-specific clone
    URL, so we fall back to the legacy github.com layout.
    """
    from src.audit_log.recorder import ActorInfo, get_recorder
    from src.runner.jobs import create_job
    from src.settings.llm.service import build_llm_scan_env
    from src.shared.config import get_token_for_org

    token = get_token_for_org(org) or ""
    clone_url = repo_url or f"https://github.com/{repo_id}"

    # Argus (threat-intel enrichment) and the BYO LLM (finding verification) are
    # independent concerns — either, both, or neither may be enabled, and neither
    # suppresses the other. A scan can ship both: Argus enriches, the LLM verifies.

    # BYO LLM — the verification engine that tightens scanner precision (fewer FPs).
    llm_env = build_llm_scan_env()
    if llm_env:
        get_recorder().record(
            action="scan.verification_started",
            resource_type="scan_run",
            resource_id=scan_id,
            actor=ActorInfo(user_id="system:scan_dispatch"),
            metadata={"model": llm_env["LLM_API_MODEL"], "scanners": scanners},
        )

    # Argus threat-intel enrichment runs backend-side (osv/argus_match.py), which
    # holds the connection and mints its own token — the runner no longer consumes
    # ARGUS_* env, so scan dispatch neither mints nor ships it.

    for scanner in scanners:
        job_type = _SCANNER_JOB_TYPES.get(scanner)
        if not job_type:
            logger.warning("submit_scan: unknown scanner type %r — skipping", scanner)
            continue

        run_id = f"{scan_id}:{scanner}"
        env: dict[str, str] = {
            "GIT_TOKEN":   token,
            "GIT_REPOS":   clone_url,
            "ORG_LABEL":   org,
            "RUN_ID":      run_id,
            "COMMIT_SHA":  commit_sha,
            "REPO_ID":     repo_id,
            "CONCURRENCY": "4",
            "SCAN_SCOPE":  scan_scope,
            **llm_env,
        }
        env["ACCEPTED_RISKS"] = accepted_risks_json
        if source_type:
            env["SOURCE_TYPE"] = source_type
        if base_sha:
            env["BASE_SHA"] = base_sha

        create_job(job_type=job_type, org=org, run_id=run_id, env_vars=env)
        logger.info("Dispatched %s runner job for scan %s (repo %s)", scanner, scan_id, repo_id)


async def _accepted_risks_json(session, asset_id: str) -> str:
    """Scope-matched, enabled accepted-risks for `asset_id` as a JSON string for
    the runner's ACCEPTED_RISKS env. Empty list ("[]") when none apply."""
    import json
    from src.sources.accepted_risks_service import list_for_assets, matched_for_repo

    rows = await list_for_assets(session, [asset_id])
    matched = matched_for_repo(rows, asset_id=asset_id)
    return json.dumps([
        {"id": r["id"], "statement": r["statement"], "path_glob": r["path_glob"],
         "rule_id": r["rule_id"], "scanner": r["scanner"]}
        for r in matched
    ])


def _resolve_repo_dispatch_target(external_ref: str) -> tuple[str, str, str, str]:
    """Resolve runner-dispatch fields from an asset's ``external_ref``.

    Returns ``(source_type, owner, name, clone_url)``. ``external_ref`` is the
    canonical ``scm_type:owner/name``; the clone URL honours the connection's
    instanceUrl so self-hosted GHE / GitLab / Gitea target the right host
    instead of assuming github.com. ``source_type`` must reach the runner as
    SOURCE_TYPE so ingest can attach each finding to its repo asset.
    """
    from src.shared.config import get_instance_url_for_org
    from src.shared.providers.base import UnknownProvider, get_repo_provider

    if ":" in external_ref:
        scm_type, path = external_ref.split(":", 1)
    else:
        scm_type, path = "github", external_ref
    parts = path.split("/", 1)
    owner = parts[0] if parts else ""
    name = parts[1] if len(parts) > 1 else ""
    try:
        instance_url = get_instance_url_for_org(owner, scm_type)
        clone_url = get_repo_provider(scm_type).clone_url(owner, name, instance_url)
    except UnknownProvider:
        clone_url = f"https://github.com/{owner}/{name}"
    return scm_type, owner, name, clone_url


async def _load_source(source_id: str):
    """Look up an Asset row by id and return a lightweight source-view object.

    Returns None when no matching row exists.  The returned object exposes the
    attributes that resolve_pr_provider and resolve_pr_base_sha expect:
      .scm_type  — derived from the 'scheme' prefix of external_ref (e.g. "github")
      .scm_base_url — None for SaaS providers; could be populated for self-hosted
      .repo      — 'owner/name' path extracted from external_ref
    """
    from types import SimpleNamespace
    from src.db.models import Asset
    async with get_session() as session:
        asset = await session.get(Asset, source_id)
    if asset is None:
        return None
    ext_ref = asset.external_ref or ""
    if ":" in ext_ref:
        scm_type, repo = ext_ref.split(":", 1)
    else:
        scm_type, repo = "github", ext_ref
    return SimpleNamespace(scm_type=scm_type, scm_base_url=None, repo=repo)


async def _resolve_pr_base_sha(source_id: str, pr_number: int, token: str) -> str | None:
    """Resolve the base-commit SHA for a PR via the appropriate SCM provider.

    Returns None on any error so callers can fall back to a full-tree scan.
    """
    if not token:
        return None
    source = await _load_source(source_id)
    if source is None:
        logger.warning("source not found for base-sha resolution: %s", source_id)
        return None
    provider = resolve_pr_provider(source)
    if provider is None:
        logger.warning("no PR adapter for source: %s (scm_type=%s)", source_id, source.scm_type)
        return None
    repo = source.repo or source_id
    return await provider.resolve_pr_base_sha(repo=repo, pr_number=pr_number, token=token)


@dataclass
class ScanSubmission:
    scan_id: str
    repo_id: str
    commit_sha: str
    scanner_types: list[str]
    status: str
    submitted_at: datetime
    submitted_by: str


@dataclass
class ScanDetail:
    scan_id: str
    repo_id: str
    commit_sha: str
    scanner_types: list[str]
    status: str
    submitted_at: datetime
    submitted_by: str
    started_at: datetime | None
    finished_at: datetime | None
    finding_counts: dict[str, int] | None
    error: str | None
    # The detail endpoint returns archived rows so deep-links survive.
    archived: bool = False
    # None when no verification ran for this scan.
    verification_summary: dict[str, Any] | None = None


def _parse_submitted_at(meta: dict[str, Any]) -> datetime:
    # submit_scan always writes submitted_at; this fallback handles legacy/foreign
    # scan_runs that pre-date this code path (e.g. scheduled scans read by /scans/{id}).
    raw = meta.get("submitted_at")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


_REPO_SCANNERS = frozenset({"dependencies_scanning", "code_scanning", "secret_scanning", "iac_scanning", "agent_scanning"})
_IMAGE_SCANNERS = frozenset({"container_scanning"})
_CLOUD_SCANNERS: frozenset[str] = frozenset()  # populated when cloud scanners exist


class ScannerNotApplicableError(ValueError):
    """Caller asked for a scanner that doesn't apply to this asset_type."""


def _validate_scanners_for_asset_type(asset_type: str, scanners: list[str]) -> None:
    valid = {"repo": _REPO_SCANNERS, "image": _IMAGE_SCANNERS, "cloud": _CLOUD_SCANNERS}.get(asset_type)
    if valid is None:
        raise ScannerNotApplicableError(f"unsupported asset_type: {asset_type!r}")
    bad = [s for s in scanners if s not in valid]
    if bad:
        raise ScannerNotApplicableError(
            f"scanner_types {bad} not applicable to asset_type={asset_type!r}; "
            f"valid choices: {sorted(valid)}"
        )


async def submit_scan(
    asset_id: str,
    user_id: str,
    *,
    commit_sha: str | None = None,
    image_digest: str | None = None,
    scanner_types: list[str] | None = None,
) -> ScanSubmission | None:
    """Polymorphic manual-scan dispatcher — routes by Asset.type.

    Returns None if no Asset row exists for the given asset_id.
    Raises ScannerNotApplicableError if scanner_types don't apply to the asset.
    Raises NotImplementedError for asset types whose dispatch isn't wired yet.
    """
    async with get_session() as session:
        from src.db.models import Asset
        asset_row = (await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one_or_none()
        if asset_row is None:
            return None

        asset_type = asset_row.type

        # Default scanner selection per asset type.
        if scanner_types is None:
            if asset_type == "repo":
                scanners = _DEFAULT_SCANNERS
            elif asset_type == "image":
                scanners = ["container_scanning"]
            elif asset_type == "cloud":
                scanners = []
            else:
                raise ScannerNotApplicableError(f"unsupported asset_type: {asset_type!r}")
        else:
            scanners = scanner_types

        _validate_scanners_for_asset_type(asset_type, scanners)

        if asset_type == "repo":
            if commit_sha is None:
                raise ScannerNotApplicableError("commit_sha is required for repo scans")
            return await _submit_repo_scan(session, asset_row, commit_sha, scanners, user_id)

        if asset_type == "image":
            return await _submit_image_scan(session, asset_row, image_digest, scanners, user_id)

        if asset_type == "cloud":
            return await _submit_cloud_scan(session, asset_row, scanners, user_id)

        raise ScannerNotApplicableError(f"unsupported asset_type: {asset_type!r}")


async def _submit_repo_scan(
    session,
    asset_row,
    commit_sha: str,
    scanners: list[str],
    user_id: str,
) -> ScanSubmission:
    scan_id = f"scan-{uuid.uuid4()}"
    submitted_at = datetime.now(timezone.utc)

    scm_type, owner, name, repo_url = _resolve_repo_dispatch_target(asset_row.external_ref or "")
    repo_id = f"{owner}/{name}"
    org = owner

    metadata = {
        "commit_sha": commit_sha,
        "repo_id": repo_id,
        "org_label": org,
        "scanner_types": scanners,
        "submitted_by": user_id,
        "submitted_at": submitted_at.isoformat(),
        "source": "user",
    }

    # tool="pre_release" identifies this row as a user-triggered scan envelope;
    # produced findings carry their own tool values ("dependencies", etc.) and feed posture.
    row = ScanRun(
        id=scan_id,
        tool="pre_release",
        asset_id=asset_row.id,
        status="queued",
        started_at=None,
        finished_at=None,
        progress=None,
        error=None,
        metadata_json=metadata,
    )
    session.add(row)
    await session.commit()
    accepted_risks_json = await _accepted_risks_json(session, asset_row.id)
    _dispatch_scanner_jobs(
        scan_id, repo_id, commit_sha, scanners, org,
        source_type=scm_type, repo_url=repo_url,
        accepted_risks_json=accepted_risks_json,
    )

    return ScanSubmission(
        scan_id=scan_id,
        repo_id=repo_id,
        commit_sha=commit_sha,
        scanner_types=scanners,
        status="queued",
        submitted_at=submitted_at,
        submitted_by=user_id,
    )


async def _submit_image_scan(
    session,
    asset_row,
    image_digest: str | None,
    scanners: list[str],
    user_id: str,
) -> ScanSubmission:
    # Per-image runner dispatch is not wired — TODO.md tracks the follow-up.
    # Until then, /scans/manual returns 501 for image assets (router translates).
    raise NotImplementedError(
        "per-image scan dispatch not yet wired; images are scanned org-wide by the scheduler"
    )


async def _submit_cloud_scan(
    session,
    asset_row,
    scanners: list[str],
    user_id: str,
) -> ScanSubmission:
    raise NotImplementedError(
        "cloud scan dispatch not yet wired; no cloud connector or scanner exists today"
    )


async def record_byo_scan_run(
    session,
    *,
    asset_id: str,
    display_name: str,
    scanner: str,
    finding_counts: dict[str, int],
    user_id: str,
) -> str:
    """Record a terminal ScanRun envelope for a Bring-Your-Own import.

    BYO findings arrive out-of-band from an external scanner, so the envelope is
    born ``completed`` — there is no queued→running lifecycle and, deliberately,
    no runner job is dispatched (unlike the ``_submit_*_scan`` paths). The row
    exists so a BYO import surfaces at ``/scans/{scan_id}`` and in the scan trail
    alongside scanner-triggered runs.

    The row is added to the caller's session but NOT committed; the caller commits
    it atomically with the imported findings so an envelope never outlives a failed
    import.
    """
    scan_id = f"scan-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)
    metadata = {
        "repo_id": display_name,
        "scanner_types": [scanner],
        "submitted_by": user_id,
        "submitted_at": now.isoformat(),
        "source": "byo",
    }
    row = ScanRun(
        id=scan_id,
        tool="byo_import",
        asset_id=asset_id,
        status="completed",
        started_at=now,
        finished_at=now,
        progress={"finding_counts": finding_counts},
        error=None,
        metadata_json=metadata,
    )
    session.add(row)
    return scan_id


async def find_inflight_scan(*, org: str, source_id: str, commit_sha: str) -> ScanRun | None:
    """Return any in-flight (queued or running) scan for the given source+commit, else None.

    Used for dedup at trigger time — any matching in-flight row satisfies the check,
    so the result is intentionally unordered (ScanRun.id is a UUID and would not sort
    monotonically anyway). The org argument is reserved for future cross-org safety;
    current scoping is enforced upstream at the router layer via API-key org binding.
    """
    async with get_session() as session:
        return (await session.execute(
            select(ScanRun)
            .where(ScanRun.asset_id == source_id)
            .where(ScanRun.commit_sha == commit_sha)
            .where(ScanRun.status.in_(("queued", "running")))
            .limit(1)
        )).scalar_one_or_none()


async def cancel_older_queued_for_pr(
    *,
    org: str,
    source_id: str,
    pr_number: int,
    keep_scan_id: str,
) -> list[str]:
    """Mark older queued scans on the same source+PR as cancelled. Return their IDs.

    The SELECT-then-UPDATE is intentionally non-atomic; concurrent triggers may
    each observe and cancel the same set, but writing 'cancelled' twice is
    idempotent.

    Also cancels the matching RunnerJob rows so the runner stops processing the
    obsolete jobs. Without this, the runner runs each superseded scan to
    completion, uploads results, posts /complete — and the backend's ingest
    step drops the work because the ScanRun is already marked cancelled.
    """
    from src.runner.jobs import cancel_jobs_for_scans

    async with get_session() as session:
        rows = (await session.execute(
            select(ScanRun.id)
            .where(ScanRun.asset_id == source_id)
            .where(ScanRun.pr_number == pr_number)
            .where(ScanRun.status == "queued")
            .where(ScanRun.id != keep_scan_id)
        )).scalars().all()

        if not rows:
            return []

        await session.execute(
            update(ScanRun)
            .where(ScanRun.id.in_(rows))
            .values(
                status="cancelled",
                cancelled_reason="superseded",
                finished_at=datetime.now(timezone.utc),
            )
        )
        await session.commit()

    scan_ids = list(rows)
    cancel_jobs_for_scans(scan_ids)
    return scan_ids


async def submit_ci_scan(
    *,
    org: str,
    source_id: str,
    commit_sha: str,
    branch: str | None,
    pr_number: int | None,
    api_key_id: int | None = None,
    triggered_by: str = "ci",
    trigger_metadata: dict | None = None,
) -> ScanSubmission:
    """Create a CI-triggered scan run, dispatch runner jobs, return submission record."""
    from src.shared.config import get_token_for_org

    scan_id = str(uuid.uuid4())
    submitted_at = datetime.now(timezone.utc)
    feedback_status = "pending" if pr_number is not None else "not_applicable"

    scan_scope = "diff_scoped" if pr_number is not None else "full_tree"
    base_sha: str | None = None
    if pr_number is not None:
        token = get_token_for_org(org) or ""
        base_sha = await _resolve_pr_base_sha(source_id, pr_number, token)
        if base_sha is None:
            # Missing token, API error, or PR not found — fall back silently.
            scan_scope = "full_tree"

    # Default trigger_metadata mirrors the audit context for the caller. The
    # CI path always has an api_key_id; webhook callers pass their own dict.
    if trigger_metadata is None:
        trigger_metadata = {"api_key_id": api_key_id} if api_key_id is not None else {}

    async with get_session() as session:
        from src.db.models import Asset
        asset = (await session.execute(
            select(Asset).where(Asset.id == source_id)
        )).scalar_one_or_none()
        run = ScanRun(
            id=scan_id,
            tool="dependencies_scanning",  # umbrella row — per-scanner sub-runs created by dispatch
            asset_id=source_id,
            status="queued",
            triggered_by=triggered_by,
            commit_sha=commit_sha,
            branch=branch,
            pr_number=pr_number,
            feedback_status=feedback_status,
            trigger_metadata=trigger_metadata,
        )
        session.add(run)
        await session.commit()
        accepted_risks_json = await _accepted_risks_json(session, source_id)

    # Carry the asset's source type + a provider-correct clone URL to the runner
    # so it clones the right repo and ingest can attach findings to the asset.
    source_type: str | None = None
    repo_url: str | None = None
    if asset is not None:
        source_type, _, _, repo_url = _resolve_repo_dispatch_target(asset.external_ref or "")

    try:
        _dispatch_scanner_jobs(
            scan_id,
            source_id,
            commit_sha,
            _DEFAULT_SCANNERS,
            org,
            base_sha=base_sha,
            scan_scope=scan_scope,
            source_type=source_type,
            repo_url=repo_url,
            accepted_risks_json=accepted_risks_json,
        )
    except Exception:
        # The ScanRun row is already committed in 'queued'. Surface the orphan
        # in logs so it can be reaped or retried out-of-band.
        logger.exception(
            "ci.scan.dispatch_failed scan_id=%s source=%s commit=%s",
            scan_id, source_id, commit_sha,
        )
        raise

    logger.info(
        "ci.scan.submitted scan_id=%s source=%s commit=%s pr=%s",
        scan_id, source_id, commit_sha, pr_number,
    )

    # Downstream readers treat ``submitted_by`` as a principal identifier
    # (e.g. ``api_key:7``, ``alice@example.com``). Shape the webhook path to
    # carry the event_id from trigger_metadata so the value stays principal-like
    # and stays distinguishable from CI/api-key triggers.
    if api_key_id is not None:
        submitted_by = f"api_key:{api_key_id}"
    elif triggered_by == "webhook":
        submitted_by = f"webhook:{trigger_metadata.get('event_id') or 'unknown'}"
    else:
        submitted_by = triggered_by

    return ScanSubmission(
        scan_id=scan_id,
        repo_id=source_id,
        commit_sha=commit_sha,
        scanner_types=list(_DEFAULT_SCANNERS),
        status="queued",
        submitted_at=submitted_at,
        submitted_by=submitted_by,
    )


async def cancel_scan(
    *,
    scan_id: str,
    asset_ids: list[str],
    actor_user_id: str | None = None,
) -> str | None:
    """Cancel an active scan and stop the runner from processing it.

    Returns:
      * the scan_id when a transition fires
      * "already_terminal" when the scan was already in a terminal state
        (completed/failed/cancelled) — idempotent no-op
      * None when the scan does not exist OR the caller has no scope on it
        (callers must treat None as 404 to avoid leaking existence)

    On a real transition, three things fire after the DB commit:
      1. Cancel matching RunnerJob rows so the runner stops working on the
         obsolete job at its next progress poll (without this the runner
         runs to completion and the result gets dropped on ingest — see
         cancel_older_queued_for_pr for the same pattern fixed in #795).
      2. Record a `scan.cancelled` audit event with the caller's user_id
         so the trail of who cancelled what is preserved for compliance.
      3. Publish a `scan.cancelled` SSE event so other browser sessions
         viewing the same scan refresh in real-time instead of waiting
         for the next periodic refetch.
    """
    from src.audit_log.recorder import ActorInfo, get_recorder
    from src.runner.jobs import cancel_jobs_for_scans
    from src.shared.event_bus import Event, get_event_bus

    if not asset_ids:
        return None

    async with get_session() as session:
        row = (await session.execute(
            select(ScanRun)
            .where(ScanRun.id == scan_id)
            .where(ScanRun.asset_id.in_(asset_ids))
        )).scalar_one_or_none()
        if row is None:
            return None

        if row.status in ("completed", "failed", "cancelled"):
            return "already_terminal"

        row.status = "cancelled"
        row.cancelled_reason = "user"
        row.finished_at = datetime.now(timezone.utc)
        if not row.error:
            row.error = "Cancelled by user"

        meta: dict[str, Any] = row.metadata_json or {}
        scanner_types = meta.get("scanner_types") or []
        repo_id = meta.get("repo_id", "")
        org = meta.get("org_label", "")
        await session.commit()

    cancel_jobs_for_scans([scan_id])

    get_recorder().record(
        action="scan.cancelled",
        resource_type="scan_run",
        resource_id=scan_id,
        actor=ActorInfo(user_id=actor_user_id or "system"),
        metadata={"scanner_types": scanner_types, "repo_id": repo_id, "org": org},
    )

    get_event_bus().publish_sync(Event(
        event_type="scan.cancelled",
        data={
            "scanId": scan_id,
            "scannerTypes": scanner_types,
            "org": org,
            "repoId": repo_id,
        },
    ))

    return scan_id


async def get_scan(scan_id: str, *, asset_ids: list[str]) -> ScanDetail | None:
    """Read a scan_run scoped to the caller's accessible assets.

    The scan must belong to one of the asset_ids the caller can see; otherwise
    the function returns None. An empty asset_ids list is treated as "no
    access" (fail-closed) — callers must resolve the caller's scope via
    ``resolve_asset_ids_from_request`` before invoking.
    """
    if not asset_ids:
        return None
    async with get_session() as session:
        stmt = (
            select(ScanRun)
            .where(ScanRun.id == scan_id)
            .where(ScanRun.asset_id.in_(asset_ids))
        )
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return None

        meta: dict[str, Any] = row.metadata_json or {}
        progress: dict[str, Any] = row.progress or {}

        verification_summary = await _verification_summary_for_scan(session, scan_id)

        return ScanDetail(
            scan_id=row.id,
            repo_id=meta.get("repo_id", ""),
            commit_sha=meta.get("commit_sha", ""),
            scanner_types=meta.get("scanner_types", []),
            status=row.status,
            submitted_at=_parse_submitted_at(meta),
            submitted_by=meta.get("submitted_by", ""),
            started_at=row.started_at,
            finished_at=row.finished_at,
            finding_counts=progress.get("finding_counts"),
            error=row.error,
            archived=bool(row.archived),
            verification_summary=verification_summary,
        )


async def _verification_summary_for_scan(session, scan_id: str) -> dict[str, Any] | None:
    """Aggregate verdict counts + token totals for findings touched by this scan.

    Returns None when the scan touched no findings.
    """
    from sqlalchemy import distinct, select as sa_select
    from src.db.models import Finding, FindingEvent

    actor_prefix = f"{scan_id}:%"
    finding_ids_subq = (
        sa_select(distinct(FindingEvent.finding_id))
        .where(FindingEvent.actor.like(actor_prefix))
        .scalar_subquery()
    )

    rows = await session.execute(
        sa_select(Finding.verdict, Finding.verification_metadata)
        .where(Finding.id.in_(finding_ids_subq))
    )

    counts = {
        "confirmed": 0,
        "needs_verify": 0,
        "possible": 0,
        "ruled_out": 0,
        "legacy": 0,
    }
    tokens_in = 0
    tokens_out = 0
    model: str | None = None
    touched = 0

    for verdict, meta_json in rows.all():
        touched += 1
        if verdict is None:
            counts["legacy"] += 1
        elif verdict in counts:
            counts[verdict] += 1

        meta_obj = meta_json or {}
        if isinstance(meta_obj, dict):
            tokens_in += int(meta_obj.get("tokens_in") or 0)
            tokens_out += int(meta_obj.get("tokens_out") or 0)
            if model is None and isinstance(meta_obj.get("model"), str):
                model = meta_obj["model"]

    if touched == 0:
        return None

    return {
        **counts,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "model": model,
    }
