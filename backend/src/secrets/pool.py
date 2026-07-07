"""Secret scanning pool (deduplication) and checkpoint management — PostgreSQL backed."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from src.db.helpers import run_db
from src.shared.paths import parse_iso_utc
from src.db.models import ScanCheckpoint, Finding
from src.secrets.store import build_secret_identity


def read_checkpoints(tool: str = "secret_scanning") -> dict[str, dict[str, Any]]:
    """Read all scan checkpoints for a tool from the DB, keyed by asset_id."""
    async def _query(session):
        result = await session.execute(
            select(ScanCheckpoint).where(ScanCheckpoint.tool == tool)
        )
        return {
            cp.asset_id: {
                "lastCommitSha": cp.last_commit_sha,
                "lastScannedAt": cp.last_commit_date,
            }
            for cp in result.scalars().all()
        }

    return run_db(_query)


def write_checkpoint_for_asset(
    asset_id: str,
    last_commit_sha: str | None,
    last_scanned_at: str,
    tool: str = "secret_scanning",
) -> None:
    """Write a checkpoint for an asset to the DB."""
    async def _query(session):
        existing = await session.get(ScanCheckpoint, (tool, asset_id))
        if existing:
            existing.last_commit_sha = last_commit_sha or ""
            existing.last_commit_date = last_scanned_at
        else:
            session.add(ScanCheckpoint(
                tool=tool,
                asset_id=asset_id,
                last_commit_sha=last_commit_sha or "",
                last_commit_date=last_scanned_at,
            ))

    run_db(_query)


def read_pool(pool_path: Any = None, org: str = "") -> dict[str, dict[str, Any]]:
    """Read the finding pool from the DB. The path param is ignored (kept for compat).

    The org parameter is no longer used for DB filtering after Plan D (Finding.org dropped).
    Returns every secret finding (across repos); merge_pool re-groups them by
    (secretIdentity, repository) for the per-source carry-forward.
    """
    async def _query(session):
        stmt = select(Finding).where(Finding.tool == "secret_scanning")
        result = await session.execute(stmt)
        pool: dict[str, dict[str, Any]] = {}
        for f in result.scalars().all():
            data = dict(f.detail or {})
            fingerprint = str(data.get("fingerprint") or f.identity_key or "").strip()
            if fingerprint:
                pool[fingerprint] = data
        return pool

    return run_db(_query)


def _detected_at_sort_key(value: Any) -> tuple[int, Any]:
    if not isinstance(value, str):
        return (0, "")
    detected_at = value.strip()
    if not detected_at:
        return (0, "")
    try:
        return (1, parse_iso_utc(detected_at))
    except ValueError:
        return (0, detected_at)


def _repo_to_latest_sha(pool: dict[str, dict[str, Any]]) -> dict[str, str | None]:
    latest_by_repo: dict[str, tuple[tuple[int, Any], str | None]] = {}
    for finding in pool.values():
        repo = str(finding.get("repository") or "").strip()
        if not repo:
            continue
        detected_at = _detected_at_sort_key(finding.get("detectedAt"))
        commit = finding.get("commit")
        commit_sha = str(commit).strip() if isinstance(commit, str) and commit.strip() else None
        current = latest_by_repo.get(repo)
        if current is None or detected_at > current[0]:
            latest_by_repo[repo] = (detected_at, commit_sha)
    return {repo: commit_sha for repo, (_, commit_sha) in latest_by_repo.items()}


def _entries_to_append(
    existing_history: list[dict],
    new_entries: list[dict],
) -> list[dict]:
    """Return entries from new_entries whose runId is not already in existing_history."""
    existing_run_ids = {e.get("runId") for e in existing_history if e.get("runId")}
    return [e for e in new_entries if e.get("runId") not in existing_run_ids]


def reset_checkpoints(asset_ids: list[str] | None = None, tool: str = "secret_scanning") -> None:
    """Delete checkpoints for a tool, optionally scoped to a set of assets.

    With ``asset_ids=None`` (default), deletes every row (across all tools and
    assets) — preserves the legacy "reset everything" behaviour of the old
    org-less call.
    """
    async def _query(session):
        if asset_ids is not None:
            if not asset_ids:
                return
            result = await session.execute(
                select(ScanCheckpoint).where(
                    ScanCheckpoint.tool == tool,
                    ScanCheckpoint.asset_id.in_(asset_ids),
                )
            )
        else:
            result = await session.execute(select(ScanCheckpoint))
        for cp in result.scalars().all():
            await session.delete(cp)

    run_db(_query)


def merge_pool(
    current_findings: list[dict[str, Any]],
    previous_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate secrets by (secretIdentity, repository) — pure function, no DB.

    One finding per secret *per repository*, so each maps to its own repo asset
    and is scoped by that repo's grants. The shared secretIdentity still lets the
    UI group a secret's per-repo findings together. Occurrences in the same repo
    (multiple files/commits) collapse into one finding's locations[].
    Merges classificationHistory entries from previous findings.

    Args:
        current_findings: Normalized findings from current scan run.
        previous_findings: Previous findings read from DB (via read_latest_findings).

    Returns:
        Deduplicated list of findings, one per (secretIdentity, repository).
    """
    # Build previous lookup for classification history carry-forward, keyed by
    # (identity, repo) to match the per-repo grouping.
    prev_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for f in previous_findings:
        identity = f.get("secretIdentity") or ""
        if identity:
            prev_by_key[(identity, str(f.get("repository") or ""))] = f

    # Group current findings by (secretIdentity, repository)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for f in current_findings:
        identity = f.get("secretIdentity") or build_secret_identity(f) or ""
        if not identity:
            continue
        groups.setdefault((identity, str(f.get("repository") or "")), []).append(f)

    merged: list[dict[str, Any]] = []
    for (identity, repo), occurrences in groups.items():
        # Build locations from all occurrences
        locations: list[dict[str, Any]] = []
        for occ in occurrences:
            locations.append({
                "repository": occ.get("repository", ""),
                "filePath": occ.get("filePath", ""),
                "line": occ.get("line"),
                "commit": occ.get("commit", ""),
                "detectedAt": occ.get("detectedAt", ""),
                "source": occ.get("source", ""),
            })

        # Merge classification history (current + previous, dedup by runId)
        all_history: list[dict] = []
        seen_run_ids: set[str] = set()

        # Previous history first
        prev = prev_by_key.get((identity, repo))
        if prev:
            for entry in prev.get("classificationHistory") or []:
                run_id = entry.get("runId")
                if run_id and run_id not in seen_run_ids:
                    all_history.append(entry)
                    seen_run_ids.add(run_id)

        # Current history
        for occ in occurrences:
            for entry in occ.get("classificationHistory") or []:
                run_id = entry.get("runId")
                if run_id and run_id not in seen_run_ids:
                    all_history.append(entry)
                    seen_run_ids.add(run_id)

        # Use first occurrence as base, override with merged data
        base = occurrences[0]
        finding = {
            **base,
            "secretIdentity": identity,
            "repository": repo,
            "locations": locations,
            "classificationHistory": all_history,
        }
        merged.append(finding)

    return merged


def get_scan_start_date(checkpoints: dict[str, dict[str, Any]]) -> str | None:
    dates = [
        str(checkpoint["lastScannedAt"])[:10]
        for checkpoint in checkpoints.values()
        if isinstance(checkpoint, dict) and isinstance(checkpoint.get("lastScannedAt"), str) and checkpoint.get("lastScannedAt")
    ]
    return min(dates) if dates else None
