"""Rule-pack update fan-out for the SAST incremental engine.

Phase 2c: when the Opengrep rule pack version bumps, all cached per-file
findings are stale — new rules may match files that weren't modified in the
latest commit.  This module enqueues a full re-scan for every affected repo.
"""
from __future__ import annotations

import logging
import secrets

from src.code_scanning.file_finding_cache import FileFindingCache, _CACHE_TYPE

logger = logging.getLogger(__name__)

_SOURCE_COMPONENT = "sast_intel_fanout"


def _distinct_repo_ids(cache: FileFindingCache) -> list[str]:
    """Return the unique repo_ids present in the SAST file-findings cache."""
    from src.db.helpers import run_db
    from src.db.models import CacheEntry
    from sqlalchemy import select

    async def _query(session):
        result = await session.execute(
            select(CacheEntry.cache_key).where(
                CacheEntry.cache_type == _CACHE_TYPE,
            )
        )
        return [row[0] for row in result.fetchall()]

    keys = run_db(_query)
    # cache_key format: '{repo_id}|{file_path}|{sha256}'
    repo_ids: list[str] = []
    seen: set[str] = set()
    for key in keys:
        repo_id = key.split("|", 1)[0]
        if repo_id not in seen:
            seen.add(repo_id)
            repo_ids.append(repo_id)
    return repo_ids


def dispatch_rule_pack_update_fanout(
    rule_pack_version: str,
    cache: FileFindingCache,
) -> int:
    """Enqueue a full SAST re-scan for every repo whose cached findings are stale.

    A repo is stale when any of its cache entries were produced with a rule pack
    version that differs from rule_pack_version.

    Returns the count of repos enqueued for re-scan.

    The enqueue call is stubbed — Phase 2c delivers the fan-out logic; actual
    job dispatch is wired in a follow-up when the orchestrator integration lands.
    """
    repo_ids = _distinct_repo_ids(cache)

    enqueued = 0
    for repo_id in repo_ids:
        entries = cache.list_repo_entries(repo_id)
        stale = any(e.rule_pack_version != rule_pack_version for e in entries)
        if not stale:
            continue

        # Stub: log the intent; real implementation dispatches to job queue
        logger.info(
            "[%s] rule pack updated to %s — enqueuing full SAST re-scan for repo=%s",
            _SOURCE_COMPONENT,
            rule_pack_version,
            repo_id,
        )
        _enqueue_full_rescan(repo_id, rule_pack_version)
        enqueued += 1

    logger.info(
        "[%s] rule_pack_version=%s: %d/%d repos enqueued for full re-scan",
        _SOURCE_COMPONENT,
        rule_pack_version,
        enqueued,
        len(repo_ids),
    )
    return enqueued


def _enqueue_full_rescan(repo_id: str, rule_pack_version: str) -> None:
    """Dispatch a full SAST re-scan runner job for a single repo.

    repo_id has the format 'org/repo'.  The org is extracted and used to look
    up the source connection (token + repo URLs) before enqueuing.

    Logs a warning and returns without raising if the org cannot be resolved or
    has no connected source — the fan-out loop must continue to the next repo.
    """
    from src.runner.jobs import create_job
    from src.shared.config import get_code_scanning_scanner_config, get_scan_sources_for_org

    if not repo_id or "/" not in repo_id:
        logger.warning(
            "[%s] skipping re-scan: repo_id %r has unexpected format (expected 'org/repo')",
            _SOURCE_COMPONENT,
            repo_id,
        )
        return

    org = repo_id.split("/", 1)[0]

    sources = get_scan_sources_for_org(org)
    repo_sources = [s for s in sources if s.repo_urls]

    if not repo_sources:
        logger.warning(
            "[%s] skipping re-scan for repo=%s: no connected code-repository source found for org=%s",
            _SOURCE_COMPONENT,
            repo_id,
            org,
        )
        return

    # Collect all repo URLs and a usable token from the first source that has one.
    all_repo_urls: list[str] = []
    source_token = ""
    for source in repo_sources:
        all_repo_urls.extend(source.repo_urls)
        if not source_token and source.token:
            source_token = source.token

    if not source_token:
        logger.warning(
            "[%s] skipping re-scan for repo=%s: no auth token available for org=%s",
            _SOURCE_COMPONENT,
            repo_id,
            org,
        )
        return

    scanner_config = get_code_scanning_scanner_config()
    run_id = secrets.token_hex(8)

    create_job(
        job_type="code_scanning",
        org=org,
        run_id=run_id,
        docker_image=scanner_config.get("image") or "aegis/scanner-code-scanning:latest",
        env_vars={
            "GIT_TOKEN": source_token,
            "GIT_REPOS": ",".join(all_repo_urls),
            "ORG_LABEL": org,
            "CONCURRENCY": scanner_config.get("concurrency") or "4",
            "RUN_ID": run_id,
            "RULESETS": scanner_config.get("rulesets") or rule_pack_version,
        },
        expected_repo_count=len(all_repo_urls),
    )

    logger.info(
        "[%s] dispatched code_scanning job run_id=%s for org=%s repo=%s",
        _SOURCE_COMPONENT,
        run_id,
        org,
        repo_id,
    )
