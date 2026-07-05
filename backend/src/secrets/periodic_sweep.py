"""Periodic full-history sweep scheduling for the secrets scanner.

Phase 2d: push-path scanning only covers NEW commits — an older committed
secret that was missed in an earlier scan window would never be found.
A weekly full sweep corrects this: it rescans the entire git history.

Triggers for a full sweep:
  1. > 7 days since the last sweep (default; configurable via SECRETS_SWEEP_DAYS)
  2. Detector version changed since last sweep (new signatures need a full pass)
  3. force_sweep=True (manual operator trigger, e.g. after entropy threshold change)
"""
from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from src.runner.jobs import create_job
from src.shared.config import get_scan_sources_for_org, get_secret_scanner_config

logger = logging.getLogger(__name__)

_DEFAULT_SWEEP_DAYS = int(os.environ.get("SECRETS_SWEEP_DAYS", "7"))


def should_run_periodic_sweep(
    repo_id: str,
    last_sweep_at: datetime | None,
    current_detector_version: str,
    last_sweep_detector_version: str | None,
    *,
    force_sweep: bool = False,
) -> bool:
    """Return True when a full history rescan of repo_id is warranted.

    Parameters
    ----------
    last_sweep_at:
        UTC timestamp of the last completed full sweep, or None if never swept.
    current_detector_version:
        The detector version string active right now (e.g. "trufflehog@3.82.1").
    last_sweep_detector_version:
        The version used for the last sweep, or None if never swept.
    force_sweep:
        Always return True regardless of other conditions.
    """
    if force_sweep:
        logger.info("repo=%s force_sweep=True — scheduling full history scan", repo_id)
        return True

    if last_sweep_at is None:
        # Never swept — must do initial full scan
        logger.info("repo=%s no prior sweep — scheduling initial full history scan", repo_id)
        return True

    if current_detector_version != last_sweep_detector_version:
        # New detector version may find secrets the old version missed
        logger.info(
            "repo=%s detector version changed %s→%s — scheduling full history scan",
            repo_id,
            last_sweep_detector_version,
            current_detector_version,
        )
        return True

    cutoff = datetime.now(timezone.utc) - timedelta(days=_DEFAULT_SWEEP_DAYS)
    if last_sweep_at < cutoff:
        logger.info(
            "repo=%s last sweep %s is older than %d days — scheduling full history scan",
            repo_id,
            last_sweep_at.isoformat(),
            _DEFAULT_SWEEP_DAYS,
        )
        return True

    return False


def enqueue_full_history_scan(repo_id: str) -> None:
    """Enqueue a full git-history secrets scan job for repo_id.

    repo_id is expected in the form ``"<org>/<source_idx>"`` — the same format
    the incremental scanner uses.  The org is extracted from the prefix, used
    to fetch source connections, and one runner job is dispatched per
    source connection that has discoverable repos.

    A full sweep omits SCAN_START_DATE so the runner scans the entire git
    history rather than a rolling window. (Secret scans always run full git
    history now, so no depth flag is needed.)
    """
    if not repo_id or "/" not in repo_id:
        logger.warning("enqueue_full_history_scan: invalid repo_id=%r — expected 'org/...' format", repo_id)
        return

    org = repo_id.split("/")[0].strip()
    if not org:
        logger.warning("enqueue_full_history_scan: could not extract org from repo_id=%r", repo_id)
        return

    sources = get_scan_sources_for_org(org)
    repo_sources = [s for s in sources if s.repo_urls]

    if not repo_sources:
        logger.warning(
            "enqueue_full_history_scan: repo=%s org=%s has no connected code-repository sources — skipping",
            repo_id,
            org,
        )
        return

    config = get_secret_scanner_config()
    concurrency = config.get("concurrency") or "4"

    for source in repo_sources:
        run_id = secrets.token_hex(8)
        repo_urls_str = ",".join(source.repo_urls)

        env_vars = {
            "GIT_TOKEN": source.token,
            "GIT_REPOS": repo_urls_str,
            "ORG_LABEL": org,
            "RUN_ID": run_id,
            "CONCURRENCY": concurrency,
        }

        create_job(
            job_type="secret_scanning",
            run_id=run_id,
            env_vars=env_vars,
            expected_repo_count=len(source.repo_urls),
        )

        logger.info(
            "enqueue_full_history_scan: repo=%s org=%s run_id=%s repos=%d job queued",
            repo_id,
            org,
            run_id,
            len(source.repo_urls),
        )
