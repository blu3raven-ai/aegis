"""Background asyncio task that posts PR sticky comments for completed CI-triggered scans.

Follows the same pattern as src/audit_stream/poster.py: Postgres polling,
per-batch processing, backoff on error.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from sqlalchemy import select, update

from src.db.engine import get_session
from src.db.models import ScanRun
from src.pr_feedback.diff import compute_new_in_pr
from src.pr_feedback.git_pr_providers.base import (
    AuthError,
    NotFoundError,
    RateLimitedError,
    TransientError,
)
from src.pr_feedback.git_pr_providers import resolve_pr_provider as _resolve_pr_provider
from src.pr_feedback.render import MARKER_PREFIX, render_sticky_comment

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 5
BACKOFF_STEPS_SECONDS = [1, 5, 30, 300]
BATCH_SIZE = 20


# Adapter functions (module-level so tests can monkeypatch). Production wiring is a follow-up.

def _list_findings_for_scan(scan_id: str) -> list[dict]:
    raise NotImplementedError(
        "integration TODO: wire to the findings store; see src/findings/service.py"
    )


def _list_findings_for_base(source_id: str, base_sha: str) -> list[dict] | None:
    raise NotImplementedError(
        "integration TODO: look up the most recent completed scan for (source, base_sha) and list its findings"
    )


def _resolve_source(source_id: str) -> Any:
    raise NotImplementedError(
        "integration TODO: return an object exposing .id, .scm_type, .stored_pat, .base_sha_for_pr(pr)"
    )



async def _select_pending() -> list[ScanRun]:
    async with get_session() as session:
        return list((await session.execute(
            select(ScanRun)
            .where(ScanRun.status == "completed")
            .where(ScanRun.pr_number.is_not(None))
            .where(ScanRun.feedback_status == "pending")
            .order_by(ScanRun.id)
            .limit(BATCH_SIZE)
        )).scalars().all())


async def _set_feedback_status(scan_id: str, status: str) -> None:
    async with get_session() as session:
        await session.execute(
            update(ScanRun).where(ScanRun.id == scan_id).values(feedback_status=status)
        )
        await session.commit()


async def process_pending_once(*, provider=None, aegis_url: str) -> dict:
    """Process up to BATCH_SIZE pending PR scans. Return counters."""
    counters = {"processed": 0, "posted": 0, "failed": 0, "skipped": 0}

    pending = await _select_pending()

    for scan in pending:
        counters["processed"] += 1
        try:
            source = _resolve_source(scan.asset_id)
            if source is None or not getattr(source, "stored_pat", None):
                await _set_feedback_status(scan.id, "skipped")
                counters["skipped"] += 1
                _emit_audit(
                    action="pr_feedback.skipped",
                    scan_id=scan.id,
                    metadata={"reason": "no_pat", "pr_number": scan.pr_number},
                )
                continue

            # Dynamic provider per source SCM type; override allowed for tests.
            active_provider = provider if provider is not None else _resolve_pr_provider(source)
            if active_provider is None:
                await _set_feedback_status(scan.id, "skipped")
                counters["skipped"] += 1
                _emit_audit(
                    action="pr_feedback.skipped",
                    scan_id=scan.id,
                    metadata={"reason": "unsupported_scm", "scm_type": getattr(source, "scm_type", None)},
                )
                continue

            head_findings = _list_findings_for_scan(scan.id)
            base_sha = source.base_sha_for_pr(scan.pr_number) if hasattr(source, "base_sha_for_pr") else None
            base_findings = _list_findings_for_base(source.id, base_sha) if base_sha else None
            new_findings, is_first = compute_new_in_pr(
                head_findings=head_findings, base_findings=base_findings,
            )

            body = render_sticky_comment(
                scan_id=scan.id,
                aegis_url=aegis_url,
                source_id=source.id,
                pr_number=scan.pr_number,
                new_findings=new_findings,
                is_first_scan_on_base=is_first,
            )

            active_provider.post_or_update_comment(
                repo=source.id,
                pr_number=scan.pr_number,
                body=body,
                marker=MARKER_PREFIX,
                token=source.stored_pat,
            )
            await _set_feedback_status(scan.id, "posted")
            counters["posted"] += 1
            _emit_audit(
                action="pr_feedback.posted",
                scan_id=scan.id,
                metadata={
                    "pr_number": scan.pr_number,
                    "new_findings_count": len(new_findings),
                    "is_first_scan_on_base": is_first,
                },
            )

        except NotFoundError:
            await _set_feedback_status(scan.id, "skipped")
            counters["skipped"] += 1
            _emit_audit(
                action="pr_feedback.skipped",
                scan_id=scan.id,
                metadata={"reason": "pr_closed", "pr_number": scan.pr_number},
            )
        except (AuthError, RateLimitedError, TransientError) as e:
            await _set_feedback_status(scan.id, "failed")
            counters["failed"] += 1
            reason = type(e).__name__.lower().replace("error", "")
            _emit_audit(
                action="pr_feedback.failed",
                scan_id=scan.id,
                metadata={"reason": reason, "pr_number": scan.pr_number, "error": str(e)[:200]},
            )
            logger.warning("pr_feedback.failed scan_id=%s err=%s", scan.id, e)

    return counters


def _emit_audit(*, action: str, scan_id: str, metadata: dict) -> None:
    """Best-effort audit event emission. Logs and continues on failure."""
    try:
        from src.audit_log.recorder import ActorInfo, get_recorder
        get_recorder().record(
            action=action,
            resource_type="scan_run",
            resource_id=scan_id,
            actor=ActorInfo(user_id="system:pr_feedback"),
            metadata=metadata,
        )
    except Exception:
        logger.exception("audit emit failed for %s scan=%s", action, scan_id)


async def poster_loop(stop_event: asyncio.Event) -> None:
    aegis_url = os.getenv("AEGIS_PUBLIC_URL", "http://localhost:8000")
    backoff_idx = 0
    while not stop_event.is_set():
        try:
            result = await process_pending_once(provider=None, aegis_url=aegis_url)
            if result["failed"] > 0:
                delay = BACKOFF_STEPS_SECONDS[min(backoff_idx, len(BACKOFF_STEPS_SECONDS) - 1)]
                backoff_idx += 1
            else:
                delay = POLL_INTERVAL_SECONDS
                backoff_idx = 0
        except Exception:
            logger.exception("pr_feedback.poster_loop crashed; backing off")
            delay = BACKOFF_STEPS_SECONDS[min(backoff_idx, len(BACKOFF_STEPS_SECONDS) - 1)]
            backoff_idx += 1
        await _sleep_or_stop(delay, stop_event)


async def _sleep_or_stop(seconds: float, stop_event: asyncio.Event) -> None:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass
