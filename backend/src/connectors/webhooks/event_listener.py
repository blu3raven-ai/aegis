"""WebhookScanDispatcher — EventBus listener that turns SCM webhook events
into CI scan submissions.

Receiver routes (``integrations/github|gitlab|bitbucket|azure-devops|jenkins/webhook``)
verify the HMAC signature (or bearer / basic credential, per provider),
normalize the body, then publish a typed ``code.push`` / ``code.pr_opened``
/ ``code.pr_updated`` event via ``EventPublisher``. This listener
subscribes to that bus, resolves the canonical asset and forwards the
request to ``submit_ci_scan``.

Gated behind ``AEGIS_WEBHOOK_DISPATCH_ENABLED=true``; ``start()`` is a no-op
when unset so v0.4.0 can ship the receiver surface without dispatching.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from sqlalchemy import select

from src.assets.refs import repo_ref
from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder
from src.db.engine import get_session
from src.db.models import Asset
from src.scans.service import cancel_older_queued_for_pr, find_inflight_scan, submit_ci_scan
from src.shared.event_bus import Event as SseEvent, EventBus, get_event_bus

logger = logging.getLogger(__name__)


SUBSCRIBED_EVENT_TYPES = frozenset({
    "code.push",
    "code.pr_opened",
    "code.pr_updated",
})


_FEATURE_FLAG_ENV = "AEGIS_WEBHOOK_DISPATCH_ENABLED"


def _is_enabled() -> bool:
    return os.getenv(_FEATURE_FLAG_ENV, "false").strip().lower() == "true"


def _parse_branch_from_ref(ref: str | None) -> str | None:
    """``refs/heads/main`` -> ``main``; anything else (tags, deletions) -> None."""
    if not ref or not isinstance(ref, str):
        return None
    prefix = "refs/heads/"
    if ref.startswith(prefix):
        return ref[len(prefix):]
    return None


def _split_repo_id(provider: str, repo_id: str) -> tuple[str, str] | None:
    """Return ``(owner, name)`` for ``repo_ref()`` or None if unparseable.

    GitHub/Bitbucket: flat ``owner/name``.
    GitLab: nested namespace (``group/subgroup/repo``) — owner is everything
    before the last slash to round-trip through ``repo_ref``.
    Azure DevOps: 2-segment ``project/repo`` emitted by the normalizer (the
    org/account segment is not reliably present in service-hook payloads), so
    it takes the same ``partition`` path as GitHub/Bitbucket.
    Jenkins: ``<controller_host>/<job_name>``; ``job_name`` itself may carry
    a folder path (``folder/sub/my-pipeline``), so the trailing segment is
    the canonical name and rpartition keeps the rest with the owner.
    """
    if not repo_id or "/" not in repo_id:
        return None
    if provider in ("gitlab", "jenkins"):
        owner, _, name = repo_id.rpartition("/")
    else:
        owner, _, name = repo_id.partition("/")
    if not owner or not name:
        return None
    return owner, name


def _extract_scan_args(event_type: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the (commit_sha, branch, pr_number) tuple per event type.

    Returns None when the event is structurally unusable (e.g. push with no
    after_sha — branch deletion).
    """
    if event_type == "code.push":
        commit_sha = payload.get("after_sha")
        if not commit_sha:
            return None
        return {
            "commit_sha": commit_sha,
            "branch": _parse_branch_from_ref(payload.get("ref")),
            "pr_number": None,
        }
    if event_type in ("code.pr_opened", "code.pr_updated"):
        commit_sha = payload.get("head_sha")
        pr_number = payload.get("pr_number")
        if not commit_sha or pr_number is None:
            return None
        return {
            "commit_sha": commit_sha,
            "branch": None,
            "pr_number": pr_number,
        }
    return None


class WebhookScanDispatcher:
    """EventBus listener that submits CI scans for SCM webhook events.

    Usage (from main.py lifespan):
        dispatcher = WebhookScanDispatcher()
        dispatcher.start()
        # ... on shutdown:
        dispatcher.stop()
    """

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._bus = event_bus or get_event_bus()
        self._listener_token: int | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self) -> None:
        """Subscribe to the event bus. Must be called AFTER ``EventBus.set_loop()``
        has installed the main loop (``main.py`` does this in the lifespan hook
        before any router starts). The dispatcher reuses that captured loop to
        bridge the sync listener callback back into async land.
        """
        if self._listener_token is not None:
            return
        if not _is_enabled():
            logger.info(
                "WebhookScanDispatcher: disabled — set %s=true to enable",
                _FEATURE_FLAG_ENV,
            )
            return
        # Source the loop from the bus rather than re-detecting it; the bus is
        # the single source of truth and main.py has already populated it.
        self._loop = getattr(self._bus, "_loop", None)
        if self._loop is None:
            logger.error(
                "WebhookScanDispatcher.start(): EventBus has no captured loop; refusing to start",
            )
            return
        self._listener_token = self._bus.register_listener(self._on_event)
        logger.info(
            "WebhookScanDispatcher started — subscribed to %s",
            ",".join(sorted(SUBSCRIBED_EVENT_TYPES)),
        )

    def stop(self) -> None:
        if self._listener_token is not None:
            self._bus.unregister_listener(self._listener_token)
            self._listener_token = None
            logger.info("WebhookScanDispatcher stopped")

    def _on_event(self, event: SseEvent) -> None:
        if event.event_type not in SUBSCRIBED_EVENT_TYPES:
            return
        # ``start()`` either captures a loop or refuses to register; the only
        # way ``self._loop`` is None here is if a caller hand-registered the
        # listener without going through start(). Drop the event loudly so
        # the EventBus publisher thread never blocks on asyncio.run.
        if self._loop is None:
            logger.error(
                "WebhookScanDispatcher: no loop captured, dropping event_id=%s event_type=%s",
                event.data.get("event_id"),
                event.event_type,
            )
            return
        try:
            asyncio.run_coroutine_threadsafe(self._dispatch(event), self._loop)
        except Exception:
            logger.exception(
                "WebhookScanDispatcher: failed to schedule dispatch for %s",
                event.event_type,
            )

    async def _dispatch(self, event: SseEvent) -> None:
        try:
            await self._dispatch_unchecked(event)
        except Exception:
            logger.exception(
                "WebhookScanDispatcher: dispatch failed for %s event_id=%s",
                event.event_type,
                event.data.get("event_id", "?"),
            )

    async def _dispatch_unchecked(self, event: SseEvent) -> None:
        event_type = event.event_type
        data = event.data
        payload: dict[str, Any] = data.get("payload") or {}
        source_component: str = data.get("source_component") or ""
        event_id: str = data.get("event_id", "")
        org_id: str = data.get("org_id", "")

        if not source_component.startswith("integrations."):
            logger.info(
                "webhook.dispatch: skipping unknown source_component=%r event_id=%s",
                source_component,
                event_id,
            )
            return
        provider = source_component[len("integrations."):]

        repo_id = payload.get("repo_id")
        if not repo_id or not isinstance(repo_id, str):
            logger.info(
                "webhook.dispatch: skipping event with missing repo_id event_id=%s",
                event_id,
            )
            return

        split = _split_repo_id(provider, repo_id)
        if split is None:
            logger.info(
                "webhook.dispatch: skipping event with unparseable repo_id=%r event_id=%s",
                repo_id,
                event_id,
            )
            return
        owner, name = split
        try:
            external_ref = repo_ref(provider, owner, name)
        except ValueError:
            logger.info(
                "webhook.dispatch: skipping event with unsupported provider=%r event_id=%s",
                provider,
                event_id,
            )
            return

        scan_args = _extract_scan_args(event_type, payload)
        if scan_args is None:
            logger.info(
                "webhook.dispatch: skipping %s — missing commit_sha/pr_number (event_id=%s ref=%r)",
                event_type,
                event_id,
                external_ref,
            )
            return

        async with get_session() as session:
            asset = (await session.execute(
                select(Asset).where(Asset.external_ref == external_ref)
            )).scalar_one_or_none()

        if asset is None:
            logger.info(
                "webhook.dispatch: no asset registered for external_ref=%s — skipping (event_id=%s)",
                external_ref,
                event_id,
            )
            return
        if asset.archived:
            logger.info(
                "webhook.dispatch: asset %s is archived — skipping (event_id=%s)",
                asset.id,
                event_id,
            )
            return

        # Pass org="" to match the CI router. The arg is explicitly
        # reserved/ignored today; keep the single call shape so the eventual
        # "wire org through" follow-up touches one site.
        inflight = await find_inflight_scan(
            org="",
            source_id=asset.id,
            commit_sha=scan_args["commit_sha"],
        )
        if inflight is not None:
            logger.info(
                "webhook.dispatch: duplicate scan suppressed — asset=%s commit=%s existing_scan=%s event_id=%s",
                asset.id,
                scan_args["commit_sha"],
                inflight.id,
                event_id,
            )
            return

        trigger_metadata = {
            "provider": provider,
            "event_id": event_id,
            "event_type": event_type,
            "ref": payload.get("ref"),
            "author": payload.get("author"),
        }
        # Drop None entries to keep the audit row tight.
        trigger_metadata = {k: v for k, v in trigger_metadata.items() if v is not None}

        submission = await submit_ci_scan(
            org=org_id,
            source_id=asset.id,
            commit_sha=scan_args["commit_sha"],
            branch=scan_args["branch"],
            pr_number=scan_args["pr_number"],
            triggered_by="webhook",
            trigger_metadata=trigger_metadata,
        )
        logger.info(
            "webhook.dispatch: submitted scan asset=%s commit=%s pr=%s provider=%s event_id=%s",
            asset.id,
            scan_args["commit_sha"],
            scan_args["pr_number"],
            provider,
            event_id,
        )

        # Mirror the CI router — push spam on a PR branch would otherwise
        # pile up queued scans behind the in-flight one. Wrap defensively so a
        # cancel failure can't block the audit emit; the CI router lets the
        # exception bubble to the HTTP layer, but the listener has no caller to
        # surface it to.
        if scan_args["pr_number"] is not None:
            try:
                await cancel_older_queued_for_pr(
                    org="",
                    source_id=asset.id,
                    pr_number=scan_args["pr_number"],
                    keep_scan_id=submission.scan_id,
                )
            except Exception:
                logger.exception(
                    "webhook.dispatch: cancel_older_queued_for_pr failed for scan=%s pr=%s",
                    submission.scan_id,
                    scan_args["pr_number"],
                )

        # Mirror the audit shape from the CI router so webhook-driven
        # scans show up in the same audit_log surface as CI-driven scans.
        # The dispatch is decoupled from the HTTP receiver, so request context
        # describes the synthetic origin rather than a live request.
        try:
            get_recorder().record(
                action="scan.triggered",
                resource_type="scan_run",
                resource_id=submission.scan_id,
                actor=ActorInfo(user_id=f"webhook:{provider}"),
                metadata={
                    "triggered_by": "webhook",
                    "provider": provider,
                    "event_id": event_id,
                    "event_type": event_type,
                    "source_id": asset.id,
                    "commit_sha": scan_args["commit_sha"],
                    "branch": scan_args["branch"],
                    "pr_number": scan_args["pr_number"],
                    "ref": payload.get("ref"),
                    "author": payload.get("author"),
                },
                request=RequestContext(
                    method="WEBHOOK",
                    path=f"/integrations/{provider}/webhook",
                ),
            )
        except Exception:
            logger.exception(
                "audit_log: scan.triggered emit failed for %s (webhook)",
                submission.scan_id,
            )
