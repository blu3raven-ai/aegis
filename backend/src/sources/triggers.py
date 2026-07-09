"""Reusable sync/scan triggers for source connections.

Both the REST endpoints (manual "Scan now" / sync) and the AutoRerunScheduler
(per-source scheduled runs) go through these so there is a single code path for
dispatching runner jobs and refreshing a connection's discovery state.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from src.sources import store as sources_store
from src.sources.test_connection import test_connection

_SCHEDULE_HOURS = {"1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24}

# Which scanner job types run for each source category.
SCANNERS_BY_CATEGORY: dict[str, list[str]] = {
    "code-repositories": ["dependencies_scanning", "secret_scanning", "code_scanning", "iac_scanning", "agent_scanning"],
    "container-registry": ["container_scanning"],
    "container-images": ["container_scanning"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _next_sync_iso(schedule: str) -> str:
    hours = _SCHEDULE_HOURS.get(schedule, 6)
    dt = datetime.now(timezone.utc) + timedelta(hours=hours)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_repo_urls(source_type: str, instance_url: str, repos: list[str]) -> list[str]:
    """Map discovered repo names (owner/name) to full clone URLs for the runner."""
    if source_type == "github":
        base = "https://github.com"
    elif source_type == "gitlab":
        base = instance_url.rstrip("/") if instance_url else "https://gitlab.com"
    elif source_type == "bitbucket":
        base = "https://bitbucket.org"
    elif source_type == "gitea":
        base = instance_url.rstrip("/") if instance_url else ""
    else:
        return []
    if not base:
        return []
    return [r if r.startswith("http") else f"{base}/{r}" for r in repos]


def dispatch_source_scan(connection: dict, *, run_prefix: str = "manual") -> list[str]:
    """Dispatch runner jobs to scan every discovered item for a connection.

    `connection` must be the unmasked dict (carrying the real auth token).
    Returns the queued run IDs. Raises ValueError with a user-facing message
    when the connection isn't in a scannable state.
    """
    from src.runner.jobs import create_job
    from src.storage import (
        create_agent_run,
        create_dependencies_run,
        create_code_scanning_run,
        create_container_scanning_run,
        create_iac_run,
        create_secret_run,
    )

    run_creators = {
        "dependencies_scanning": create_dependencies_run,
        "secret_scanning": create_secret_run,
        "code_scanning": create_code_scanning_run,
        "container_scanning": create_container_scanning_run,
        "iac_scanning": create_iac_run,
        "agent_scanning": create_agent_run,
    }

    auth = connection.get("auth") or {}
    org = (auth.get("orgOrOwner") or "").strip()
    token = auth.get("token") or ""
    source_type = connection.get("sourceType") or ""
    category = connection.get("category") or ""
    discovered_items: list[str] = list(connection.get("discoveredItems") or [])

    if not org:
        raise ValueError("Source has no configured org — cannot dispatch scan")
    if not discovered_items:
        raise ValueError("No repositories discovered yet — sync the connection first")

    # Dedup: a manual scan is a no-op while one is already in flight for this
    # source, so repeated "Scan" clicks can't stack duplicate runs.
    from src.runner.jobs import has_active_jobs_for_org
    if has_active_jobs_for_org(org):
        raise ValueError("A scan is already in progress for this source — wait for it to finish before starting another.")

    scanner_types = SCANNERS_BY_CATEGORY.get(category)
    if not scanner_types:
        raise ValueError(f"Scan not supported for category: {category!r}")

    # Honour the per-connection scanner selection. An empty selection means
    # "all applicable", so new scanners added to a category are picked up
    # automatically. Order follows SCANNERS_BY_CATEGORY, not the stored list.
    selected = set(connection.get("scanners") or [])
    if selected:
        scanner_types = [s for s in scanner_types if s in selected]
        if not scanner_types:
            raise ValueError("No applicable scanners are selected for this source.")

    instance_url = auth.get("instanceUrl") or ""
    repo_urls = build_repo_urls(source_type, instance_url, discovered_items)
    if not repo_urls and category == "code-repositories":
        raise ValueError(f"Source type {source_type!r} is not supported for scan dispatch")

    git_repos_str = ",".join(repo_urls)
    run_ts = int(time.time() * 1000)
    queued: list[str] = []

    # BYO LLM verification config — the same env every scan job needs so SAST/IaC
    # findings get verified. Resolved once per dispatch; empty when disabled.
    from src.settings.llm.service import build_llm_scan_env
    llm_env = build_llm_scan_env()

    for scanner_type in scanner_types:
        run_id = f"{run_prefix}-{run_ts}-{scanner_type}"
        run_creators[scanner_type](org, run_id)

        env: dict[str, str] = {
            "GIT_TOKEN":   token,
            "GIT_REPOS":   git_repos_str,
            "ORG_LABEL":   org,
            "RUN_ID":      run_id,
            # Carried through env_vars (which persists) so ingest can resolve
            # each finding's repo asset — alongside ORG_LABEL / RUN_ID.
            "SOURCE_TYPE": source_type,
            "COMMIT_SHA":  "",
            "CONCURRENCY": "4",
            "SCAN_SCOPE":  "full_tree",
            **llm_env,
        }

        create_job(job_type=scanner_type, org=org, run_id=run_id, env_vars=env)
        queued.append(run_id)

    return queued


async def run_source_sync(connection_id: str, *, emit_events: bool = True) -> dict:
    """Re-discover items for a connection and refresh its status.

    Returns the updated connection dict. Raises SourceNotFoundError if missing.
    """
    from src.shared.encryption import DecryptionError
    from src.shared.event_bus import Event, get_event_bus

    try:
        connection = sources_store.get_connection_with_secrets(connection_id)
    except DecryptionError:
        # The stored credential can't be decrypted under any configured root
        # (the encryption key changed). Report that accurately instead of the
        # misleading "missing token" that an empty decrypt used to produce.
        return sources_store.update_connection_status(
            connection_id,
            status="disconnected",
            status_message=(
                "Stored credentials could not be decrypted — the encryption key "
                "may have changed. Re-enter the token to reconnect."
            ),
            last_synced_at=_now_iso(),
            next_sync_at=_next_sync_iso("6h"),
        )
    sources_store.update_connection_status(connection_id, status="syncing")

    result = await test_connection(connection["sourceType"], connection["auth"])

    now = _now_iso()
    next_sync = _next_sync_iso(connection.get("syncSchedule", "6h"))

    if result.success:
        updated = sources_store.update_connection_status(
            connection_id,
            status="connected",
            status_message=result.message,
            discovered_item_count=result.discovered_count,
            discovered_items=result.discovered_items,
            last_synced_at=now,
            next_sync_at=next_sync,
        )
    else:
        updated = sources_store.update_connection_status(
            connection_id,
            status="disconnected",
            status_message=result.message,
            last_synced_at=now,
            next_sync_at=next_sync,
        )

    if emit_events:
        get_event_bus().publish_sync(Event(
            event_type="source.synced",
            data={
                "connectionId": connection_id,
                "status": "connected" if result.success else "disconnected",
                "discoveredCount": result.discovered_count,
                "message": result.message,
            },
            require_admin=True,
        ))
        from src.notifications.emitter import notify_source_synced
        conn_name = connection.get("name") or connection.get("sourceType", "Unknown")
        notify_source_synced(
            connection_id=connection_id,
            connection_name=conn_name,
            success=result.success,
            message=result.message,
            discovered_count=result.discovered_count,
        )

    return updated, result
