"""Runner registration, approval, token management, heartbeat tracking."""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Any

from src.runner.storage import (
    delete_runner,
    generate_auth_token,
    generate_registration_token,
    hash_token,
    list_runners,
    read_runner,
    validate_registration_token,
    write_runner,
)
from src.shared.paths import now_iso


import logging

logger = logging.getLogger(__name__)

HEARTBEAT_ONLINE_SECONDS = 60
HEARTBEAT_STALE_SECONDS = 120
AUTO_ARCHIVE_DAYS = 30


def create_registration_token() -> tuple[str, dict[str, Any]]:
    return generate_registration_token()


def register_runner(
    raw_token: str,
    name: str,
    os_name: str = "",
    arch: str = "",
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Register a new runner using a registration token.

    Accepts either:
    - A one-time DB-issued registration token (from admin UI)
    - The pre-shared RUNNER_REGISTRATION_TOKEN env var (reusable, for Docker Compose)

    Returns (runner_record, raw_auth_token, error_message).
    """
    # Check DB-issued one-time token
    token_record = validate_registration_token(raw_token)

    # Check pre-shared RUNNER_REGISTRATION_TOKEN (reusable for compose runners)
    local_token = os.environ.get("RUNNER_REGISTRATION_TOKEN", "")
    if local_token and local_token in ("change-me", "default"):
        logger.warning("RUNNER_REGISTRATION_TOKEN is using a default value — change it in production")
    is_local = bool(local_token and raw_token == local_token)

    if not token_record and not is_local:
        return None, None, "Invalid or expired registration token"

    raw_auth, auth_hash = generate_auth_token()

    # For compose runners: idempotent by name — reuse existing runner on restart
    if is_local and name:
        existing = _find_runner_by_name(name)
        if existing:
            existing["authTokenHash"] = auth_hash
            existing["lastHeartbeatAt"] = now_iso()
            if os_name:
                existing["os"] = os_name
            if arch:
                existing["arch"] = arch
            write_runner(existing)
            return existing, raw_auth, None

    runner_id = f"runner-{secrets.token_hex(8)}"

    runner: dict[str, Any] = {
        "id": runner_id,
        "name": name or runner_id,
        "status": "pending_approval",
        "os": os_name,
        "arch": arch,
        "registeredAt": now_iso(),
        "approvedAt": None,
        "lastHeartbeatAt": now_iso(),
        "jobsCompleted": 0,
        "authTokenHash": auth_hash,
    }
    # Auto-approve compose runners (token matches RUNNER_REGISTRATION_TOKEN env var)
    if is_local:
        runner["status"] = "approved"
        runner["approvedAt"] = now_iso()

    write_runner(runner)
    return runner, raw_auth, None


def _find_runner_by_name(name: str) -> dict[str, Any] | None:
    """Find an existing runner by name. Prefers approved runners over pending/stale ones."""
    matches = [r for r in list_runners() if r.get("name") == name]
    if not matches:
        return None
    # Prefer approved runner (avoids matching a stale/orphaned entry)
    for r in matches:
        if r.get("status") == "approved":
            return r
    return matches[0]


def authenticate_runner(raw_token: str) -> dict[str, Any] | None:
    """Authenticate a runner by its server-issued auth token."""
    token_hash = hash_token(raw_token)
    for runner in list_runners():
        if runner.get("authTokenHash") == token_hash:
            return runner
    return None


def heartbeat(runner_id: str, metrics: dict[str, Any] | None = None) -> dict[str, Any] | None:
    runner = read_runner(runner_id)
    if not runner:
        return None
    runner["lastHeartbeatAt"] = now_iso()
    write_runner(runner)

    # Store metrics if provided
    if metrics:
        from src.runner.storage import update_runner_metrics, record_heartbeat
        update_runner_metrics(runner_id, metrics)
        record_heartbeat(runner_id, metrics.get("cpuPercent"), metrics.get("memoryUsedGb"))

    # Prune old heartbeats periodically (1 in 10 chance)
    import random
    if random.random() < 0.1:
        from src.runner.storage import prune_old_heartbeats
        prune_old_heartbeats()

    # Re-read to get updated metrics
    return read_runner(runner_id)


def approve_runner(runner_id: str) -> dict[str, Any] | None:
    runner = read_runner(runner_id)
    if not runner:
        return None
    runner["status"] = "approved"
    runner["approvedAt"] = now_iso()
    write_runner(runner)
    return runner


def revoke_runner(runner_id: str) -> dict[str, Any] | None:
    runner = read_runner(runner_id)
    if not runner:
        return None
    runner["status"] = "pending_approval"
    runner["approvedAt"] = None
    runner["authTokenHash"] = hash_token(secrets.token_hex(32))
    write_runner(runner)
    return runner


def remove_runner(runner_id: str) -> bool:
    runner = read_runner(runner_id)
    if not runner:
        return False
    delete_runner(runner_id)
    return True


def rotate_auth_token(runner_id: str) -> tuple[str | None, str | None]:
    runner = read_runner(runner_id)
    if not runner:
        return None, "Runner not found"
    raw, token_hash = generate_auth_token()
    runner["authTokenHash"] = token_hash
    write_runner(runner)
    return raw, None


def compute_runner_status(runner: dict[str, Any]) -> str:
    base_status = runner.get("status", "pending_approval")
    if base_status == "pending_approval":
        return "pending_approval"
    if base_status == "archived":
        return "archived"

    last_hb = runner.get("lastHeartbeatAt", "")
    if not last_hb:
        return "offline"

    try:
        hb_time = datetime.fromisoformat(last_hb.replace("Z", "+00:00"))
        elapsed = (datetime.now(timezone.utc) - hb_time).total_seconds()
    except (ValueError, TypeError):
        return "offline"

    if elapsed <= HEARTBEAT_ONLINE_SECONDS:
        return "online"
    if elapsed <= HEARTBEAT_STALE_SECONDS:
        return "stale"
    return "offline"


def list_runners_with_status() -> list[dict[str, Any]]:
    from src.runner.storage import count_heartbeats
    runners = list_runners()
    for runner in runners:
        runner["computedStatus"] = compute_runner_status(runner)

        # Health starts at 100%, decreases for each missed heartbeat.
        # Only measure over the time the runner has actually been up (max 60 min).
        registered = runner.get("registeredAt", "")
        try:
            reg_time = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            uptime_minutes = min(60, (datetime.now(timezone.utc) - reg_time).total_seconds() / 60)
        except (ValueError, TypeError):
            uptime_minutes = 60

        if uptime_minutes < 1:
            runner["healthPercent"] = 100
        else:
            window = max(1, int(uptime_minutes))
            expected = window * 2  # 1 heartbeat every 30s = 2 per minute
            received = count_heartbeats(runner["id"], window_minutes=window)
            missed = max(0, expected - received)
            runner["healthPercent"] = max(0, round(100 - (missed / expected) * 100))

    return runners


def list_approved_online_runners() -> list[dict[str, Any]]:
    return [
        r for r in list_runners_with_status()
        if r.get("status") == "approved" and r["computedStatus"] == "online"
    ]
