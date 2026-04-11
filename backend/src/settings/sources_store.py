from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from src.db.helpers import run_db
from src.db.models import SourceConnection
from src.shared.encryption import decrypt_string, encrypt_string, is_encrypted
from src.shared.paths import dt_to_iso as _dt_to_iso, now_iso as _now_iso

_logger = logging.getLogger(__name__)

VALID_CATEGORIES = {"code-repositories", "container-images", "container-registry"}
VALID_SOURCE_TYPES = {
    "github", "gitlab", "bitbucket", "gitea",
    "docker-hub", "ghcr", "ecr", "acr", "gcr", "gitlab-registry",
    "github-actions", "gitlab-ci",
}
VALID_SCAN_SCOPES = {"all", "all-except-excluded"}
VALID_SYNC_SCHEDULES = {"1h", "3h", "6h", "12h", "24h"}
_SCHEDULE_HOURS = {"1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24}
VALID_STATUSES = {"connected", "syncing", "error", "disconnected", "not-synced"}

# Alias mapping: frontend names → canonical backend names
_CATEGORY_ALIASES: dict[str, str] = {
    "container-registry": "container-images",
}

CATEGORY_SOURCE_TYPES: dict[str, set[str]] = {
    "code-repositories": {"github", "gitlab", "bitbucket", "gitea"},
    "container-images": {"ghcr", "docker-hub", "ecr", "acr", "gcr", "gitlab-registry"},
    "container-registry": {"ghcr", "docker-hub", "ecr", "acr", "gcr", "gitlab-registry"},  # alias
}

# Auth dict keys that contain secrets and must be encrypted at rest
_SENSITIVE_AUTH_KEYS = {"token", "password", "secret"}


def _encrypt_auth(auth: dict[str, Any]) -> dict[str, Any]:
    """Encrypt sensitive fields in an auth dict before writing to DB."""
    if not auth:
        return auth
    result = dict(auth)
    for key in _SENSITIVE_AUTH_KEYS:
        value = result.get(key)
        if isinstance(value, str) and value and not is_encrypted(value):
            result[key] = encrypt_string(value)
    return result


def _decrypt_auth(auth: dict[str, Any]) -> dict[str, Any]:
    """Decrypt sensitive fields in an auth dict after reading from DB.

    Backward-compatible: if a value is not Fernet-encrypted (no gAAAAA prefix),
    it is returned as-is (legacy plaintext data).
    """
    if not auth:
        return auth
    result = dict(auth)
    for key in _SENSITIVE_AUTH_KEYS:
        value = result.get(key)
        if isinstance(value, str) and value and is_encrypted(value):
            result[key] = decrypt_string(value)
    return result


def normalize_category(category: str) -> str:
    """Normalize category to canonical backend name."""
    return _CATEGORY_ALIASES.get(category, category)


class SourceValidationError(ValueError):
    pass


class SourceNotFoundError(SourceValidationError):
    pass


class SourceStoreError(RuntimeError):
    pass


def _mask_auth(auth: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive fields in auth dict for API responses.

    Decrypts first (if encrypted), then masks so the last-4 hint is from
    the real plaintext, not the ciphertext.
    """
    decrypted = _decrypt_auth(auth)
    masked = dict(decrypted)
    if "token" in masked and masked["token"]:
        token = str(masked["token"])
        masked["token"] = f"{'*' * 8}{token[-4:]}" if len(token) > 4 else "****"
    return masked


def _conn_to_dict(conn: SourceConnection) -> dict[str, Any]:
    now = _now_iso()
    return {
        "id": conn.id,
        "category": conn.category,
        "sourceType": conn.source_type,
        "name": conn.name,
        "auth": _mask_auth(conn.auth or {}),
        "scanScope": conn.scan_scope or "all",
        "excludedItems": conn.excluded_items or [],
        "syncSchedule": conn.sync_schedule or "6h",
        "status": conn.status or "not-synced",
        "statusMessage": conn.status_message,
        "lastSyncedAt": _dt_to_iso(conn.last_synced_at),
        "nextSyncAt": _dt_to_iso(conn.next_sync_at),
        "discoveredItemCount": conn.discovered_item_count,
        "discoveredItems": conn.discovered_items or [],
        "createdAt": _dt_to_iso(conn.created_at) or now,
        "updatedAt": _dt_to_iso(conn.updated_at) or now,
    }


def list_connections(category: str | None = None) -> list[dict[str, Any]]:
    async def _query(session):
        stmt = select(SourceConnection)
        if category:
            stmt = stmt.where(SourceConnection.category == normalize_category(category))
        result = await session.execute(stmt)
        return [_conn_to_dict(c) for c in result.scalars().all()]

    return run_db(_query)


def _conn_to_dict_unmasked(conn: SourceConnection) -> dict[str, Any]:
    """Return connection dict with real (unmasked, decrypted) auth — for internal use only."""
    result = _conn_to_dict(conn)
    result["auth"] = _decrypt_auth(conn.auth or {})
    return result


def list_connections_with_secrets(category: str | None = None) -> list[dict[str, Any]]:
    """List connections with unmasked auth — for internal scanner/sync use only."""
    async def _query(session):
        stmt = select(SourceConnection)
        if category:
            stmt = stmt.where(SourceConnection.category == normalize_category(category))
        result = await session.execute(stmt)
        return [_conn_to_dict_unmasked(c) for c in result.scalars().all()]

    return run_db(_query)


def get_connection(connection_id: str) -> dict[str, Any]:
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")
        return _conn_to_dict(conn)

    return run_db(_query)


def get_connection_with_secrets(connection_id: str) -> dict[str, Any]:
    """Get connection with unmasked auth — for internal use (test/sync) only."""
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")
        result = _conn_to_dict(conn)
        result["auth"] = _decrypt_auth(conn.auth or {})  # override masked auth with decrypted auth
        return result

    return run_db(_query)


def count_by_category() -> dict[str, int]:
    async def _query(session):
        result = await session.execute(
            select(SourceConnection.category, func.count()).group_by(SourceConnection.category)
        )
        counts: dict[str, int] = {cat: 0 for cat in VALID_CATEGORIES}
        for cat, cnt in result.all():
            if cat in counts:
                counts[cat] = cnt
        # Also include alias keys so frontend can read by either name
        _REVERSE_ALIASES = {v: k for k, v in _CATEGORY_ALIASES.items()}
        for canonical, alias in _REVERSE_ALIASES.items():
            if canonical in counts:
                counts[alias] = counts[canonical]
        return counts

    return run_db(_query)


def create_connection(data: dict[str, Any]) -> dict[str, Any]:
    raw_category = data.get("category", "")
    category = normalize_category(raw_category)
    source_type = data.get("sourceType", "")
    name = (data.get("name") or "").strip()

    if category not in VALID_CATEGORIES:
        raise SourceValidationError(f"Invalid category: {raw_category}")
    if source_type not in CATEGORY_SOURCE_TYPES.get(category, set()):
        raise SourceValidationError(f"Source type '{source_type}' is not valid for category '{category}'.")
    if not name:
        raise SourceValidationError("Connection name is required.")
    if not isinstance(data.get("auth"), dict):
        raise SourceValidationError("Auth configuration is required.")

    # NEW: extract identifiers for duplicate check
    org_or_owner = (data["auth"].get("orgOrOwner") or "").strip().lower()
    instance_url = (data["auth"].get("instanceUrl") or "").strip().lower()

    async def _query(session):
        # NEW: duplicate guard — same sourceType + orgOrOwner + instanceUrl
        existing_result = await session.execute(
            select(SourceConnection).where(SourceConnection.source_type == source_type)
        )
        for existing in existing_result.scalars().all():
            if existing.source_type != source_type:
                continue
            ex_org = ((existing.auth or {}).get("orgOrOwner") or "").strip().lower()
            ex_url = ((existing.auth or {}).get("instanceUrl") or "").strip().lower()
            if ex_org == org_or_owner and ex_url == instance_url:
                display_org = (data["auth"].get("orgOrOwner") or org_or_owner)
                raise SourceValidationError(
                    f"A {source_type} connection for '{display_org}' already exists."
                )

        now = datetime.now(timezone.utc)
        conn = SourceConnection(
            id=f"src_{secrets.token_hex(8)}",
            category=category,
            source_type=source_type,
            name=name,
            auth=_encrypt_auth(data["auth"]),
            scan_scope=data.get("scanScope", "all"),
            excluded_items=data.get("excludedItems", []),
            sync_schedule=data.get("syncSchedule", "6h"),
            status="not-synced",
            status_message=None,
            last_synced_at=None,
            next_sync_at=None,
            discovered_item_count=None,
            discovered_items=[],
            created_at=now,
            updated_at=now,
        )
        session.add(conn)
        await session.flush()
        return _conn_to_dict(conn)

    return run_db(_query)


def update_connection(connection_id: str, data: dict[str, Any]) -> dict[str, Any]:
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")

        allowed_fields = {
            "auth": "auth",
            "scanScope": "scan_scope",
            "excludedItems": "excluded_items",
            "syncSchedule": "sync_schedule",
        }
        for json_key, db_attr in allowed_fields.items():
            if json_key in data:
                value = data[json_key]
                if json_key == "auth" and isinstance(value, dict):
                    value = _encrypt_auth(value)
                setattr(conn, db_attr, value)

        # Recalculate nextSyncAt when schedule changes
        if "syncSchedule" in data and conn.last_synced_at:
            hours = _SCHEDULE_HOURS.get(data["syncSchedule"], 6)
            next_dt = conn.last_synced_at + timedelta(hours=hours)
            if next_dt <= datetime.now(timezone.utc):
                next_dt = datetime.now(timezone.utc) + timedelta(hours=hours)
            conn.next_sync_at = next_dt

        conn.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _conn_to_dict(conn)

    return run_db(_query)


def delete_connection(connection_id: str) -> None:
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")
        await session.delete(conn)

    run_db(_query)


def update_connection_status(
    connection_id: str,
    status: str,
    status_message: str | None = None,
    discovered_item_count: int | None = None,
    discovered_items: list[str] | None = None,
    last_synced_at: str | None = None,
    next_sync_at: str | None = None,
) -> dict[str, Any]:
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")

        conn.status = status
        conn.status_message = status_message
        if discovered_item_count is not None:
            conn.discovered_item_count = discovered_item_count
        if discovered_items is not None:
            conn.discovered_items = discovered_items
        if last_synced_at is not None:
            conn.last_synced_at = datetime.fromisoformat(last_synced_at.replace("Z", "+00:00"))
        if next_sync_at is not None:
            conn.next_sync_at = datetime.fromisoformat(next_sync_at.replace("Z", "+00:00"))
        conn.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _conn_to_dict(conn)

    return run_db(_query)
