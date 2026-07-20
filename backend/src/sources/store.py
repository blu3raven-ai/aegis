from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from src.assets.refs import image_ref, repo_ref
from src.db.helpers import run_db
from src.db.models import SourceConnection
from src.shared.encryption import decrypt_string, encrypt_string, is_encrypted
from src.shared.paths import dt_to_iso as _dt_to_iso, now_iso as _now_iso, parse_iso_utc
from src.shared.repo_owner import owner_of
from src.shared.url_guard import UnsafeURLError, assert_sendable_url

_logger = logging.getLogger(__name__)


VALID_CATEGORIES = {"code-repositories", "container-images", "container-registry", "ci-systems"}
VALID_SOURCE_TYPES = {
    "github", "gitlab", "bitbucket", "gitea", "azure_devops",
    "docker-hub", "ghcr", "ecr", "acr", "gcr", "gitlab-registry",
    "github-actions", "gitlab-ci",
    "jenkins",
}
VALID_SCAN_SCOPES = {"all", "all-except-excluded", "selected"}
VALID_SYNC_SCHEDULES = {"1h", "3h", "6h", "12h", "24h"}
_SCHEDULE_HOURS = {"1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24}
VALID_STATUSES = {"connected", "syncing", "error", "disconnected", "not-synced"}

# Alias mapping: frontend names → canonical backend names
_CATEGORY_ALIASES: dict[str, str] = {
    "container-registry": "container-images",
}

CATEGORY_SOURCE_TYPES: dict[str, set[str]] = {
    "code-repositories": {"github", "gitlab", "bitbucket", "gitea", "azure_devops"},
    "container-images": {"ghcr", "docker-hub", "ecr", "acr", "gcr", "gitlab-registry"},
    "container-registry": {"ghcr", "docker-hub", "ecr", "acr", "gcr", "gitlab-registry"},  # alias
    # Jenkins is a CI controller, not an SCM — distinct category so the
    # connect-source wizards do not surface it as a repo-host option.
    "ci-systems": {"jenkins"},
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


def _decrypt_auth(auth: dict[str, Any], *, strict: bool = False) -> dict[str, Any]:
    """Decrypt sensitive fields in an auth dict after reading from DB.

    Backward-compatible: if a value is not Fernet-encrypted (no gAAAAA prefix),
    it is returned as-is (legacy plaintext data).

    ``strict=True`` (use paths — sync, clone) raises DecryptionError when a value
    can't be decrypted under any configured root, so the caller reports "couldn't
    decrypt credentials — key changed" instead of shipping an empty token that
    reads as "no token". Display/masking paths stay lenient so an undecryptable
    credential never 500s the sources UI.
    """
    if not auth:
        return auth
    result = dict(auth)
    for key in _SENSITIVE_AUTH_KEYS:
        value = result.get(key)
        if isinstance(value, str) and value and is_encrypted(value):
            result[key] = decrypt_string(value, strict=strict)
    return result


def normalize_category(category: str) -> str:
    """Normalize category to canonical backend name."""
    return _CATEGORY_ALIASES.get(category, category)


def _validate_scanners(category: str, scanners: Any) -> None:
    """Ensure a scanner selection only names scanners valid for the category.

    An empty list is allowed and means "all scanners applicable to the
    category" — resolved at dispatch time, so new scanners added to a category
    are picked up without a data migration.
    """
    from src.sources.triggers import SCANNERS_BY_CATEGORY

    if not isinstance(scanners, list):
        raise SourceValidationError("scanners must be a list of scanner types.")
    applicable = set(SCANNERS_BY_CATEGORY.get(category, []))
    for scanner in scanners:
        if scanner not in applicable:
            raise SourceValidationError(
                f"Scanner '{scanner}' is not applicable for category '{category}'."
            )


VALID_CONNECTION_METHODS = {"pat", "webhook", "cicd"}


def _validate_connection_methods(methods: Any) -> None:
    """Ensure the recorded connection methods are a non-empty known set."""
    if not isinstance(methods, list) or not methods:
        raise SourceValidationError("connectionMethods must be a non-empty list.")
    for method in methods:
        if method not in VALID_CONNECTION_METHODS:
            raise SourceValidationError(f"Unknown connection method: {method!r}")


class SourceValidationError(ValueError):
    pass


class SourceNotFoundError(SourceValidationError):
    pass


class SourceStoreError(RuntimeError):
    pass


def _reject_unsafe_instance_url(auth: dict[str, Any]) -> None:
    """Block SSRF at the save boundary.

    A source's ``instanceUrl`` becomes the base the runner clones/fetches from
    with the connection's token, so an internal/link-local target would
    exfiltrate that credential as HTTP basic-auth. Validate it the same way the
    live connection test does — normalizing a bare host to https:// since a
    schemeless value is otherwise rejected outright.
    """
    raw = (auth.get("instanceUrl") or "").strip()
    if not raw:
        return
    candidate = raw if raw.lower().startswith(("http://", "https://")) else f"https://{raw}"
    try:
        assert_sendable_url(candidate)
    except UnsafeURLError as exc:
        raise SourceValidationError(f"instanceUrl is not allowed: {exc}") from exc


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


def _scope_refs(conn: SourceConnection) -> list[str]:
    """Canonical asset identifiers for the items this connection actually covers.

    A cherry-pick ("selected") connection covers only ``included_items`` — the
    repos the user picked and that scan dispatch actually runs — not the full
    ``discovered_items``. Any other scope covers everything discovered. Raw
    provider names ("owner/repo" or "registry/image:tag") are mapped through the
    same ``repo_ref``/``image_ref`` helper that named the assets, so the
    per-source findings list scopes correctly. Unconvertible items are skipped.
    """
    st = (conn.source_type or "").strip().lower()
    scope = getattr(conn, "scan_scope", None)
    included = getattr(conn, "included_items", None)
    source_items = (included if scope == "selected" and included else conn.discovered_items) or []
    out: list[str] = []
    for item in source_items:
        if not isinstance(item, str) or not item.strip():
            continue
        try:
            if "/" in item and ":" not in item.rsplit("/", 1)[-1]:
                owner, name = item.split("/", 1)
                out.append(repo_ref(st, owner, name))
            elif "/" in item:
                # registry/image:tag
                registry, rest = item.split("/", 1)
                image, _, tag = rest.partition(":")
                out.append(image_ref(registry, image, tag))
        except ValueError:
            continue
    return out


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
        "includedItems": conn.included_items or [],
        "scanners": conn.scanners or [],
        "connectionMethods": conn.connection_methods or ["pat"],
        "syncSchedule": conn.sync_schedule or "6h",
        "syncScheduleMode": conn.sync_schedule_mode or "preset",
        "syncScheduleCron": conn.sync_schedule_cron,
        "scanAutoEnabled": bool(conn.scan_auto_enabled),
        "scanScheduleMode": conn.scan_schedule_mode or "preset",
        "scanSchedulePreset": conn.scan_schedule_preset or "24h",
        "scanScheduleCron": conn.scan_schedule_cron,
        "status": conn.status or "not-synced",
        "statusMessage": conn.status_message,
        "lastSyncedAt": _dt_to_iso(conn.last_synced_at),
        "nextSyncAt": _dt_to_iso(conn.next_sync_at),
        # Filled by list_connections from the latest scan_run for this org — the
        # connection row itself has no scan timestamp.
        "lastScanAt": None,
        "discoveredItemCount": conn.discovered_item_count,
        "discoveredItems": conn.discovered_items or [],
        # Canonical asset refs (display_name format) for scoping the per-source
        # findings list — see _scope_refs.
        "scopeRefs": _scope_refs(conn),
        "createdAt": _dt_to_iso(conn.created_at) or now,
        "updatedAt": _dt_to_iso(conn.updated_at) or now,
    }


def list_connections(category: str | None = None, org_id: str = "default") -> list[dict[str, Any]]:
    async def _query(session):
        from sqlalchemy import func
        from src.db.models import Asset, Finding, ScanRun

        stmt = select(SourceConnection).where(SourceConnection.org_id == org_id)
        if category:
            stmt = stmt.where(SourceConnection.category == normalize_category(category))
        conns = list((await session.execute(stmt)).scalars().all())
        dicts = [_conn_to_dict(c) for c in conns]

        # Most recent scan per org (scan_runs are tied to a connection's org via
        # metadata.org_label) so the list can show last scan alongside last sync.
        org_col = func.lower(ScanRun.metadata_json["org_label"].astext)
        rows = (
            await session.execute(select(org_col, func.max(ScanRun.started_at)).group_by(org_col))
        ).all()
        last_scan_by_org = {org: ts for org, ts in rows if org}

        # Open findings per org, bucketed by severity. Findings tie back to a
        # connection through the owner segment of the asset's external_ref
        # (source discovery never stamps source_ref) — the same owner→org signal
        # the per-source findings/scans views use.
        owner_col = func.lower(func.split_part(func.split_part(Asset.external_ref, ":", 2), "/", 1))
        finding_rows = (
            await session.execute(
                select(owner_col, Finding.severity, func.count(Finding.id))
                .join(Finding, Finding.asset_id == Asset.id)
                .where(Finding.state == "open")
                .group_by(owner_col, Finding.severity)
            )
        ).all()
        counts_by_org: dict[str, dict[str, int]] = {}
        for owner, severity, cnt in finding_rows:
            if not owner:
                continue
            bucket = counts_by_org.setdefault(owner, {"critical": 0, "high": 0, "medium": 0, "low": 0})
            if severity in bucket:
                bucket[severity] = cnt

        for conn, d in zip(conns, dicts):
            if conn.scan_scope == "selected" and conn.included_items:
                owners = {owner_of(i) for i in conn.included_items}
                agg = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                latest = None
                for o in owners:
                    for sev, n in (counts_by_org.get(o) or {}).items():
                        if sev in agg:
                            agg[sev] += n
                    ts = last_scan_by_org.get(o)
                    if ts and (latest is None or ts > latest):
                        latest = ts
                d["findingCounts"] = agg
                d["lastScanAt"] = _dt_to_iso(latest) if latest else None
            else:
                org = ((conn.auth or {}).get("orgOrOwner") or "").strip().lower()
                d["lastScanAt"] = _dt_to_iso(last_scan_by_org.get(org)) if org else None
                d["findingCounts"] = counts_by_org.get(org) or {"critical": 0, "high": 0, "medium": 0, "low": 0}
        return dicts

    return run_db(_query)


def _conn_to_dict_unmasked(conn: SourceConnection, *, strict: bool = False) -> dict[str, Any]:
    """Return connection dict with real (unmasked, decrypted) auth — for internal use only.

    ``strict`` is opt-in: single-connection use paths (sync, test) raise on an
    undecryptable credential so the caller reports it accurately. The bulk
    ``list_connections_with_secrets`` path stays lenient so one bad row doesn't
    take down scan-env resolution for every other connection.
    """
    result = _conn_to_dict(conn)
    result["auth"] = _decrypt_auth(conn.auth or {}, strict=strict)
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


def get_connection(connection_id: str, org_id: str = "default") -> dict[str, Any]:
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn or conn.org_id != org_id:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")
        return _conn_to_dict(conn)

    return run_db(_query)


def get_connection_with_secrets(connection_id: str, org_id: str = "default") -> dict[str, Any]:
    """Get connection with unmasked auth — for internal use (test/sync) only.

    Strict: an undecryptable credential raises DecryptionError so sync/test can
    report "couldn't decrypt credentials — key changed" instead of proceeding
    with an empty token that reads as "no token".
    """
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn or conn.org_id != org_id:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")
        result = _conn_to_dict(conn)
        # override masked auth with decrypted auth (strict — see docstring)
        result["auth"] = _decrypt_auth(conn.auth or {}, strict=True)
        return result

    return run_db(_query)


def count_by_category(org_id: str = "default") -> dict[str, int]:
    async def _query(session):
        result = await session.execute(
            select(SourceConnection.category, func.count())
            .where(SourceConnection.org_id == org_id)
            .group_by(SourceConnection.category)
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


def create_connection(data: dict[str, Any], org_id: str = "default") -> dict[str, Any]:
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
    _reject_unsafe_instance_url(data["auth"])

    scanners = data.get("scanners") or []
    _validate_scanners(category, scanners)

    connection_methods = data.get("connectionMethods") or ["pat"]
    _validate_connection_methods(connection_methods)

    # NEW: extract identifiers for duplicate check
    org_or_owner = (data["auth"].get("orgOrOwner") or "").strip().lower()
    instance_url = (data["auth"].get("instanceUrl") or "").strip().lower()

    async def _query(session):
        # Duplicate guard — same sourceType + orgOrOwner + instanceUrl.
        # Skip when orgOrOwner is blank: cherry-pick connections have no org
        # and should not collide with each other.
        if org_or_owner:
            existing_result = await session.execute(
                select(SourceConnection).where(SourceConnection.source_type == source_type)
            )
            for existing in existing_result.scalars().all():
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
            included_items=data.get("includedItems", []),
            scanners=scanners,
            connection_methods=connection_methods,
            # New-source defaults: sync hourly and auto-scan every 6h out of the
            # box so a freshly connected source starts producing findings without
            # manual setup. Callers may override any of these.
            sync_schedule=data.get("syncSchedule", "1h"),
            scan_auto_enabled=data.get("scanAutoEnabled", True),
            scan_schedule_preset=data.get("scanSchedulePreset", "6h"),
            status="not-synced",
            status_message=None,
            last_synced_at=None,
            next_sync_at=None,
            discovered_item_count=None,
            discovered_items=[],
            created_at=now,
            updated_at=now,
            org_id=org_id,
        )
        session.add(conn)
        await session.flush()
        return _conn_to_dict(conn)

    return run_db(_query)


def _validate_schedule_fields(data: dict[str, Any]) -> None:
    """Validate schedule modes, presets, and cron expressions before persisting."""
    from src.sources.scheduling import VALID_MODES, VALID_PRESETS, is_valid_cron

    for key in ("syncScheduleMode", "scanScheduleMode"):
        if key in data and data[key] not in VALID_MODES:
            raise SourceValidationError(f"Invalid {key}: {data[key]!r}")
    if "scanSchedulePreset" in data and data["scanSchedulePreset"] not in VALID_PRESETS:
        raise SourceValidationError(f"Invalid scan schedule preset: {data['scanSchedulePreset']!r}")
    for key in ("syncScheduleCron", "scanScheduleCron"):
        value = data.get(key)
        if value and not is_valid_cron(value):
            raise SourceValidationError(f"Invalid cron expression for {key}: {value!r}")
    # A cron-mode schedule must carry a valid cron expression.
    if data.get("syncScheduleMode") == "cron" and not (data.get("syncScheduleCron") or "").strip():
        raise SourceValidationError("Sync schedule is set to custom but no cron expression was provided.")
    if data.get("scanScheduleMode") == "cron" and not (data.get("scanScheduleCron") or "").strip():
        raise SourceValidationError("Scan schedule is set to custom but no cron expression was provided.")


def update_connection(connection_id: str, data: dict[str, Any], org_id: str = "default") -> dict[str, Any]:
    _validate_schedule_fields(data)
    if isinstance(data.get("auth"), dict):
        _reject_unsafe_instance_url(data["auth"])

    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn or conn.org_id != org_id:
            raise SourceNotFoundError(f"Connection '{connection_id}' not found.")

        if "scanners" in data:
            _validate_scanners(conn.category, data["scanners"])

        allowed_fields = {
            "auth": "auth",
            "scanScope": "scan_scope",
            "excludedItems": "excluded_items",
            "includedItems": "included_items",
            "scanners": "scanners",
            "syncSchedule": "sync_schedule",
            "syncScheduleMode": "sync_schedule_mode",
            "syncScheduleCron": "sync_schedule_cron",
            "scanAutoEnabled": "scan_auto_enabled",
            "scanScheduleMode": "scan_schedule_mode",
            "scanSchedulePreset": "scan_schedule_preset",
            "scanScheduleCron": "scan_schedule_cron",
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


def delete_connection(connection_id: str, org_id: str = "default") -> None:
    async def _query(session):
        conn = await session.get(SourceConnection, connection_id)
        if not conn or conn.org_id != org_id:
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
            conn.last_synced_at = parse_iso_utc(last_synced_at)
        if next_sync_at is not None:
            conn.next_sync_at = parse_iso_utc(next_sync_at)
        conn.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _conn_to_dict(conn)

    return run_db(_query)
