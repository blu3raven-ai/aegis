"""Signing and verification for outbound webhook payloads."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.connectors.webhooks.signature import sign_hmac_sha256
from src.db.helpers import run_db
from src.db.models import NotificationDestination, WebhookSigningSecret

logger = logging.getLogger(__name__)

_SIG_VERSION = "v1"
TOLERANCE_SECONDS = 300  # 5-minute replay window



def sign_payload(
    payload: dict[str, Any],
    secret: str,
    timestamp: datetime | None = None,
) -> tuple[str, str]:
    """Return (timestamp_str, signature) for one secret.

    signature format: 'v1=<hex>'
    signed string:    '{unix_ts}.{canonical_json}'
    """
    ts = timestamp or datetime.now(timezone.utc)
    ts_str = str(int(ts.timestamp()))
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signed = f"{ts_str}.{payload_str}".encode()
    return ts_str, f"{_SIG_VERSION}={sign_hmac_sha256(signed, secret)}"


def verify_signature(
    payload: dict[str, Any],
    secret: str,
    timestamp_str: str,
    signature: str,
    tolerance_seconds: int = TOLERANCE_SECONDS,
) -> bool:
    """Verify one (secret, signature) pair.

    Returns False — never raises — so callers can safely iterate over multiple
    candidate secrets without exception-driven control flow.
    """
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False

    if abs(time.time() - ts) > tolerance_seconds:
        return False

    _, expected = sign_payload(payload, secret, datetime.fromtimestamp(ts, tz=timezone.utc))
    return hmac.compare_digest(expected, signature)


def build_signing_headers(
    payload: dict[str, Any],
    raw_secrets: list[str],
) -> dict[str, str]:
    """Produce the three X-Aegis-* headers for an outbound webhook.

    All non-revoked secrets are used so receivers can verify with either key
    during a rotation window.  Returns {} when raw_secrets is empty.
    """
    if not raw_secrets:
        return {}

    ts = datetime.now(timezone.utc)
    sigs: list[str] = []
    ts_str = str(int(ts.timestamp()))
    for raw in raw_secrets:
        _, sig = sign_payload(payload, raw, ts)
        sigs.append(sig)

    return {
        "X-Aegis-Timestamp": ts_str,
        "X-Aegis-Signature": ",".join(sigs),
        "X-Aegis-Signature-Version": "1",
    }



def _secret_to_dict(row: WebhookSigningSecret) -> dict[str, Any]:
    return {
        "id": row.id,
        "channel_id": row.channel_id,
        "version": row.version,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


def list_signing_secrets(channel_id: int) -> list[dict[str, Any]]:
    """Return metadata for all secret versions (no raw values)."""
    async def _q(session):
        result = await session.execute(
            select(WebhookSigningSecret)
            .where(WebhookSigningSecret.channel_id == channel_id)
            .order_by(WebhookSigningSecret.version.desc())
        )
        return [_secret_to_dict(r) for r in result.scalars().all()]

    return run_db(_q)


def create_signing_secret(channel_id: int) -> tuple[dict[str, Any], str]:
    """Generate a new signing secret for a channel.

    Any currently active secrets are demoted to 'rotating' (still valid for
    the tolerance window) so receivers can verify against both keys during
    the handover period.

    Returns (metadata_dict, raw_secret).  raw_secret is returned exactly once
    and must be shown to the user immediately; it is never stored in plain text.
    The caller is responsible for persisting the raw value in the destination's
    config (under '_signing_secrets') so outbound signing works after restart.
    """
    raw = secrets.token_urlsafe(32)  # 256-bit URL-safe secret
    secret_hash = hashlib.sha256(raw.encode()).hexdigest()
    now = datetime.now(timezone.utc)

    async def _q(session):
        result = await session.execute(
            select(WebhookSigningSecret)
            .where(WebhookSigningSecret.channel_id == channel_id)
            .order_by(WebhookSigningSecret.version.desc())
            .limit(1)
        )
        latest = result.scalars().first()
        next_version = (latest.version + 1) if latest else 1

        active_q = await session.execute(
            select(WebhookSigningSecret).where(
                WebhookSigningSecret.channel_id == channel_id,
                WebhookSigningSecret.status == "active",
            )
        )
        for existing in active_q.scalars().all():
            existing.status = "rotating"

        new_row = WebhookSigningSecret(
            id=f"wss_{uuid.uuid4().hex[:20]}",
            channel_id=channel_id,
            secret_hash=secret_hash,
            version=next_version,
            status="active",
            created_at=now,
        )
        session.add(new_row)
        await session.flush()
        await session.refresh(new_row)
        return _secret_to_dict(new_row)

    meta = run_db(_q)
    return meta, raw


def revoke_signing_secret_version(channel_id: int, version: int) -> dict[str, Any] | None:
    """Revoke a specific version. Returns updated metadata or None if not found."""
    now = datetime.now(timezone.utc)

    async def _q(session):
        result = await session.execute(
            select(WebhookSigningSecret).where(
                WebhookSigningSecret.channel_id == channel_id,
                WebhookSigningSecret.version == version,
            )
        )
        row = result.scalars().first()
        if row is None:
            return None
        row.status = "revoked"
        row.revoked_at = now
        await session.flush()
        return _secret_to_dict(row)

    return run_db(_q)


def persist_raw_secret_to_channel(
    channel_id: int,
    version: int,
    raw: str,
) -> None:
    """Append a new raw signing secret entry to the channel config.

    Existing entries are kept (with their status) so the rotation window is
    preserved.  This is called immediately after create_signing_secret returns
    the raw value.
    """
    from sqlalchemy.orm.attributes import flag_modified
    import copy

    now_iso = datetime.now(timezone.utc).isoformat()

    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).where(
                NotificationDestination.id == channel_id,
            )
        )
        dest = result.scalars().first()
        if dest is None:
            return

        existing: list[dict[str, Any]] = copy.deepcopy(dest.config.get("_signing_secrets") or [])
        for entry in existing:
            if isinstance(entry, dict) and entry.get("status") == "active":
                entry["status"] = "rotating"

        from src.shared.encryption import encrypt_string

        # Encrypt the raw secret at rest — it's the working outbound-signing key,
        # so it must be stored like every other secret class, not in cleartext.
        existing.append(
            {"version": version, "raw": encrypt_string(raw), "status": "active", "created_at": now_iso}
        )
        dest.config = {**dest.config, "_signing_secrets": existing}
        flag_modified(dest, "config")
        await session.flush()

    run_db(_q)


def revoke_raw_secret_in_channel(channel_id: int, version: int) -> None:
    """Mark the matching version entry in channel config as revoked."""
    from sqlalchemy.orm.attributes import flag_modified

    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).where(
                NotificationDestination.id == channel_id,
            )
        )
        dest = result.scalars().first()
        if dest is None:
            return

        # Deep-copy entries so SQLAlchemy detects the change as a new object
        import copy
        entries: list[dict[str, Any]] = copy.deepcopy(dest.config.get("_signing_secrets") or [])
        for entry in entries:
            if isinstance(entry, dict) and entry.get("version") == version:
                entry["status"] = "revoked"
        dest.config = {**dest.config, "_signing_secrets": entries}
        flag_modified(dest, "config")
        await session.flush()

    run_db(_q)
