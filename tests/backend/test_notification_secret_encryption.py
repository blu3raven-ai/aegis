"""Notification config secrets are encrypted at rest.

Webhook HMAC signing secrets, the legacy signing secret, and Slack bearer URLs
were the only secret class stored in plaintext JSONB. They are now encrypted on
write and decrypted on read like every other secret class. Runs against
testcontainer Postgres.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import NotificationDestination
from src.notifications.destination import _encrypt_config_secrets, read_config_secret
from src.notifications.webhook_signing import persist_raw_secret_to_channel
from src.shared.encryption import is_encrypted


def test_config_secrets_encrypted_and_roundtrip():
    cfg = {"secret": "shh", "webhook_url": "https://hooks.slack.com/services/T/B/ZZZ", "url": "https://ex.test"}
    enc = _encrypt_config_secrets(cfg)
    assert enc["secret"] != "shh" and is_encrypted(enc["secret"])
    assert enc["webhook_url"] != cfg["webhook_url"] and is_encrypted(enc["webhook_url"])
    assert enc["url"] == "https://ex.test"  # non-secret key untouched
    assert read_config_secret(enc["secret"]) == "shh"
    assert read_config_secret(enc["webhook_url"]) == cfg["webhook_url"]


def test_read_tolerates_legacy_cleartext_and_empty():
    assert read_config_secret("legacy-plaintext") == "legacy-plaintext"
    assert read_config_secret("") == ""
    assert read_config_secret(None) == ""


def test_encrypt_is_idempotent():
    once = _encrypt_config_secrets({"secret": "shh"})
    twice = _encrypt_config_secrets(once)
    assert twice["secret"] == once["secret"]  # already-encrypted not re-wrapped
    assert read_config_secret(twice["secret"]) == "shh"


def test_signing_secret_persisted_encrypted():
    async def _seed(session):
        dest = NotificationDestination(destination_type="webhook", name="t", config={}, enabled=True)
        session.add(dest)
        await session.flush()
        return dest.id

    dest_id = run_db(_seed)
    try:
        persist_raw_secret_to_channel(dest_id, version=1, raw="super-secret-hmac")

        async def _read(session):
            return (
                await session.execute(
                    select(NotificationDestination.config).where(NotificationDestination.id == dest_id)
                )
            ).scalar_one()

        config = run_db(_read)
        entry = config["_signing_secrets"][0]
        assert entry["raw"] != "super-secret-hmac"          # not cleartext at rest
        assert is_encrypted(entry["raw"])                    # Fernet ciphertext
        assert read_config_secret(entry["raw"]) == "super-secret-hmac"  # recoverable for signing
    finally:
        async def _cleanup(session):
            await session.execute(delete(NotificationDestination).where(NotificationDestination.id == dest_id))

        run_db(_cleanup)
