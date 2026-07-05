"""Re-encrypt every at-rest secret under the current APP_SECRET root.

Run as: python -m src.shared.reencrypt_secrets [--dry-run]

Decrypts each encrypted column and rewrites it under the current root, upgrading
any legacy-wire-format entry to a v2 token. Run it after provisioning APP_SECRET
so every at-rest secret is bound to the current root and wire format.

Idempotent and safe to re-run. A value that does not decrypt under the current
root is left untouched and counted as ``errored`` (never overwritten / lost), so
a single orphaned secret can't take the rest of the re-encryption down with it.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import (
    ArgusConnection,
    AuditStreamConfig,
    LlmConfig,
    SourceConnection,
    SsoConfig,
    User,
    WebhookEndpoint,
)
from src.security import crypto
from src.settings.webhooks.service import _context as _webhook_context
from src.shared.encryption import decrypt, decrypt_string, encrypt, encrypt_string, is_encrypted
from src.sources.store import _decrypt_auth, _encrypt_auth, _SENSITIVE_AUTH_KEYS

logger = logging.getLogger(__name__)

# Columns encrypted via security.crypto (Fernet, context "settings_secret").
_CRYPTO_COLUMNS: list[tuple[type, str]] = [
    (LlmConfig, "api_key_enc"),
    (ArgusConnection, "refresh_token_enc"),
    (SsoConfig, "oidc_client_secret_enc"),
    (SsoConfig, "saml_sp_private_key_enc"),
    (AuditStreamConfig, "auth_token_enc"),
]


@dataclass
class ReencryptStats:
    rewritten: int = 0
    skipped_empty: int = 0
    errored: int = 0
    per_target: dict[str, int] = field(default_factory=dict)

    def add(self, target: str, *, rewritten: int, skipped: int, errored: int) -> None:
        self.rewritten += rewritten
        self.skipped_empty += skipped
        self.errored += errored
        self.per_target[target] = rewritten


async def _reencrypt_crypto_columns(session: AsyncSession, dry_run: bool) -> ReencryptStats:
    stats = ReencryptStats()
    for model, column in _CRYPTO_COLUMNS:
        rewritten = skipped = errored = 0
        rows = (await session.execute(select(model))).scalars().all()
        for row in rows:
            value = getattr(row, column)
            if not value:
                skipped += 1
                continue
            try:
                plaintext = crypto.decrypt(value)
                if not dry_run:
                    setattr(row, column, crypto.encrypt(plaintext))
                rewritten += 1
            except Exception:
                logger.warning(
                    "reencrypt: %s.%s row could not be decrypted under any root — leaving as-is",
                    model.__tablename__, column,
                )
                errored += 1
        stats.add(f"{model.__tablename__}.{column}", rewritten=rewritten, skipped=skipped, errored=errored)
    return stats


async def _reencrypt_totp(session: AsyncSession, dry_run: bool) -> ReencryptStats:
    stats = ReencryptStats()
    rewritten = skipped = errored = 0
    for user in (await session.execute(select(User).where(User.totp_secret.isnot(None)))).scalars():
        value = user.totp_secret
        if not value or not is_encrypted(value):
            skipped += 1
            continue
        try:
            plaintext = decrypt_string(value, strict=True)
            if not dry_run:
                user.totp_secret = encrypt_string(plaintext)
            rewritten += 1
        except Exception:
            logger.warning("reencrypt: users.totp_secret row could not be decrypted — leaving as-is")
            errored += 1
    stats.add("users.totp_secret", rewritten=rewritten, skipped=skipped, errored=errored)
    return stats


async def _reencrypt_webhooks(session: AsyncSession, dry_run: bool) -> ReencryptStats:
    stats = ReencryptStats()
    rewritten = skipped = errored = 0
    for ep in (await session.execute(select(WebhookEndpoint))).scalars():
        value = ep.secret_enc
        if not value:
            skipped += 1
            continue
        ctx = _webhook_context(ep.provider)
        try:
            plaintext = decrypt(value, context=ctx, strict=True)
            if not dry_run:
                ep.secret_enc = encrypt(plaintext, context=ctx)
            rewritten += 1
        except Exception:
            logger.warning(
                "reencrypt: webhook_endpoints.secret_enc (provider=%s) could not be decrypted — leaving as-is",
                ep.provider,
            )
            errored += 1
    stats.add("webhook_endpoints.secret_enc", rewritten=rewritten, skipped=skipped, errored=errored)
    return stats


async def _reencrypt_source_auth(session: AsyncSession, dry_run: bool) -> ReencryptStats:
    stats = ReencryptStats()
    rewritten = skipped = errored = 0
    for conn in (await session.execute(select(SourceConnection))).scalars():
        auth = conn.auth or {}
        if not any(isinstance(auth.get(k), str) and auth.get(k) for k in _SENSITIVE_AUTH_KEYS):
            skipped += 1
            continue
        try:
            # strict decrypt so an undecryptable token raises (and is skipped)
            # instead of re-encrypting an empty value and losing the credential.
            plaintext_auth = _decrypt_auth(auth, strict=True)
            if not dry_run:
                conn.auth = _encrypt_auth(plaintext_auth)
            rewritten += 1
        except Exception:
            logger.warning(
                "reencrypt: source_connections.auth (id=%s) could not be decrypted — leaving as-is",
                conn.id,
            )
            errored += 1
    stats.add("source_connections.auth", rewritten=rewritten, skipped=skipped, errored=errored)
    return stats


async def reencrypt_all(dry_run: bool = False) -> ReencryptStats:
    """Re-encrypt every at-rest secret under the current root. Returns cumulative stats."""
    total = ReencryptStats()
    engine = create_async_engine(DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as session:
            for step in (
                _reencrypt_crypto_columns,
                _reencrypt_totp,
                _reencrypt_webhooks,
                _reencrypt_source_auth,
            ):
                s = await step(session, dry_run)
                total.rewritten += s.rewritten
                total.skipped_empty += s.skipped_empty
                total.errored += s.errored
                total.per_target.update(s.per_target)
            if not dry_run:
                await session.commit()
    finally:
        await engine.dispose()
    return total


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="Report what would change; write nothing.")
    args = parser.parse_args()

    stats = asyncio.run(reencrypt_all(dry_run=args.dry_run))
    logger.info(
        "Re-encryption %s: rewritten=%d skipped_empty=%d errored=%d",
        "(dry run)" if args.dry_run else "complete",
        stats.rewritten, stats.skipped_empty, stats.errored,
    )
    for target, n in sorted(stats.per_target.items()):
        logger.info("  %-42s %d", target, n)
    if stats.errored:
        logger.warning(
            "%d value(s) could not be decrypted under any configured root and were left "
            "untouched — check that every legacy root is still set before removing them.",
            stats.errored,
        )
    return 0 if stats.errored == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
