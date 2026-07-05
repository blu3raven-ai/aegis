"""The re-encrypt command rewraps every at-rest secret under the current root.

The DB iteration is thin SQLAlchemy plumbing; the security-critical invariant is
that re-encrypting a value (decrypt → re-encrypt under the current root) upgrades
any legacy-wire-format entry to a v2 token that decodes under the current root.
These tests lock that invariant for both encryption modules the command uses,
plus a sanity check on the target registry.
"""
from __future__ import annotations

import base64
import hashlib
import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from cryptography.fernet import Fernet  # noqa: E402

from src.security import crypto  # noqa: E402
from src.shared import encryption as shared_enc  # noqa: E402
import src.shared.reencrypt_secrets as rc  # noqa: E402


def _set_root(monkeypatch, value: str) -> None:
    """Point APP_SECRET (the sole root) at ``value`` and reset the cache."""
    monkeypatch.setenv("APP_SECRET", value)
    shared_enc._reset_cache_for_tests()


def test_crypto_reencrypt_rewraps_under_current_root(monkeypatch):
    """A settings secret re-encrypted (decrypt → re-encrypt under the current root)
    still decodes — the rewrap round-trip the command relies on."""
    try:
        _set_root(monkeypatch, "root-value-a")
        ct = crypto.encrypt("api-key-secret")
        ct_rewrapped = crypto.encrypt(crypto.decrypt(ct))
        assert crypto.decrypt(ct_rewrapped) == "api-key-secret"
    finally:
        shared_enc._reset_cache_for_tests()


def test_shared_reencrypt_upgrades_legacy_wire_to_v2(monkeypatch):
    """A pre-v2 (legacy-KDF) ciphertext, re-encrypted, becomes a v2 token that
    decodes under the current root — the wire-format upgrade the command performs."""
    ctx = "source_connection_auth"
    try:
        _set_root(monkeypatch, "root-value-a")
        # Write a legacy (pre-v2) token the way the old shared module did.
        legacy_key = base64.urlsafe_b64encode(hashlib.sha256(b"root-value-a").digest())
        ct_legacy = Fernet(legacy_key).encrypt(b"ghp_token").decode()
        assert not ct_legacy.startswith("v2:")

        # Re-encrypt: decrypt (legacy KDF) → encrypt (v2), what the command does.
        ct_v2 = shared_enc.encrypt(
            shared_enc.decrypt(ct_legacy, context=ctx, strict=True), context=ctx
        )
        assert ct_v2.startswith("v2:")
        assert shared_enc.decrypt(ct_v2, context=ctx, strict=True) == "ghp_token"
    finally:
        shared_enc._reset_cache_for_tests()


def test_target_registry_covers_the_known_crypto_columns():
    targets = {f"{m.__tablename__}.{c}" for m, c in rc._CRYPTO_COLUMNS}
    assert targets == {
        "llm_config.api_key_enc",
        "argus_connection.refresh_token_enc",
        "sso_config.oidc_client_secret_enc",
        "sso_config.saml_sp_private_key_enc",
        "audit_stream_config.auth_token_enc",
    }
