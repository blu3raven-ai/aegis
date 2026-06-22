"""Single source of truth for application-level field encryption.

Derives a per-context Fernet key from RUNNER_ENCRYPTION_KEY via HKDF-SHA256.
Callers name their use site with a `context` label; mismatched contexts cannot
decrypt one another's ciphertext because the underlying keys differ.

Wire format:

    v2:<urlsafe-b64 fernet token>

Legacy entries written before consolidation are still readable. The legacy
KDF used for a given context is declared in `_LEGACY_KDFS` below — there is no
silent multi-KDF fallback. A context with no legacy KDF rejects legacy data
loudly rather than guessing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from typing import Any, Callable

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_logger = logging.getLogger(__name__)

# Bumped whenever the v2 KDF or wire format changes — current implementations
# read this for sanity checks only; the prefix in the ciphertext is what
# actually selects the decoder.
_V2_PREFIX = "v2:"


_base_secret: bytes | None = None


def _get_base_secret() -> bytes:
    """Read RUNNER_ENCRYPTION_KEY once and cache.

    Falls back to an ephemeral random key outside production so dev/test work
    without provisioning. Production refuses to start without a real secret.

    JWT_SHARED_SECRET is accepted for one transitional release.
    """
    global _base_secret
    if _base_secret is not None:
        return _base_secret

    secret = os.environ.get("RUNNER_ENCRYPTION_KEY") or os.environ.get("JWT_SHARED_SECRET", "")
    if not secret:
        if os.environ.get("FASTAPI_ENV") != "production":
            secret = secrets.token_hex(32)
            _logger.warning(
                "[security] RUNNER_ENCRYPTION_KEY not set — using ephemeral key for field encryption"
            )
        else:
            raise RuntimeError(
                "RUNNER_ENCRYPTION_KEY not set — cannot encrypt sensitive fields"
            )

    _base_secret = secret.encode()
    return _base_secret



_cipher_cache: dict[str, Fernet] = {}


def _derive_v2_key(context: str) -> bytes:
    """HKDF-SHA256 over the base secret with the context as the info field.

    A fixed salt is fine here — the base secret is high-entropy and HKDF's
    info parameter gives us per-context domain separation, which is what
    matters for this consolidation.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aegis-encryption-v2",
        info=context.encode(),
    )
    raw = hkdf.derive(_get_base_secret())
    return base64.urlsafe_b64encode(raw)


def _get_cipher(context: str) -> Fernet:
    if context in _cipher_cache:
        return _cipher_cache[context]
    cipher = Fernet(_derive_v2_key(context))
    _cipher_cache[context] = cipher
    return cipher


# Legacy KDFs — preserved only to read pre-v2 ciphertext on disk. New writes
# always go through the v2 path. Contexts not listed here cannot decrypt legacy
# data and will raise, which is intentional (no silent guessing across domains).

def _legacy_shared_sha256_key() -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(_get_base_secret()).digest())


def _legacy_runner_pbkdf2_key() -> bytes:
    return base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", _get_base_secret(), b"runner-job-env-vars", 100_000)
    )


_LEGACY_KDFS: dict[str, Callable[[], bytes]] = {
    # Shared-domain contexts read pre-v2 entries written by the old
    # shared.encryption module (SHA256(secret) → Fernet).
    "source_connection_auth": _legacy_shared_sha256_key,
    "totp_secret": _legacy_shared_sha256_key,
    # Runner-domain context reads pre-v2 entries written by the old
    # runner.encryption module (PBKDF2-HMAC-SHA256, salt 'runner-job-env-vars').
    "runner_job_env": _legacy_runner_pbkdf2_key,
}


def _legacy_cipher(context: str) -> Fernet | None:
    kdf = _LEGACY_KDFS.get(context)
    if kdf is None:
        return None
    return Fernet(kdf())




def encrypt(plaintext: str, *, context: str) -> str:
    """Encrypt plaintext under the named context. Returns a 'v2:'-prefixed token."""
    if not plaintext:
        return plaintext
    if not context:
        raise ValueError("encrypt requires a non-empty context label")
    token = _get_cipher(context).encrypt(plaintext.encode()).decode()
    return f"{_V2_PREFIX}{token}"


def decrypt(ciphertext: str, *, context: str) -> str:
    """Decrypt ciphertext under the named context.

    Routes v2-prefixed tokens through the HKDF-derived key. Legacy tokens
    (no prefix) fall back to the context's declared legacy KDF; a context
    without one cannot decrypt legacy data and raises.

    Returns an empty string on cryptographic failure (corrupt data, key
    rotation) rather than crashing the caller — matches the prior behaviour
    of decrypt_string / decrypt_env_vars.
    """
    if not ciphertext:
        return ciphertext
    if not context:
        raise ValueError("decrypt requires a non-empty context label")

    try:
        if ciphertext.startswith(_V2_PREFIX):
            payload = ciphertext[len(_V2_PREFIX):]
            return _get_cipher(context).decrypt(payload.encode()).decode()
        legacy = _legacy_cipher(context)
        if legacy is None:
            raise RuntimeError(
                f"no legacy KDF declared for context {context!r}; "
                f"cannot decrypt unversioned ciphertext"
            )
        return legacy.decrypt(ciphertext.encode()).decode()
    except RuntimeError:
        # Misconfiguration — surface loudly. Distinct from a Fernet decryption
        # error, which is data corruption / key rotation territory.
        raise
    except Exception:
        _logger.warning(
            "[security] decryption failed under context %r — returning empty string",
            context,
        )
        return ""


#
# Existing call sites named their use directly (encrypt_string, encrypt_dict,
# encrypt_env_vars). Each is now a thin wrapper that pins its own context so
# the two old modules collapse to one without churning every caller.


def is_encrypted(value: str) -> bool:
    """True if *value* looks like a v2 token or a raw Fernet token."""
    if not isinstance(value, str):
        return False
    return value.startswith(_V2_PREFIX) or value.startswith("gAAAAA")


_SOURCE_CONTEXT = "source_connection_auth"
_TOTP_CONTEXT = "totp_secret"


def encrypt_string(plaintext: str) -> str:
    """Encrypt a plaintext string for source-connection / TOTP storage.

    Both call sites historically used the shared SHA256 KDF, so they read as
    the same context. Splitting them in the future is a follow-up — at that
    point each caller would route through `encrypt(..., context=...)` directly.
    """
    return encrypt(plaintext, context=_SOURCE_CONTEXT)


def decrypt_string(ciphertext: str) -> str:
    """Decrypt a value written by encrypt_string()."""
    return decrypt(ciphertext, context=_SOURCE_CONTEXT)


def encrypt_dict(data: dict[str, Any]) -> str:
    if not data:
        return ""
    plaintext = json.dumps(data, separators=(",", ":"), sort_keys=True)
    return encrypt_string(plaintext)


def decrypt_dict(ciphertext: str) -> dict[str, Any]:
    if not ciphertext:
        return {}
    plaintext = decrypt_string(ciphertext)
    if not plaintext:
        return {}
    try:
        return json.loads(plaintext)
    except (json.JSONDecodeError, TypeError):
        _logger.warning("[security] Decrypted auth blob is not valid JSON")
        return {}


# Test-only reset hook — production callers never touch this.
def _reset_cache_for_tests() -> None:
    global _base_secret
    _base_secret = None
    _cipher_cache.clear()
