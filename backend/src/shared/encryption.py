"""Single source of truth for application-level field encryption.

Derives a per-context Fernet key from the APP_SECRET root via HKDF-SHA256.
Callers name their use site with a `context` label; mismatched contexts cannot
decrypt one another's ciphertext because the underlying keys differ. This is the
one root all at-rest encryption and app-level signing keys derive from.

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

# FASTAPI_ENV values (plus unset, "") for which an ephemeral encryption key is
# acceptable when no root is configured — local dev / CI / tests only.
_EPHEMERAL_KEY_ENVS = frozenset({"", "dev", "development", "test", "testing", "local", "ci"})


_candidate_cache: list[bytes] | None = None


def _resolve_candidate_secrets() -> list[bytes]:
    """The encryption root secret (APP_SECRET), as a one-element list.

    Returned as a list because decryption still iterates candidates — if a
    future migration needs a transitional second root, this is the one seam to
    extend. Legacy fallback roots were dropped after the one-time re-encrypt
    migration; all data is now under APP_SECRET.

    Falls back to an ephemeral key outside production so dev/test work without
    provisioning; production refuses to start without a real secret.
    """
    val = os.environ.get("APP_SECRET")
    if val:
        # The root feeds HKDF for every derived key; a low-entropy value weakens
        # all of them. 32 bytes matches the recommended `openssl rand -base64 32`.
        # Warn (don't refuse) so existing deployments aren't broken.
        if len(val.encode()) < 32:
            _logger.warning(
                "[security] the encryption root secret is short (%d bytes); use a "
                "high-entropy value such as `openssl rand -base64 32`",
                len(val.encode()),
            )
        return [val.encode()]
    # No root configured. An ephemeral key is regenerated every process start, so
    # any data written under it is lost on restart — acceptable ONLY for local
    # dev/test. Allow it for an explicit dev/test env (or unset, = local dev), but
    # refuse for anything else (staging, a mis-typed "prod", etc.) so a real
    # deployment that forgot the key fails loudly instead of silently churning
    # keys and orphaning every secret on each restart.
    env = os.environ.get("FASTAPI_ENV", "").strip().lower()
    if env in _EPHEMERAL_KEY_ENVS:
        _logger.warning(
            "[security] APP_SECRET not set (FASTAPI_ENV=%r) — using an ephemeral "
            "key for field encryption; stored secrets will not survive a restart",
            env or "<unset>",
        )
        return [secrets.token_hex(32).encode()]
    raise RuntimeError(
        f"APP_SECRET not set and FASTAPI_ENV={env!r} is not a recognised "
        f"dev/test environment — refusing to run with an ephemeral encryption key"
    )


def candidate_secrets() -> list[bytes]:
    """Candidate root secrets to try on decrypt (the current root).

    Public so the sibling ``security.crypto`` module derives keys from the same
    root, and so a future transitional-root migration has one seam to extend.
    """
    global _candidate_cache
    if _candidate_cache is None:
        _candidate_cache = _resolve_candidate_secrets()
    return _candidate_cache


def _get_base_secret() -> bytes:
    """The current (primary) root — used for all new encryption."""
    return candidate_secrets()[0]



_cipher_cache: dict[str, Fernet] = {}


def _derive_v2_key(context: str, root: bytes) -> bytes:
    """HKDF-SHA256 over ``root`` with the context as the info field.

    A fixed salt is fine here — the root is high-entropy and HKDF's info
    parameter gives per-context domain separation, which is what matters.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aegis-encryption-v2",
        info=context.encode(),
    )
    return base64.urlsafe_b64encode(hkdf.derive(root))


def _get_cipher(context: str) -> Fernet:
    if context in _cipher_cache:
        return _cipher_cache[context]
    cipher = Fernet(_derive_v2_key(context, _get_base_secret()))
    _cipher_cache[context] = cipher
    return cipher


def derive_key(context: str) -> bytes:
    """Derive a stable urlsafe-b64 32-byte key from the CURRENT root for callers
    that manage their own cipher/signer (a Fernet key, or an itsdangerous secret).
    Distinct contexts yield independent keys, so leaking one does not compromise
    the others."""
    if not context:
        raise ValueError("derive_key requires a non-empty context label")
    return _derive_v2_key(context, _get_base_secret())


# Legacy KDFs — preserved only to read pre-v2 ciphertext on disk. New writes
# always go through the v2 path. Contexts not listed here cannot decrypt legacy
# data and will raise, which is intentional (no silent guessing across domains).

def _legacy_shared_sha256_key(root: bytes) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(root).digest())


def _legacy_runner_pbkdf2_key(root: bytes) -> bytes:
    return base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", root, b"runner-job-env-vars", 100_000)
    )


_LEGACY_KDFS: dict[str, Callable[[bytes], bytes]] = {
    # Shared-domain contexts read pre-v2 entries written by the old
    # shared.encryption module (SHA256(secret) → Fernet).
    "source_connection_auth": _legacy_shared_sha256_key,
    "totp_secret": _legacy_shared_sha256_key,
    # Runner-domain context reads pre-v2 entries written by the old
    # runner.encryption module (PBKDF2-HMAC-SHA256, salt 'runner-job-env-vars').
    "runner_job_env": _legacy_runner_pbkdf2_key,
}


def _candidate_v2_ciphers(context: str) -> list[Fernet]:
    """A Fernet for ``context`` under each candidate root (current first)."""
    return [Fernet(_derive_v2_key(context, root)) for root in candidate_secrets()]


def _candidate_legacy_ciphers(context: str) -> list[Fernet]:
    """Legacy (pre-v2) Fernets for ``context`` under each candidate root."""
    kdf = _LEGACY_KDFS.get(context)
    if kdf is None:
        return []
    return [Fernet(kdf(root)) for root in candidate_secrets()]




def encrypt(plaintext: str, *, context: str) -> str:
    """Encrypt plaintext under the named context. Returns a 'v2:'-prefixed token."""
    if not plaintext:
        return plaintext
    if not context:
        raise ValueError("encrypt requires a non-empty context label")
    token = _get_cipher(context).encrypt(plaintext.encode()).decode()
    return f"{_V2_PREFIX}{token}"


class DecryptionError(RuntimeError):
    """A ciphertext could not be decrypted under any configured root/scheme.

    Distinct from a genuinely absent value: callers that must not confuse
    "can't read the secret" with "no secret stored" decrypt in ``strict`` mode
    and handle this explicitly. Only raised once the multi-root fallback has
    exhausted every candidate, so it means the encrypting root is truly gone —
    not merely that the preferred root changed.
    """


def decrypt(ciphertext: str, *, context: str, strict: bool = False) -> str:
    """Decrypt ciphertext under the named context.

    v2-prefixed tokens are tried against the HKDF-derived key of every candidate
    root (current first, then legacy roots); unversioned tokens are tried against
    the context's legacy KDF under every candidate root. Trying all candidate
    roots is what lets a root switch (e.g. #1368's move to APP_SECRET) read
    data written under a previously-preferred root instead of orphaning it.

    When no candidate matches: the default returns an empty string (display /
    tolerant paths rely on this). Pass ``strict=True`` to raise
    :class:`DecryptionError` instead, so a use path (sync, clone, 2FA verify)
    surfaces a wrong-key problem clearly rather than reading the secret as absent.
    """
    if not ciphertext:
        return ciphertext
    if not context:
        raise ValueError("decrypt requires a non-empty context label")

    if ciphertext.startswith(_V2_PREFIX):
        payload = ciphertext[len(_V2_PREFIX):].encode()
        ciphers = _candidate_v2_ciphers(context)
    else:
        ciphers = _candidate_legacy_ciphers(context)
        if not ciphers:
            # A context with no legacy KDF cannot decode unversioned data — this
            # is a misconfiguration, not a key-rotation miss, so surface it.
            raise RuntimeError(
                f"no legacy KDF declared for context {context!r}; "
                f"cannot decrypt unversioned ciphertext"
            )
        payload = ciphertext.encode()

    for cipher in ciphers:
        try:
            return cipher.decrypt(payload).decode()
        except Exception:
            continue

    if strict:
        raise DecryptionError(
            f"could not decrypt {context!r} value under any configured root — "
            f"the encryption key may have changed"
        )
    _logger.warning(
        "[security] decryption failed under context %r (no candidate root/scheme "
        "matched) — returning empty string",
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


def decrypt_string(ciphertext: str, *, strict: bool = False) -> str:
    """Decrypt a value written by encrypt_string().

    ``strict=True`` raises :class:`DecryptionError` when no configured root can
    decrypt it, instead of returning an empty string — for use paths that must
    not treat an undecryptable secret as an absent one.
    """
    return decrypt(ciphertext, context=_SOURCE_CONTEXT, strict=strict)


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
    global _candidate_cache
    _candidate_cache = None
    _cipher_cache.clear()
