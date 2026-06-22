"""Symmetric encryption for sensitive job env vars.

Delegates to the consolidated `src.shared.encryption` API under the
'runner_job_env' context. Pre-consolidation entries (raw `gAAAAA...` Fernet
tokens written with the old PBKDF2-derived key) are still readable through
the legacy KDF declared for that context.

Wire format on disk is unchanged: sensitive values are prefixed with `ENC:`
so the queue payload schema stays the same across backends.
"""
from __future__ import annotations

import logging

from src.shared.encryption import decrypt, encrypt

_logger = logging.getLogger(__name__)

SENSITIVE_KEYS: frozenset[str] = frozenset({"GIT_TOKEN", "REGISTRY_TOKEN", "REGISTRY_AUTHS"})
_ENC_PREFIX = "ENC:"
_CONTEXT = "runner_job_env"


def encrypt_env_vars(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of *env* with sensitive values encrypted."""
    result: dict[str, str] = {}
    for k, v in env.items():
        if k in SENSITIVE_KEYS and v:
            result[k] = _ENC_PREFIX + encrypt(v, context=_CONTEXT)
        else:
            result[k] = v
    return result


def decrypt_env_vars(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of *env* with ENC:-prefixed values decrypted."""
    result: dict[str, str] = {}
    for k, v in env.items():
        if isinstance(v, str) and v.startswith(_ENC_PREFIX):
            result[k] = decrypt(v[len(_ENC_PREFIX):], context=_CONTEXT)
        else:
            result[k] = v
    return result
