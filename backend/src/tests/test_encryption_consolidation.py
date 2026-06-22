"""Single-source-of-truth encryption — round trip, context isolation, legacy reads.

Regression suite for TODO #17. Prior to consolidation, src.shared.encryption
and src.runner.encryption each derived a Fernet key from the same secret via
a different KDF, so data written by one module silently could not be read by
the other. The fix exposes one `encrypt(value, context=...)` API in
src.shared.encryption; src.runner.encryption now delegates to it.
"""
from __future__ import annotations

import base64
import hashlib
import os

import pytest
from cryptography.fernet import Fernet

os.environ["RUNNER_ENCRYPTION_KEY"] = "test-only-encryption-secret-do-not-use-in-prod"

from src.shared import encryption as shared_enc  # noqa: E402
from src.runner.encryption import (  # noqa: E402
    SENSITIVE_KEYS,
    decrypt_env_vars,
    encrypt_env_vars,
)

# Force the cached base secret / cipher cache to pick up the env var above.
shared_enc._reset_cache_for_tests()




def test_round_trip_under_context():
    ciphertext = shared_enc.encrypt("hello", context="source_connection_auth")
    assert ciphertext.startswith("v2:")
    assert shared_enc.decrypt(ciphertext, context="source_connection_auth") == "hello"


def test_round_trip_for_every_declared_legacy_context():
    for context in ("source_connection_auth", "totp_secret", "runner_job_env"):
        ct = shared_enc.encrypt("payload-" + context, context=context)
        assert shared_enc.decrypt(ct, context=context) == "payload-" + context




def test_mismatched_context_decrypts_to_empty_string():
    """Ciphertext sealed under context A cannot be read under context B.

    Per-context HKDF means the underlying Fernet keys differ; a mismatched
    decrypt falls into the safety-net empty-string return rather than yielding
    plausible plaintext.
    """
    ciphertext = shared_enc.encrypt("secret-value", context="source_connection_auth")
    assert shared_enc.decrypt(ciphertext, context="runner_job_env") == ""




def test_runner_encrypt_env_vars_round_trip():
    """encrypt_env_vars + decrypt_env_vars in the runner module still work."""
    env = {"GIT_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaa", "OTHER": "not-secret"}
    encrypted = encrypt_env_vars(env)
    assert encrypted["GIT_TOKEN"].startswith("ENC:")
    assert encrypted["OTHER"] == "not-secret"

    decrypted = decrypt_env_vars(encrypted)
    assert decrypted == env


def test_shared_and_runner_use_same_base_secret_but_distinct_contexts():
    """The two modules now share one source of truth; their keys are isolated
    only by the context label, not by accidentally divergent KDFs.
    """
    # Encrypt a token through the runner module — that uses 'runner_job_env'.
    enc = encrypt_env_vars({"GIT_TOKEN": "abc123"})
    raw_token = enc["GIT_TOKEN"][len("ENC:"):]

    # The shared API can decrypt it when given the same context.
    assert shared_enc.decrypt(raw_token, context="runner_job_env") == "abc123"

    # And cannot decrypt it under a different context.
    assert shared_enc.decrypt(raw_token, context="source_connection_auth") == ""




def _legacy_shared_cipher() -> Fernet:
    secret = os.environ["RUNNER_ENCRYPTION_KEY"].encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret).digest()))


def _legacy_runner_cipher() -> Fernet:
    secret = os.environ["RUNNER_ENCRYPTION_KEY"].encode()
    raw = hashlib.pbkdf2_hmac("sha256", secret, b"runner-job-env-vars", 100_000)
    return Fernet(base64.urlsafe_b64encode(raw))


def test_legacy_shared_ciphertext_still_readable():
    """A pre-v2 token written by the old shared.encryption module decrypts."""
    legacy = _legacy_shared_cipher().encrypt(b"legacy-shared-value").decode()
    assert legacy.startswith("gAAAAA")
    assert shared_enc.decrypt(legacy, context="source_connection_auth") == "legacy-shared-value"


def test_legacy_runner_ciphertext_still_readable():
    """A pre-v2 token written by the old runner.encryption module decrypts."""
    legacy = _legacy_runner_cipher().encrypt(b"legacy-env-value").decode()
    assert shared_enc.decrypt(legacy, context="runner_job_env") == "legacy-env-value"


def test_legacy_runner_env_var_still_decryptable_via_runner_api():
    """End-to-end: env vars written by the old runner module still round-trip."""
    legacy = _legacy_runner_cipher().encrypt(b"old-token").decode()
    env_on_disk = {"GIT_TOKEN": "ENC:" + legacy, "OTHER": "plain"}
    decrypted = decrypt_env_vars(env_on_disk)
    assert decrypted == {"GIT_TOKEN": "old-token", "OTHER": "plain"}


def test_unknown_context_rejects_legacy_loudly():
    """A context with no declared legacy KDF refuses to guess across domains."""
    legacy = _legacy_shared_cipher().encrypt(b"value").decode()
    with pytest.raises(RuntimeError, match="no legacy KDF"):
        shared_enc.decrypt(legacy, context="brand-new-context-with-no-legacy")




def test_is_encrypted_recognises_both_formats():
    assert shared_enc.is_encrypted("v2:gAAAAAxyz") is True
    assert shared_enc.is_encrypted("gAAAAAxyz") is True
    assert shared_enc.is_encrypted("plain-string") is False
    assert shared_enc.is_encrypted("") is False


def test_empty_inputs_short_circuit():
    assert shared_enc.encrypt("", context="source_connection_auth") == ""
    assert shared_enc.decrypt("", context="source_connection_auth") == ""


def test_empty_context_rejected_loudly():
    with pytest.raises(ValueError):
        shared_enc.encrypt("x", context="")
    with pytest.raises(ValueError):
        shared_enc.decrypt("x", context="")




def test_encrypt_string_decrypt_string_round_trip():
    ct = shared_enc.encrypt_string("session-token")
    assert ct.startswith("v2:")
    assert shared_enc.decrypt_string(ct) == "session-token"


def test_encrypt_dict_decrypt_dict_round_trip():
    payload = {"token": "abc", "type": "pat"}
    ct = shared_enc.encrypt_dict(payload)
    assert shared_enc.decrypt_dict(ct) == payload
