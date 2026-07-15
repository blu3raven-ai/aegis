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

os.environ["APP_SECRET"] = "test-only-encryption-secret-do-not-use-in-prod"

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
    env = {
        "GIT_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaa",
        "ARGUS_TOKEN": "argus-short-lived-access-token",
        "LLM_API_KEY": "sk-secret-model-key",
        "OTHER": "not-secret",
    }
    encrypted = encrypt_env_vars(env)
    assert encrypted["GIT_TOKEN"].startswith("ENC:")
    assert encrypted["ARGUS_TOKEN"].startswith("ENC:")
    # The BYO LLM key must not ride the job queue in cleartext (transit leak).
    assert encrypted["LLM_API_KEY"].startswith("ENC:")
    assert "sk-secret-model-key" not in encrypted["LLM_API_KEY"]
    assert {"ARGUS_TOKEN", "LLM_API_KEY"} <= SENSITIVE_KEYS
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
    secret = os.environ["APP_SECRET"].encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret).digest()))


def _legacy_runner_cipher() -> Fernet:
    secret = os.environ["APP_SECRET"].encode()
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




# ── consolidation: crypto + federation derive from the single APP_SECRET root


def test_derive_key_is_context_isolated_and_fernet_valid():
    k1 = shared_enc.derive_key("settings_secret")
    k2 = shared_enc.derive_key("federation_state")
    assert k1 != k2
    Fernet(k1).encrypt(b"x")  # usable as a Fernet key
    with pytest.raises(ValueError):
        shared_enc.derive_key("")


def test_settings_crypto_round_trips_from_root():
    from src.security import crypto

    ct = crypto.encrypt("integration-secret")
    assert crypto.decrypt(ct) == "integration-secret"
    assert crypto.decrypt(None) is None


def test_settings_crypto_raises_loudly_when_no_candidate_root_matches(monkeypatch):
    """When NO configured root can decrypt (the encrypting root is fully rotated
    away), fail loudly — never silently return garbage."""
    from src.security import crypto

    ct = crypto.encrypt("under-root-A")
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.setenv("APP_SECRET", "a-totally-different-root-value")
    shared_enc._reset_cache_for_tests()
    try:
        with pytest.raises(RuntimeError, match="decryption failed"):
            crypto.decrypt(ct)
    finally:
        shared_enc._reset_cache_for_tests()


def test_shared_encryption_returns_empty_when_no_candidate_root_matches(monkeypatch):
    """No candidate root/scheme matches → empty string (lenient default), not a
    crash. Phase 2 wires strict=True for use paths."""
    ct = shared_enc.encrypt("pat-value", context="source_connection_auth")
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.setenv("APP_SECRET", "a-totally-different-root-value")
    shared_enc._reset_cache_for_tests()
    try:
        assert shared_enc.decrypt(ct, context="source_connection_auth") == ""
    finally:
        shared_enc._reset_cache_for_tests()


def test_federation_state_round_trips_from_root():
    from src.auth.federation.state import decode_state, encode_state

    token = encode_state(state="s-value", nonce="n-value")
    assert decode_state(token) == {"state": "s-value", "nonce": "n-value"}


def test_aegis_secret_key_alone_is_sufficient(monkeypatch):
    """A fresh install that sets only APP_SECRET can encrypt and decrypt —
    no separate encryption key needed."""
    from src.security import crypto

    monkeypatch.setenv("APP_SECRET", "sole-root-secret-value")
    shared_enc._reset_cache_for_tests()
    try:
        ct = crypto.encrypt("secret")
        assert crypto.decrypt(ct) == "secret"
    finally:
        shared_enc._reset_cache_for_tests()


def test_shared_encryption_strict_raises_when_no_candidate_root_matches(monkeypatch):
    """Phase 2: strict=True raises DecryptionError instead of returning "" when
    no configured root can decrypt — so use paths report a key problem clearly."""
    ct = shared_enc.encrypt("pat-value", context="source_connection_auth")
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.setenv("APP_SECRET", "a-totally-different-root-value")
    shared_enc._reset_cache_for_tests()
    try:
        with pytest.raises(shared_enc.DecryptionError):
            shared_enc.decrypt(ct, context="source_connection_auth", strict=True)
        # Lenient default still returns "" for the same input.
        assert shared_enc.decrypt(ct, context="source_connection_auth") == ""
    finally:
        shared_enc._reset_cache_for_tests()


def test_source_decrypt_auth_strict_raises_on_undecryptable_token(monkeypatch):
    """The source use-path (_decrypt_auth strict=True) raises so sync reports
    'couldn't decrypt credentials' instead of shipping an empty token."""
    from src.sources import store

    auth = {"token": shared_enc.encrypt("ghp_x", context="source_connection_auth")}
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.setenv("APP_SECRET", "a-totally-different-root-value")
    shared_enc._reset_cache_for_tests()
    try:
        with pytest.raises(shared_enc.DecryptionError):
            store._decrypt_auth(auth, strict=True)
        # Lenient (display) path masks the empty value without raising.
        assert store._decrypt_auth(auth)["token"] == ""
    finally:
        shared_enc._reset_cache_for_tests()


def test_verify_totp_raises_when_stored_secret_cannot_decrypt(monkeypatch):
    """Phase 5b: a wrong/rotated key surfaces as DecryptionError (→ '2FA
    unavailable') instead of silently rejecting every valid code as 'wrong'."""
    from src.shared.totp import verify_totp

    enc = shared_enc.encrypt_string("JBSWY3DPEHPK3PXP")  # a base32 TOTP secret
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.setenv("APP_SECRET", "a-totally-different-root-value")
    shared_enc._reset_cache_for_tests()
    try:
        with pytest.raises(shared_enc.DecryptionError):
            verify_totp(enc, "000000")
        # A plaintext (unencrypted) secret is verified without any decrypt.
        assert verify_totp("JBSWY3DPEHPK3PXP", "000000") is False
    finally:
        shared_enc._reset_cache_for_tests()


def test_ephemeral_key_refused_outside_dev(monkeypatch):
    """No root + a non-dev FASTAPI_ENV (staging, mis-typed prod) refuses to run
    on an ephemeral key; dev/test/unset still get one."""
    monkeypatch.delenv("APP_SECRET", raising=False)
    try:
        for bad in ("staging", "prod", "Production "):
            monkeypatch.setenv("FASTAPI_ENV", bad)
            shared_enc._reset_cache_for_tests()
            with pytest.raises(RuntimeError, match="ephemeral"):
                shared_enc.candidate_secrets()
        for ok in ("dev", "test", ""):
            monkeypatch.setenv("FASTAPI_ENV", ok)
            shared_enc._reset_cache_for_tests()
            assert len(shared_enc.candidate_secrets()) == 1  # ephemeral allowed
    finally:
        monkeypatch.delenv("FASTAPI_ENV", raising=False)
        shared_enc._reset_cache_for_tests()
