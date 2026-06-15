import pytest


def test_state_roundtrip(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from src.auth.sso.state import decode_state, encode_state

    token = encode_state(state="abc", nonce="xyz")
    decoded = decode_state(token)
    assert decoded == {"state": "abc", "nonce": "xyz"}


def test_state_rejects_expired(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from src.auth.sso.state import decode_state, encode_state

    token = encode_state(state="abc", nonce="xyz")
    with pytest.raises(RuntimeError, match="expired"):
        decode_state(token, max_age=0)


def test_state_rejects_tampered(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from src.auth.sso.state import decode_state

    with pytest.raises(RuntimeError):
        decode_state("not-a-real-token")
