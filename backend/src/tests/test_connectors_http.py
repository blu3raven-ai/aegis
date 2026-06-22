from __future__ import annotations

import httpx

from src.connectors.http import DEFAULT_TIMEOUT_S, default_client, with_retry


def test_default_client_returns_httpx_client():
    with default_client() as client:
        assert isinstance(client, httpx.Client)


def test_default_client_uses_default_timeout():
    with default_client() as client:
        # httpx normalizes a float to a Timeout with all four phases set.
        assert client.timeout.read == DEFAULT_TIMEOUT_S
        assert client.timeout.connect == DEFAULT_TIMEOUT_S


def test_default_client_accepts_custom_timeout():
    with default_client(timeout_s=5.0) as client:
        assert client.timeout.read == 5.0


def test_with_retry_returns_immediately_on_success():
    calls = {"n": 0}

    def send():
        calls["n"] += 1
        return True, 200, None

    success, code, err = with_retry(send, backoff_s=[0, 0, 0])
    assert success is True
    assert code == 200
    assert err is None
    assert calls["n"] == 1


def test_with_retry_retries_until_success():
    attempts = iter([(False, 503, "boom"), (False, 503, "boom"), (True, 200, None)])

    def send():
        return next(attempts)

    success, code, err = with_retry(send, backoff_s=[0, 0, 0])
    assert success is True
    assert code == 200


def test_with_retry_returns_last_failure_when_exhausted():
    calls = {"n": 0}

    def send():
        calls["n"] += 1
        return False, 500, f"attempt {calls['n']}"

    success, code, err = with_retry(send, backoff_s=[0, 0])
    assert success is False
    assert code == 500
    assert err == "attempt 3"
    assert calls["n"] == 3  # initial + 2 retries from len(backoff_s)
