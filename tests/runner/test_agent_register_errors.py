"""Registration must surface the backend error instead of crashing on a non-JSON body."""
from __future__ import annotations

import httpx
import pytest

from runner import agent as agent_mod


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    real_client = httpx.Client

    def factory(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        kwargs.pop("timeout", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(agent_mod.httpx, "Client", factory)


def _register_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BACKEND_URL", "http://aegis:3000")
    monkeypatch.setenv("RUNNER_REGISTRATION_TOKEN", "tok")


def test_load_config_non_json_error_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain-text middleware rejection (e.g. invalid host) must not raise JSONDecodeError."""
    _register_env(monkeypatch)
    _patch_client(monkeypatch, lambda request: httpx.Response(400, text="Invalid host header"))

    with pytest.raises(RuntimeError, match="Invalid host header"):
        agent_mod.load_config()


def test_load_config_json_error_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """A structured JSON error still surfaces the `error` field."""
    _register_env(monkeypatch)
    _patch_client(
        monkeypatch,
        lambda request: httpx.Response(400, json={"error": "Invalid or expired registration token"}),
    )

    with pytest.raises(RuntimeError, match="Invalid or expired registration token"):
        agent_mod.load_config()


def test_load_config_empty_error_body_falls_back_to_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty body falls back to the HTTP status so the failure stays diagnosable."""
    _register_env(monkeypatch)
    _patch_client(monkeypatch, lambda request: httpx.Response(503, text=""))

    with pytest.raises(RuntimeError, match="HTTP 503"):
        agent_mod.load_config()
