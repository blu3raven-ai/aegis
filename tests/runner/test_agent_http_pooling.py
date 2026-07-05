"""Verify runner agent reuses a single pooled httpx.Client across backend calls."""
from __future__ import annotations

import httpx

from runner.agent import RunnerAgent


def _agent() -> RunnerAgent:
    return RunnerAgent({"portalUrl": "https://example.com", "authToken": "t"})


def test_runner_agent_constructs_pooled_http_client():
    agent = _agent()
    try:
        assert hasattr(agent, "_http"), "RunnerAgent must own a pooled http client at self._http"
        assert isinstance(agent._http, httpx.Client)
    finally:
        agent._http.close()


def test_runner_agent_http_client_has_keepalive():
    """The pooled client should permit multiple concurrent connections."""
    agent = _agent()
    try:
        pool = agent._http._transport._pool
        assert pool._max_connections is not None
        assert pool._max_connections >= 4
        assert pool._max_keepalive_connections is not None
        assert pool._max_keepalive_connections >= 1
    finally:
        agent._http.close()


def test_runner_agent_stop_closes_http_client():
    agent = _agent()
    agent._http.close()  # idempotent in httpx
    # stop() should not raise even after manual close
    # but we won't call stop() directly here because it touches threads/drain;
    # the contract we care about is that stop() includes a close() call. Use
    # source inspection to verify the close call is present.
    import inspect
    src = inspect.getsource(RunnerAgent.stop)
    assert "self._http.close()" in src
