"""Verify runner heartbeat payload no longer emits vestigial fields."""
from __future__ import annotations

import inspect

from runner import agent


def test_runner_agent_has_no_get_active_containers_method():
    """The synthetic container-name emitter is gone after the embedded migration."""
    assert not hasattr(agent.RunnerAgent, "_get_active_containers")


def test_heartbeat_loop_does_not_reference_active_containers():
    """The heartbeat_loop body must not emit `activeContainers` or `scannerImages`."""
    src = inspect.getsource(agent.RunnerAgent.heartbeat_loop)
    assert "activeContainers" not in src
    assert "scannerImages" not in src
