"""The saved runner config holds the auth token — it must be owner-only at rest."""
from __future__ import annotations

import stat

import pytest
from unittest.mock import patch

from runner import agent


def test_save_config_is_owner_only(tmp_path):
    cfg = tmp_path / ".vuln-runner" / "config.json"
    with patch.object(agent, "CONFIG_PATH", cfg):
        agent.save_config({"authToken": "secret", "portalUrl": "https://x"})
    assert cfg.exists()
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600, oct(cfg.stat().st_mode)


def test_configure_container_storage_uses_overlay_when_fuse_present(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(agent.os.path, "exists", lambda p: p == "/dev/fuse")
    monkeypatch.setattr(agent.shutil, "which", lambda n: "/usr/bin/fuse-overlayfs")
    agent.configure_container_storage()
    conf = tmp_path / ".config" / "containers" / "storage.conf"
    assert conf.exists()
    text = conf.read_text()
    assert 'driver = "overlay"' in text and "fuse-overlayfs" in text


def test_configure_container_storage_noop_without_fuse(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    agent.configure_container_storage()
    assert not (tmp_path / ".config" / "containers" / "storage.conf").exists()


def test_execute_job_rejects_unsafe_job_id():
    # The jobId guard is the first statement in _execute_job, before any use of
    # self, so a forged '../' payload is refused before it can touch the filesystem.
    obj = agent.RunnerAgent.__new__(agent.RunnerAgent)
    with pytest.raises(ValueError):
        obj._execute_job({"jobId": "../../etc/passwd"})
