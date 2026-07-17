"""The saved runner config holds the auth token — it must be owner-only at rest."""
from __future__ import annotations

import stat
from unittest.mock import patch

from runner import agent


def test_save_config_is_owner_only(tmp_path):
    cfg = tmp_path / ".vuln-runner" / "config.json"
    with patch.object(agent, "CONFIG_PATH", cfg):
        agent.save_config({"authToken": "secret", "portalUrl": "https://x"})
    assert cfg.exists()
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600, oct(cfg.stat().st_mode)
