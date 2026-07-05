"""Configure registry auth for syft from the REGISTRY_AUTHS env var.

REGISTRY_AUTHS is a JSON list of {"registry": "...", "token": "...", "username": "..."}.
Writes ~/.docker/config.json so syft can pull from private registries.

Port of the inline python3 block in scanners/container/run.sh (lines 11-32)."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def configure_registry_auth(config_dir: Path | None = None) -> int:
    """Read REGISTRY_AUTHS and write <config_dir>/config.json.

    Returns the number of registries configured. If REGISTRY_AUTHS is unset,
    invalid JSON, or contains no usable entries, returns 0 without writing.

    The REGISTRY_AUTHS env var is popped after parsing so child subprocesses
    cannot read it — mirrors the ``unset REGISTRY_AUTHS`` in the bash original.
    """
    raw = os.environ.pop("REGISTRY_AUTHS", None)
    if not raw:
        return 0
    try:
        auths = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("[!] REGISTRY_AUTHS is not valid JSON: %s", e)
        return 0
    if not isinstance(auths, list):
        logger.warning("[!] REGISTRY_AUTHS must be a JSON list")
        return 0

    config: dict = {"auths": {}}
    for entry in auths:
        if not isinstance(entry, dict):
            continue
        reg = entry.get("registry", "")
        tok = entry.get("token", "")
        usr = entry.get("username") or "_token"
        if reg and tok:
            config["auths"][reg] = {"username": usr, "password": tok}

    if not config["auths"]:
        return 0

    target_dir = config_dir or (Path.home() / ".docker")
    target_dir.mkdir(parents=True, exist_ok=True)
    config_path = target_dir / "config.json"
    config_path.write_text(json.dumps(config))
    try:
        config_path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass
    return len(config["auths"])
