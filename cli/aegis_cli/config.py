"""Config loading: env vars > ~/.aegis/config.toml > defaults.

Priority order ensures CI/CD pipelines can override without touching disk.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_CONFIG_PATH = Path.home() / ".aegis" / "config.toml"
_CREDENTIALS_PATH = Path.home() / ".aegis" / "credentials"

_DEFAULT_BASE_URL = "https://aegis.example.org"


@dataclass
class CliConfig:
    base_url: str
    api_token: str
    default_org: str | None = None


def load_config() -> CliConfig:
    """Load configuration from env > ~/.aegis/config.toml > defaults.

    Env vars take priority so CI runners can inject secrets without
    touching any config file on disk.
    """
    file_cfg = _load_file_config()

    base_url = (
        os.environ.get("AEGIS_BASE_URL")
        or file_cfg.get("base_url")
        or _DEFAULT_BASE_URL
    )
    api_token = (
        os.environ.get("AEGIS_API_TOKEN")
        or _load_credentials_file()
        or file_cfg.get("api_token")
        or ""
    )
    default_org = (
        os.environ.get("AEGIS_DEFAULT_ORG")
        or file_cfg.get("default_org")
    )

    return CliConfig(
        base_url=base_url.rstrip("/"),
        api_token=api_token,
        default_org=default_org,
    )


def _load_file_config() -> dict:
    if not _CONFIG_PATH.exists():
        return {}
    try:
        with open(_CONFIG_PATH, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def _load_credentials_file() -> str:
    """Read a bare API token from ~/.aegis/credentials, ignoring comments."""
    if not _CREDENTIALS_PATH.exists():
        return ""
    try:
        text = _CREDENTIALS_PATH.read_text().strip()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                return stripped
    except Exception:
        pass
    return ""
