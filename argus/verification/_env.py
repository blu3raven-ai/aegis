"""Typed env-var reader for verification budgets.

Copied from the Aegis runner's ``scanners._shared`` so the Argus service owns its
dependency and the ``argus/`` tree has no ``runner.*`` import (repo-liftable).
"""
from __future__ import annotations

import os
from typing import Any


class JobEnv:
    """Reads env vars from a job payload, falling back to ``os.environ``."""

    def __init__(self, job: dict[str, Any]) -> None:
        self._vars: dict[str, str] = job.get("envVars") or {}

    def get(self, key: str, default: str = "") -> str:
        return self._vars.get(key) or os.environ.get(key) or default

    def get_int(self, key: str, default: int) -> int:
        raw = self.get(key)
        try:
            return int(raw) if raw else default
        except ValueError:
            return default
