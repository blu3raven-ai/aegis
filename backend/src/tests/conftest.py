"""Shared pytest fixtures and configuration for unit tests.

Sets DATABASE_URL before any module imports so that db/engine.py doesn't
raise at collection time. Tests that mock run_db never touch the real DB.
"""
from __future__ import annotations

import os

# Must be set before any src.db.* imports — engine.py raises at module level
# if DATABASE_URL is absent.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)
