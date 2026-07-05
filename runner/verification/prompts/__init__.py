"""Prompt library, one module per agent role. Top-level re-exports for back-compat."""
from __future__ import annotations

from runner.verification.prompts.sast import (
    HUNTER_SYSTEM,
    SKEPTIC_SYSTEM,
    hunter_user_message,
    skeptic_user_message,
)

__all__ = (
    "HUNTER_SYSTEM",
    "SKEPTIC_SYSTEM",
    "hunter_user_message",
    "skeptic_user_message",
)
