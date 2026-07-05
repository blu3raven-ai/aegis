"""Prompt library, one module per agent role. Top-level re-exports for back-compat."""
from __future__ import annotations

from argus.verification.prompts.sast import (
    HUNTER_SYSTEM,
    SKEPTIC_SYSTEM,
    hunter_user_message,
    skeptic_user_message,
)
from argus.verification.prompts.secrets import (
    HUNTER_SYSTEM_SECRET,
    SKEPTIC_SYSTEM_SECRET,
    hunter_secret_user_message,
    skeptic_secret_user_message,
)

__all__ = (
    "HUNTER_SYSTEM",
    "SKEPTIC_SYSTEM",
    "hunter_user_message",
    "skeptic_user_message",
    "HUNTER_SYSTEM_SECRET",
    "SKEPTIC_SYSTEM_SECRET",
    "hunter_secret_user_message",
    "skeptic_secret_user_message",
)
