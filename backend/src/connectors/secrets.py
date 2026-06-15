"""Secret resolution — Protocol for pluggable backends + env-backed default.

DB-backed resolution lands in PR4 when outbound senders need it; PR1 ships
only the env path because that covers every existing inbound webhook secret.
"""
from __future__ import annotations

import os
from typing import Protocol


class MissingSecretError(LookupError):
    """Raised when a required secret is missing or empty.

    Treated as a deployment error, not a silent bypass — the call site
    should propagate it, never default to a placeholder secret.
    """


class SecretResolver(Protocol):
    """Pluggable secret resolution strategy."""

    def resolve(self, key: str) -> str:
        """Return the secret stored under `key`, or raise MissingSecretError."""
        ...


class EnvSecretResolver:
    """Read secrets from process environment variables.

    Empty values raise MissingSecretError — an unconfigured env var must
    not silently become an empty secret that fails open.
    """

    def resolve(self, key: str) -> str:
        value = os.getenv(key, "")
        if not value:
            raise MissingSecretError(key)
        return value
