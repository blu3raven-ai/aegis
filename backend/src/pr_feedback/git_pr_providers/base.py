"""Provider protocol and typed errors for posting PR comments."""
from __future__ import annotations

from typing import Protocol


class AuthError(Exception):
    """SCM auth failed (revoked PAT, expired, wrong scopes)."""


class NotFoundError(Exception):
    """Resource not found (PR closed/deleted, repo deleted)."""


class RateLimitedError(Exception):
    """SCM rate limit hit (caller should back off and retry)."""

    def __init__(self, retry_after_seconds: int | None = None) -> None:
        super().__init__("scm rate limited")
        self.retry_after_seconds = retry_after_seconds


class TransientError(Exception):
    """5xx or network error — caller may retry."""


class GitPrProvider(Protocol):
    def post_or_update_comment(
        self,
        *,
        repo: str,
        pr_number: int,
        body: str,
        marker: str,
        token: str,
    ) -> None:
        """Post a new comment or update the existing one matching `marker`."""
        ...

    async def resolve_pr_base_sha(
        self,
        *,
        repo: str,
        pr_number: int,
        token: str,
    ) -> str | None:
        """Return the base-commit SHA of a PR, or None on any error."""
        ...
