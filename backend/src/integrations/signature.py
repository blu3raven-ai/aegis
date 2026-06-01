"""HMAC signature verification for each SCM webhook provider.

Each provider uses a different mechanism:
- GitHub:    HMAC-SHA256 over the raw body; header is 'sha256=<hex>'
- GitLab:    Raw token comparison; header is the token verbatim
- Bitbucket: HMAC-SHA256 over the raw body; header is 'sha256=<hex>'

All comparisons use hmac.compare_digest to prevent timing attacks.
An unconfigured secret (empty env var) always returns False so that
missing configuration is an explicit deployment error, not a silent bypass.
"""
from __future__ import annotations

import hashlib
import hmac
import os


def verify_github_signature(body: bytes, header: str) -> bool:
    """Verify GitHub's 'sha256=<hex>' HMAC-SHA256 signature."""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def verify_gitlab_signature(body: bytes, header: str) -> bool:  # noqa: ARG001
    """Verify GitLab's raw token from the X-Gitlab-Token header.

    GitLab sends the shared secret verbatim — there is no HMAC envelope.
    The body argument is accepted for interface consistency but unused.
    """
    secret = os.getenv("GITLAB_WEBHOOK_SECRET", "")
    if not secret or not header:
        return False
    return hmac.compare_digest(secret, header)


def verify_bitbucket_signature(body: bytes, header: str) -> bool:
    """Verify Bitbucket Cloud's 'sha256=<hex>' HMAC-SHA256 signature."""
    secret = os.getenv("BITBUCKET_WEBHOOK_SECRET", "")
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
