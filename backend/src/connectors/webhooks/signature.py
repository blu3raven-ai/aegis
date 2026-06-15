"""Webhook signature verification primitives.

Two providers, two algorithms:

- `verify_hmac_sha256` — covers GitHub (`X-Hub-Signature-256`) and
  Bitbucket (`X-Hub-Signature`). Body is HMAC-SHA256'd with the shared
  secret; header is `sha256=<hex>`.
- `verify_token_eq` — covers GitLab (`X-Gitlab-Token`). No HMAC envelope;
  the header carries the raw shared token.

Both use `hmac.compare_digest` for timing-safe comparison and treat an
empty secret as an explicit deployment error, not a silent bypass.
"""
from __future__ import annotations

import hashlib
import hmac


def verify_hmac_sha256(body: bytes, header: str, secret: str) -> bool:
    """Verify an `sha256=<hex>` HMAC-SHA256 signature over `body`.

    Returns False (does not raise) if anything is missing or malformed.
    Callers must treat False as authentication failure and reject the
    request — never log and continue.
    """
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def verify_token_eq(secret: str, header: str) -> bool:
    """Constant-time equality check for raw-token providers (GitLab).

    Empty secret or empty header → False. Never returns True when the
    secret hasn't been configured."""
    if not secret or not header:
        return False
    return hmac.compare_digest(secret, header)
