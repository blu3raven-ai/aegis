"""Webhook signature verification primitives.

Four providers, four algorithms:

- `verify_hmac_sha256` — covers GitHub (`X-Hub-Signature-256`) and
  Bitbucket (`X-Hub-Signature`). Body is HMAC-SHA256'd with the shared
  secret; header is `sha256=<hex>`.
- `verify_token_eq` — covers GitLab (`X-Gitlab-Token`). No HMAC envelope;
  the header carries the raw shared token.
- `verify_basic_auth` — covers Azure DevOps Services, which configures a
  `Basic` Authorization header on the subscription rather than signing
  the body. Header is `Basic <base64(user:password)>` and the decoded
  `user:password` string is compared to the shared secret.
- `verify_bearer_token` — covers Jenkins (Notification Plugin), which
  does not sign the body. Header is `Bearer <token>` and the token is
  compared to the shared secret. The `Bearer ` prefix is matched
  case-sensitively because Jenkins always emits it that way.

All four use `hmac.compare_digest` for timing-safe comparison and treat
an empty secret as an explicit deployment error, not a silent bypass.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac


def sign_hmac_sha256(body: bytes, secret: str) -> str:
    """Return the lowercase hex HMAC-SHA256 of `body` keyed by `secret`.

    Low-level primitive shared by inbound providers that verify a sha256
    header (GitHub, Bitbucket) and outbound notification signers that
    wrap the hex in their own version prefix (notifications/webhook_signing.py).
    Empty secret returns an empty string — callers must treat that as
    "no secret configured" and refuse to issue signatures."""
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_hmac_sha256(body: bytes, header: str, secret: str) -> bool:
    """Verify an `sha256=<hex>` HMAC-SHA256 signature over `body`.

    Returns False (does not raise) if anything is missing or malformed.
    Callers must treat False as authentication failure and reject the
    request — never log and continue.
    """
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + sign_hmac_sha256(body, secret)
    return hmac.compare_digest(expected, header)


def verify_token_eq(secret: str, header: str) -> bool:
    """Constant-time equality check for raw-token providers (GitLab).

    Empty secret or empty header → False. Never returns True when the
    secret hasn't been configured."""
    if not secret or not header:
        return False
    return hmac.compare_digest(secret, header)


def verify_basic_auth(secret: str, header: str) -> bool:
    """Constant-time comparison for `Authorization: Basic <base64>` headers.

    The decoded `user:password` string is compared in full to ``secret``
    so deployments can pick either half (or both, joined with `:`) as the
    shared secret as long as the value configured on the ADO subscription
    round-trips through base64 to the same string.

    Empty secret, empty header, missing `Basic ` prefix, or malformed
    base64 → False. Never returns True when the secret hasn't been
    configured."""
    if not secret or not header or not header.startswith("Basic "):
        return False
    encoded = header[len("Basic "):].strip()
    if not encoded:
        return False
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(secret, decoded)


def verify_bearer_token(secret: str, header: str) -> bool:
    """Constant-time comparison for `Authorization: Bearer <token>` headers.

    The `Bearer ` prefix is matched case-sensitively because Jenkins always
    emits it that way; accepting a case-mismatched prefix would widen the
    attack surface for header injection from intermediaries that lowercase
    the value. Empty secret, empty header, missing prefix, or empty token
    payload → False. Never returns True when the secret hasn't been
    configured."""
    if not secret or not header or not header.startswith("Bearer "):
        return False
    token = header[len("Bearer "):].strip()
    if not token:
        return False
    return hmac.compare_digest(secret, token)
