import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

_dev_secret: str | None = None


def _get_dev_secret() -> str:
    """Auto-generate a random JWT secret for development. Logged once so the frontend can use it."""
    global _dev_secret
    if _dev_secret is None:
        _dev_secret = secrets.token_hex(32)
        logging.getLogger(__name__).warning(
            "[security] JWT_SHARED_SECRET not set — using ephemeral dev secret (set JWT_SHARED_SECRET in .env for stable sessions)"
        )
    return _dev_secret


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def verify_internal_jwt(token: str) -> dict:
    """Verify an HS256 JWT signed by the Next.js BFF.

    Returns the decoded claims dict on success.
    Raises ValueError with a descriptive message on any failure.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")

    header_b64, payload_b64, sig_b64 = parts

    # Validate alg before touching the secret — closes algorithm confusion attacks
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception:
        raise ValueError("malformed token header")

    if header.get("alg") != "HS256":
        raise ValueError("unsupported algorithm")

    secret = os.environ.get("JWT_SHARED_SECRET", "")
    if not secret:
        if os.environ.get("FASTAPI_ENV") != "production":
            secret = _get_dev_secret()
        else:
            raise ValueError("JWT_SHARED_SECRET not set")

    # Match Node logic: 64-char hex string -> decode as hex bytes, otherwise UTF-8
    import re
    if re.fullmatch(r"[0-9a-fA-F]{64}", secret):
        key = bytes.fromhex(secret)
    else:
        key = secret.encode("utf-8")

    expected = (
        base64.urlsafe_b64encode(
            hmac.new(key, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )

    # Constant-time comparison — prevents timing attacks
    if not hmac.compare_digest(expected, sig_b64):
        raise ValueError("invalid signature")

    # Decode payload only after signature is verified
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise ValueError("malformed token payload")

    # 5-second clock skew tolerance: allow tokens that expired up to 5s ago
    if claims.get("exp", 0) < int(time.time()) - 5:
        raise ValueError("token expired")

    return claims
