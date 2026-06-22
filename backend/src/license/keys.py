"""JWT license key decoding and validation."""

from __future__ import annotations

import jwt

from .types import LicenseClaims, Tier

EMBEDDED_PUBLIC_KEY = """\
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmrko1m/cV5LeWAFq8vFDDDzpQP0YCXH8
o5/jKQSlRZW4hY7FA2nisOXe6jB70535vTEC/yajpCwyyhZ95F+QE7c4SfQRLpqN
Bln5Mq6DDGgpa+pir8irhUQtxZjQc5nf
-----END PUBLIC KEY-----
"""


class LicenseError(Exception):
    """Raised when a license token cannot be decoded or is invalid."""


def decode_license(token: str, public_key: str) -> LicenseClaims:
    """Decode and validate a JWT license key signed with ES384.

    Args:
        token: The JWT token string.
        public_key: PEM-encoded EC public key for ES384 verification.

    Returns:
        A validated ``LicenseClaims`` instance.

    Raises:
        LicenseError: On expired token, invalid signature, bad format,
            or unknown tier value.

    Note – org validation:
        The ``org`` claim in the license is stored but NOT enforced against
        the current deployment's org. This is intentional for single-tenant
        mode where there is exactly one deployment per license. If multi-tenant
        support is added, the caller should verify that ``claims.org`` matches
        the requesting org before granting Enterprise features.
    """
    try:
        payload = jwt.decode(token, public_key, algorithms=["ES384"])
    except jwt.ExpiredSignatureError:
        raise LicenseError("License has expired")
    except jwt.InvalidSignatureError:
        raise LicenseError("Invalid license signature")
    except jwt.DecodeError as exc:
        raise LicenseError(f"Bad license format: {exc}")
    except jwt.InvalidTokenError as exc:
        raise LicenseError(f"Invalid license token: {exc}")

    # Map payload fields to LicenseClaims
    try:
        tier_str = payload["tier"]
    except KeyError:
        raise LicenseError("License payload missing required field: tier")

    try:
        tier = Tier(tier_str)
    except ValueError:
        raise LicenseError(f"Unknown tier value: {tier_str!r}")

    try:
        return LicenseClaims(
            tier=tier,
            org=payload["org"],
            max_users=payload.get("max_users"),
            max_orgs=payload.get("max_orgs"),
            issued_at=str(payload["iat"]),
            expires_at=str(payload["exp"]),
            license_id=payload["jti"],
        )
    except KeyError as exc:
        raise LicenseError(f"License payload missing required field: {exc}")
