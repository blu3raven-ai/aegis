"""Signed state+nonce cookie helper for the OIDC flow."""
from __future__ import annotations

import os
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


def _serializer() -> URLSafeTimedSerializer:
    key = os.environ.get("AEGIS_SECRET_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("AEGIS_SECRET_ENCRYPTION_KEY must be set to sign OIDC state.")
    return URLSafeTimedSerializer(key, salt="aegis-oidc-state")


def encode_state(*, state: str, nonce: str) -> str:
    return _serializer().dumps({"state": state, "nonce": nonce})


def decode_state(token: str, max_age: int = 300) -> dict[str, Any]:
    # itsdangerous allows age==max_age, so a zero max_age is always expired
    if max_age <= 0:
        raise RuntimeError("OIDC state expired.")
    try:
        return _serializer().loads(token, max_age=max_age)
    except SignatureExpired as exc:
        raise RuntimeError("OIDC state expired.") from exc
    except BadSignature as exc:
        raise RuntimeError("OIDC state signature invalid.") from exc
