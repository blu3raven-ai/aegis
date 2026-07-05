"""Signed state+nonce cookie helper for the OIDC + SAML SLO flows."""
from __future__ import annotations

from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from src.shared.encryption import derive_key


def _serializer(salt: str = "aegis-oidc-state") -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(derive_key("federation_state"), salt=salt)


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


def encode_saml_slo_state(*, request_id: str, session_id: str) -> str:
    """Sign the SP-initiated SLO relay state.

    Binds the in-flight LogoutRequest to the Aegis session so the IdP's
    LogoutResponse callback can clear the right cookie and revoke the right
    session even across processes (the value is opaque to the IdP and
    round-trips through the SAML RelayState parameter).
    """
    return _serializer(salt="aegis-saml-slo-state").dumps(
        {"request_id": request_id, "session_id": session_id}
    )


def decode_saml_slo_state(token: str, max_age: int = 300) -> dict[str, Any]:
    if max_age <= 0:
        raise RuntimeError("SAML SLO state expired.")
    try:
        return _serializer(salt="aegis-saml-slo-state").loads(token, max_age=max_age)
    except SignatureExpired as exc:
        raise RuntimeError("SAML SLO state expired.") from exc
    except BadSignature as exc:
        raise RuntimeError("SAML SLO state signature invalid.") from exc
