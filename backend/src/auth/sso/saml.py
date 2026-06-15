"""pysaml2 SP wrapper for the Aegis SAML SSO flow."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterator

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

from src.db.models import SsoConfig
from src.security.crypto import decrypt


@dataclass
class SamlIdentity:
    subject: str
    email: str
    name: str


@contextmanager
def _sp_config(row: SsoConfig, origin: str) -> Iterator[SPConfig]:
    if not row.saml_metadata_xml:
        raise RuntimeError("SAML metadata is not configured.")
    if not row.saml_sp_certificate or not row.saml_sp_private_key_enc:
        raise RuntimeError("SAML SP keypair is not configured.")
    private_key = decrypt(row.saml_sp_private_key_enc)
    if private_key is None:
        raise RuntimeError("SAML SP keypair is not configured.")

    # TemporaryDirectory deletes the decrypted SP private key on context exit.
    with TemporaryDirectory(prefix="aegis-saml-") as tmpdir:
        tmp = Path(tmpdir)
        metadata_path = tmp / "metadata.xml"
        cert_path = tmp / "sp.crt"
        key_path = tmp / "sp.key"
        metadata_path.write_text(row.saml_metadata_xml, encoding="utf-8")
        cert_path.write_text(row.saml_sp_certificate, encoding="ascii")
        key_path.write_text(private_key, encoding="ascii")

        conf = SPConfig()
        conf.load({
            "entityid": f"{origin}/auth/sso/saml/metadata",
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            (f"{origin}/auth/sso/saml/acs", BINDING_HTTP_POST),
                        ],
                    },
                    "allow_unsolicited": True,
                    "authn_requests_signed": True,
                    "want_assertions_signed": True,
                    "want_response_signed": False,
                },
            },
            "metadata": {"local": [str(metadata_path)]},
            "cert_file": str(cert_path),
            "key_file": str(key_path),
            "allow_unknown_attributes": True,
        })
        yield conf


def build_authn_request(row: SsoConfig, origin: str) -> tuple[str, str]:
    with _sp_config(row, origin) as conf:
        client = Saml2Client(config=conf)
        req_id, info = client.prepare_for_authenticate(
            relay_state="/", binding=BINDING_HTTP_REDIRECT,
        )
        location = dict(info["headers"]).get("Location")
        if not location:
            raise RuntimeError("pysaml2 did not produce a redirect Location.")
        return location, req_id


def verify_saml_response(row: SsoConfig, origin: str, saml_response_b64: str) -> SamlIdentity:
    with _sp_config(row, origin) as conf:
        client = Saml2Client(config=conf)
        try:
            authn = client.parse_authn_request_response(saml_response_b64, BINDING_HTTP_POST)
        except Exception as exc:
            raise RuntimeError("Invalid SAML response.") from exc
        if authn is None:
            raise RuntimeError("Invalid SAML response.")
        name_id = authn.get_subject()
        attrs: dict[str, Any] = authn.get_identity() or {}

    def _first(key: str) -> str:
        values = attrs.get(key) or []
        if isinstance(values, list) and values:
            return str(values[0])
        return ""

    email = _first("email") or _first("mail") or _first("urn:oid:0.9.2342.19200300.100.1.3")
    name = _first("displayName") or _first("name") or email
    if not name_id or not name_id.text:
        raise RuntimeError("SAML response missing NameID.")
    if not email:
        raise RuntimeError("SAML response missing email attribute.")
    return SamlIdentity(subject=name_id.text, email=email, name=name)


def sp_metadata_xml(row: SsoConfig, origin: str) -> str:
    with _sp_config(row, origin) as conf:
        return str(entity_descriptor(conf))
