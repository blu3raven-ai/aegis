"""pysaml2 SP wrapper for the Aegis SAML SSO flow."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterator

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor
from saml2.saml import NameID
from saml2.s_utils import status_message_factory, success_status_factory
from saml2.samlp import STATUS_REQUESTER

from src.db.models import SsoConfig
from src.security.crypto import decrypt

_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def enforce_metadata_signature(metadata_xml: str) -> None:
    """Reject metadata that does not carry a top-level <ds:Signature> element."""
    try:
        root = ET.fromstring(metadata_xml.encode("utf-8"))
    except ET.ParseError as exc:
        raise RuntimeError("IdP metadata XML is malformed.") from exc
    if root.find(f"{{{_DS_NS}}}Signature") is None:
        raise RuntimeError(
            "IdP metadata signature validation is enabled but the metadata document is not signed."
        )


@dataclass
class SamlIdentity:
    subject: str
    email: str
    name: str


@dataclass
class SamlSloRequest:
    """A parsed inbound SAML LogoutRequest awaiting a response."""

    request_id: str
    name_id: str
    raw: Any  # pysaml2 LogoutRequest message instance


@dataclass
class SamlSloDispatch:
    """HTTP info for sending a SAML SLO message bound per the chosen binding.

    `method` is "GET" for HTTP-Redirect (302 to the location URL with the
    SAML payload in the query string) or "POST" for HTTP-POST (an auto-submit
    HTML form). `body` is the rendered HTML form when POST, else empty.
    """

    method: str
    url: str
    body: str


@contextmanager
def _sp_config(row: SsoConfig, origin: str) -> Iterator[SPConfig]:
    if not row.saml_metadata_xml:
        raise RuntimeError("SAML metadata is not configured.")
    if not row.saml_sp_certificate or not row.saml_sp_private_key_enc:
        raise RuntimeError("SAML SP keypair is not configured.")
    private_key = decrypt(row.saml_sp_private_key_enc)
    if private_key is None:
        raise RuntimeError("SAML SP keypair is not configured.")
    if row.saml_validate_metadata_signature:
        enforce_metadata_signature(row.saml_metadata_xml)

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
                        "single_logout_service": [
                            (f"{origin}/auth/sso/saml/slo", BINDING_HTTP_REDIRECT),
                            (f"{origin}/auth/sso/saml/slo", BINDING_HTTP_POST),
                        ],
                    },
                    "allow_unsolicited": True,
                    "authn_requests_signed": True,
                    "want_assertions_signed": True,
                    "want_response_signed": True,
                    "logout_requests_signed": True,
                    "logout_responses_signed": True,
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


def _http_info_to_dispatch(http_info: dict[str, Any]) -> SamlSloDispatch:
    """Normalize pysaml2 apply_binding output to a binding-agnostic dispatch.

    For HTTP-Redirect pysaml2 returns headers containing a Location header
    plus method=GET. For HTTP-POST it returns a rendered HTML auto-submit
    form in `data` plus method=POST.
    """
    method = http_info.get("method", "GET")
    if method == "GET":
        location = ""
        for key, value in http_info.get("headers", []):
            if key.lower() == "location":
                location = value
                break
        if not location:
            location = http_info.get("url", "")
        return SamlSloDispatch(method="GET", url=location, body="")
    body = http_info.get("data", "")
    if isinstance(body, (list, tuple)):
        body = "".join(body)
    return SamlSloDispatch(method="POST", url=http_info.get("url", ""), body=body)


def _idp_entity_id_and_slo_binding(client: Saml2Client) -> tuple[str, str]:
    """Return (idp_entity_id, slo_binding_to_use).

    Picks the first IdP from the configured metadata and prefers HTTP-Redirect
    when the IdP advertises it, otherwise falls back to HTTP-POST. Raises if
    the IdP's metadata does not advertise a SingleLogoutService at all —
    that's the configuration the caller must fall through to the inline
    cookie-clear path.
    """
    idps = client.metadata.identity_providers()
    if not idps:
        raise RuntimeError("No IdP found in SAML metadata.")
    idp_entity_id = idps[0]
    for binding in (BINDING_HTTP_REDIRECT, BINDING_HTTP_POST):
        services = client.metadata.single_logout_service(
            entity_id=idp_entity_id, binding=binding, typ="idpsso",
        )
        if services:
            return idp_entity_id, binding
    raise RuntimeError("IdP does not advertise a SingleLogoutService.")


def idp_supports_slo(row: SsoConfig, origin: str) -> bool:
    """True iff the IdP metadata advertises a SingleLogoutService endpoint.

    SP-initiated SLO is only meaningful when the IdP can receive a
    LogoutRequest. When this returns False the caller must fall through to
    the inline cookie-clear logout path.
    """
    try:
        with _sp_config(row, origin) as conf:
            client = Saml2Client(config=conf)
            _idp_entity_id_and_slo_binding(client)
            return True
    except Exception:
        return False


def build_sp_logout_request(
    row: SsoConfig,
    origin: str,
    name_id_text: str,
    *,
    request_id: str,
    relay_state: str,
) -> SamlSloDispatch:
    """Construct an SP-initiated LogoutRequest bound for the IdP.

    The caller pre-generates `request_id` (an opaque SAML message ID) so the
    same value can be encoded into `relay_state` AND set as the message's
    `ID` attribute. The IdP's `LogoutResponse.InResponseTo` will then match
    the encoded request_id one-to-one on the callback leg.
    """
    if not request_id:
        raise ValueError("request_id must be non-empty")
    with _sp_config(row, origin) as conf:
        client = Saml2Client(config=conf)
        idp_entity_id, binding = _idp_entity_id_and_slo_binding(client)
        services = client.metadata.single_logout_service(
            entity_id=idp_entity_id, binding=binding, typ="idpsso",
        )
        destination = ""
        for srv in services:
            destination = srv.get("location", "")
            if destination:
                break
        if not destination:
            raise RuntimeError("IdP SingleLogoutService has no location.")

        name_id = NameID(text=name_id_text)
        sign = bool(client.logout_requests_signed)
        sign_redirect = sign and binding == BINDING_HTTP_REDIRECT
        sign_post = sign and binding == BINDING_HTTP_POST
        _, request = client.create_logout_request(
            destination=destination,
            issuer_entity_id=idp_entity_id,
            name_id=name_id,
            sign=sign_post,
            message_id=request_id,
        )
        http_info = client.apply_binding(
            binding,
            str(request),
            destination,
            relay_state,
            sign=sign_redirect,
        )
        return _http_info_to_dispatch(http_info)


def parse_idp_logout_request(
    row: SsoConfig,
    origin: str,
    saml_request: str,
    binding: str,
    *,
    relay_state: str | None = None,
    sigalg: str | None = None,
    signature: str | None = None,
) -> SamlSloRequest:
    """Verify + parse an IdP-initiated LogoutRequest.

    Signature verification is delegated to pysaml2 (`logout_requests_signed`
    on the SP config enables `must=True` semantics at the entity layer).
    """
    with _sp_config(row, origin) as conf:
        client = Saml2Client(config=conf)
        try:
            parsed = client.parse_logout_request(
                xmlstr=saml_request,
                binding=binding,
                relay_state=relay_state,
                sigalg=sigalg,
                signature=signature,
            )
        except Exception as exc:
            raise RuntimeError("Invalid SAML LogoutRequest.") from exc
        if parsed is None or parsed.message is None:
            raise RuntimeError("Invalid SAML LogoutRequest.")
        msg = parsed.message
        name_id = msg.name_id
        if name_id is None or not name_id.text:
            raise RuntimeError("SAML LogoutRequest missing NameID.")
        return SamlSloRequest(
            request_id=msg.id, name_id=name_id.text, raw=msg,
        )


def build_idp_logout_response(
    row: SsoConfig,
    origin: str,
    request_msg: Any,
    request_binding: str,
    *,
    success: bool,
    relay_state: str | None = None,
) -> SamlSloDispatch:
    """Construct a LogoutResponse for an IdP-initiated request.

    Mirrors the SAML 2.0 Profile spec: on success returns status
    `urn:oasis:names:tc:SAML:2.0:status:Success`; on unknown NameID (no
    matching active session) returns `...:status:Requester` per the bindings
    profile so the IdP can present a sensible message rather than a 500.
    """
    if success:
        status = success_status_factory()
    else:
        status = status_message_factory("Unknown principal", STATUS_REQUESTER)
    with _sp_config(row, origin) as conf:
        client = Saml2Client(config=conf)
        response_bindings = {
            BINDING_HTTP_POST: [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT],
            BINDING_HTTP_REDIRECT: [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST],
        }.get(request_binding, [BINDING_HTTP_REDIRECT])

        for response_binding in response_bindings:
            sign = bool(client.logout_responses_signed)
            sign_redirect = sign and response_binding == BINDING_HTTP_REDIRECT
            sign_post = sign and response_binding == BINDING_HTTP_POST
            try:
                response_xml = client.create_logout_response(
                    request_msg, bindings=[response_binding], status=status, sign=sign_post,
                )
                rinfo = client.response_args(request_msg, [response_binding])
                http_info = client.apply_binding(
                    rinfo["binding"],
                    response_xml,
                    rinfo["destination"],
                    relay_state,
                    response=True,
                    sign=sign_redirect,
                )
                return _http_info_to_dispatch(http_info)
            except Exception:
                continue
        raise RuntimeError("Failed to build SAML LogoutResponse.")


def verify_idp_logout_response(
    row: SsoConfig, origin: str, saml_response: str, binding: str,
) -> str:
    """Verify a LogoutResponse from the IdP and return the InResponseTo ID.

    Used after SP-initiated SLO: when the IdP redirects the user-agent back
    to the SP with a signed LogoutResponse, the SP must verify it before
    clearing the local session.
    """
    with _sp_config(row, origin) as conf:
        client = Saml2Client(config=conf)
        try:
            parsed = client.parse_logout_request_response(saml_response, binding)
        except Exception as exc:
            raise RuntimeError("Invalid SAML LogoutResponse.") from exc
        if parsed is None or parsed.response is None:
            raise RuntimeError("Invalid SAML LogoutResponse.")
        in_response_to = getattr(parsed.response, "in_response_to", "") or ""
        return in_response_to
