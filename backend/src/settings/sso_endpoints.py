"""SSO admin endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import SsoConfig
from src.security.crypto import encrypt
from src.settings.router import require_permission
from src.settings.schemas import SsoConfigRequest

sso_router = APIRouter(prefix="/api/v1/settings/sso", tags=["sso"])


def _origin(request: Request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def _serialize(row: SsoConfig, request: Request) -> dict:
    origin = _origin(request)
    return {
        "enabled": row.enabled,
        "protocol": row.protocol,
        "defaultRoleId": row.default_role_id,
        "samlMetadataUrl": row.saml_metadata_url,
        "samlMetadataXml": row.saml_metadata_xml,
        "samlSpCertificate": row.saml_sp_certificate,
        "samlSpPrivateKeySet": row.saml_sp_private_key_enc is not None,
        "samlAcsUrl": f"{origin}/auth/sso/saml/acs",
        "samlSpEntityId": f"{origin}/auth/sso/saml/metadata",
        "samlSpMetadataUrl": f"{origin}/auth/sso/saml/metadata",
        "oidcDiscoveryUrl": row.oidc_discovery_url,
        "oidcClientId": row.oidc_client_id,
        "oidcClientSecretSet": row.oidc_client_secret_enc is not None,
        "oidcScopes": row.oidc_scopes,
        "oidcRedirectUri": f"{origin}/auth/sso/oidc/callback",
        "updatedAt": row.updated_at.isoformat() if row.updated_at else None,
    }


async def _get_singleton(session) -> SsoConfig:
    row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
    if row is None:
        row = SsoConfig(id=1)
        session.add(row)
        await session.flush()
    return row


@sso_router.get("")
def get_sso(request: Request) -> JSONResponse:
    async def _q(session):
        row = await _get_singleton(session)
        return _serialize(row, request)
    return JSONResponse(run_db(_q), status_code=200)


@sso_router.patch("")
def patch_sso(request: Request, body: SsoConfigRequest) -> JSONResponse:
    require_permission(request, "manage_settings")

    async def _q(session):
        row = await _get_singleton(session)
        if body.enabled is not None:
            row.enabled = body.enabled
        if body.protocol is not None:
            row.protocol = body.protocol
        if body.defaultRoleId is not None:
            row.default_role_id = body.defaultRoleId or None
        if body.samlMetadataUrl is not None:
            row.saml_metadata_url = body.samlMetadataUrl or None
        if body.samlMetadataXml is not None:
            row.saml_metadata_xml = body.samlMetadataXml or None
        if body.oidcDiscoveryUrl is not None:
            row.oidc_discovery_url = body.oidcDiscoveryUrl or None
        if body.oidcClientId is not None:
            row.oidc_client_id = body.oidcClientId or None
        if body.oidcClientSecret:
            row.oidc_client_secret_enc = encrypt(body.oidcClientSecret)
        if body.oidcScopes is not None:
            row.oidc_scopes = body.oidcScopes or "openid email profile"
        return _serialize(row, request)

    return JSONResponse(run_db(_q), status_code=200)


@sso_router.post("/saml/sp-keypair")
def generate_saml_keypair(request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis SAML SP")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now.replace(year=now.year + 10))
        .sign(key, hashes.SHA256())
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pem_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    async def _q(session):
        row = await _get_singleton(session)
        row.saml_sp_certificate = pem_cert
        row.saml_sp_private_key_enc = encrypt(pem_key)
        return {"certificate": pem_cert, "updatedAt": row.updated_at.isoformat()}

    return JSONResponse(run_db(_q), status_code=200)


@sso_router.post("/saml/refresh-metadata")
def refresh_saml_metadata(request: Request) -> JSONResponse:
    import httpx
    require_permission(request, "manage_settings")

    async def _q(session):
        row = await _get_singleton(session)
        if not row.saml_metadata_url:
            return {"ok": False, "error": "No metadata URL configured."}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(row.saml_metadata_url)
                resp.raise_for_status()
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}
        row.saml_metadata_xml = resp.text
        return {"ok": True}

    return JSONResponse(run_db(_q), status_code=200)
