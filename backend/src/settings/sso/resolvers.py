"""GraphQL resolver for the SSO settings surface."""
from __future__ import annotations

from typing import Optional

import strawberry
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.authz.enforcement import has_permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.db.helpers import run_db
from src.db.models import SsoConfig
from src.graphql.resolver_utils import raise_permission_denied, raise_unauthenticated


@strawberry.type
class SsoSettings:
    enabled: bool
    protocol: Optional[str]
    default_role_id: Optional[str]
    saml_metadata_url: Optional[str]
    saml_metadata_xml: Optional[str]
    saml_sp_certificate: Optional[str]
    saml_sp_private_key_set: bool
    saml_validate_metadata_signature: bool
    saml_acs_url: str
    saml_sp_entity_id: str
    saml_sp_metadata_url: str
    oidc_discovery_url: Optional[str]
    oidc_client_id: Optional[str]
    oidc_client_secret_set: bool
    oidc_scopes: str
    oidc_redirect_uri: str
    updated_at: Optional[str]


def _gate(info_context: dict):
    request = info_context.get("request") if info_context else None
    if request is None:
        raise_unauthenticated()
    if not has_permission(request, MANAGE_SETTINGS):
        raise_permission_denied("Permission denied: manage_settings")
    return request


def _origin(request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


async def _get_sso_singleton(session) -> SsoConfig:
    # ON CONFLICT DO NOTHING then re-SELECT — two concurrent first-reads can't
    # both insert and trip a UniqueViolation. Cheap when the row already exists.
    await session.execute(
        pg_insert(SsoConfig).values(id=1).on_conflict_do_nothing(index_elements=["id"])
    )
    return (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one()


def sso_settings(*, info_context: dict) -> SsoSettings:
    request = _gate(info_context)
    origin = _origin(request)

    async def _q(session):
        row = await _get_sso_singleton(session)
        return SsoSettings(
            enabled=row.enabled,
            protocol=row.protocol,
            default_role_id=row.default_role_id,
            saml_metadata_url=row.saml_metadata_url,
            saml_metadata_xml=row.saml_metadata_xml,
            saml_sp_certificate=row.saml_sp_certificate,
            saml_sp_private_key_set=row.saml_sp_private_key_enc is not None,
            saml_validate_metadata_signature=row.saml_validate_metadata_signature,
            saml_acs_url=f"{origin}/auth/sso/saml/acs",
            saml_sp_entity_id=f"{origin}/auth/sso/saml/metadata",
            saml_sp_metadata_url=f"{origin}/auth/sso/saml/metadata",
            oidc_discovery_url=row.oidc_discovery_url,
            oidc_client_id=row.oidc_client_id,
            oidc_client_secret_set=row.oidc_client_secret_enc is not None,
            oidc_scopes=row.oidc_scopes,
            oidc_redirect_uri=f"{origin}/auth/sso/oidc/callback",
            updated_at=row.updated_at.isoformat() if row.updated_at else None,
        )

    return run_db(_q)
