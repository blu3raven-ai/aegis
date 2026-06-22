"""Unit tests for the auth/SSO/SCIM settings GraphQL resolvers.

Covers permission denial (now enforced on all three reads — including the
two that the legacy REST GET handlers left unauthenticated), shape
correctness, and the origin-URL building for the SSO and SCIM endpoints.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from graphql import GraphQLError

from src.graphql.schema import SettingsQuery


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace()})


def _request(scheme: str = "https", host: str = "aegis.example.com"):
    return SimpleNamespace(
        url=SimpleNamespace(scheme=scheme, netloc=host),
        headers={"host": host},
    )


def _run_db_inline(coro_fn):
    """Run the resolver's async closure against a MagicMock session inside a
    worker thread so the resolver's sync wrapper can call asyncio.run without
    colliding with the test's event loop."""
    import concurrent.futures

    def _runner():
        return asyncio.run(coro_fn(MagicMock()))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_runner).result()


@pytest.fixture
def admin_ctx():
    with patch(
        "src.graphql.schema.get_workspace_context",
        new=AsyncMock(return_value={
            "user_id": "admin",
            "role": "admin",
            "role_id": None,
            "tier": "enterprise",
            "request": _request(),
        }),
    ):
        yield


@pytest.fixture
def no_request_ctx():
    with patch(
        "src.graphql.schema.get_workspace_context",
        new=AsyncMock(return_value={
            "user_id": "u",
            "role": "viewer",
            "role_id": None,
            "tier": "enterprise",
        }),
    ):
        yield


@pytest.fixture
def grant_permission():
    with (
        patch("src.settings.auth_security.resolvers.has_permission", return_value=True),
        patch("src.settings.sso.resolvers.has_permission", return_value=True),
        patch("src.settings.scim.resolvers.has_permission", return_value=True),
    ):
        yield


@pytest.fixture
def deny_permission():
    with (
        patch("src.settings.auth_security.resolvers.has_permission", return_value=False),
        patch("src.settings.sso.resolvers.has_permission", return_value=False),
        patch("src.settings.scim.resolvers.has_permission", return_value=False),
    ):
        yield


# ── auth_security_settings ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_auth_security_missing_request_raises_unauthenticated(no_request_ctx):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().auth_security(_info())
    assert excinfo.value.extensions == {"code": "UNAUTHENTICATED"}


@pytest.mark.asyncio
async def test_auth_security_denies_without_permission(admin_ctx, deny_permission):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().auth_security(_info())
    assert excinfo.value.extensions == {"code": "PERMISSION_DENIED"}
    assert "manage_settings" in str(excinfo.value)


@pytest.mark.asyncio
async def test_auth_security_returns_parsed_config(admin_ctx, grant_permission):
    cfg = {
        "authSecurity": {
            "requireMfaManualUsers": True,
            "requireMfaAdmins": True,
            "trustedSessionDurationDays": 14,
            "recoveryCodePolicy": "optional",
        },
    }
    with patch(
        "src.settings.auth_security.resolvers.read_app_config",
        return_value=cfg,
    ):
        result = await SettingsQuery().auth_security(_info())

    assert result.require_mfa_manual_users is True
    assert result.require_mfa_admins is True
    assert result.trusted_session_duration_days == 14
    assert result.recovery_code_policy == "optional"


# ── sso_settings ──────────────────────────────────────────────────────────


def _sso_row(
    *,
    enabled: bool = True,
    protocol: str | None = "saml",
    default_role_id: str | None = "role-1",
    saml_metadata_url: str | None = "https://idp.example.com/metadata",
    saml_metadata_xml: str | None = "<xml/>",
    saml_sp_certificate: str | None = "PEM-CERT",
    saml_sp_private_key_enc: str | None = "ENC-KEY",
    saml_validate_metadata_signature: bool = True,
    oidc_discovery_url: str | None = None,
    oidc_client_id: str | None = None,
    oidc_client_secret_enc: str | None = None,
    oidc_scopes: str = "openid email profile",
    updated_at: datetime | None = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
):
    row = MagicMock()
    row.enabled = enabled
    row.protocol = protocol
    row.default_role_id = default_role_id
    row.saml_metadata_url = saml_metadata_url
    row.saml_metadata_xml = saml_metadata_xml
    row.saml_sp_certificate = saml_sp_certificate
    row.saml_sp_private_key_enc = saml_sp_private_key_enc
    row.saml_validate_metadata_signature = saml_validate_metadata_signature
    row.oidc_discovery_url = oidc_discovery_url
    row.oidc_client_id = oidc_client_id
    row.oidc_client_secret_enc = oidc_client_secret_enc
    row.oidc_scopes = oidc_scopes
    row.updated_at = updated_at
    return row


@pytest.mark.asyncio
async def test_sso_missing_request_raises_unauthenticated(no_request_ctx):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().sso(_info())
    assert excinfo.value.extensions == {"code": "UNAUTHENTICATED"}


@pytest.mark.asyncio
async def test_sso_denies_without_permission(admin_ctx, deny_permission):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().sso(_info())
    assert excinfo.value.extensions == {"code": "PERMISSION_DENIED"}
    assert "manage_settings" in str(excinfo.value)


@pytest.mark.asyncio
async def test_sso_returns_shape_and_computed_urls(admin_ctx, grant_permission):
    row = _sso_row()
    with patch(
        "src.settings.sso.resolvers._get_sso_singleton",
        new=AsyncMock(return_value=row),
    ), patch(
        "src.settings.sso.resolvers.run_db", side_effect=_run_db_inline,
    ):
        result = await SettingsQuery().sso(_info())

    assert result.enabled is True
    assert result.protocol == "saml"
    assert result.default_role_id == "role-1"
    assert result.saml_metadata_url == "https://idp.example.com/metadata"
    assert result.saml_metadata_xml == "<xml/>"
    assert result.saml_sp_certificate == "PEM-CERT"
    assert result.saml_sp_private_key_set is True
    assert result.saml_validate_metadata_signature is True
    assert result.saml_acs_url == "https://aegis.example.com/auth/sso/saml/acs"
    assert result.saml_sp_entity_id == "https://aegis.example.com/auth/sso/saml/metadata"
    assert result.saml_sp_metadata_url == "https://aegis.example.com/auth/sso/saml/metadata"
    assert result.oidc_redirect_uri == "https://aegis.example.com/auth/sso/oidc/callback"
    assert result.oidc_client_secret_set is False
    assert result.oidc_scopes == "openid email profile"
    assert result.updated_at == "2026-06-01T12:00:00+00:00"


@pytest.mark.asyncio
async def test_sso_secret_fields_set_flags_flip_when_present(
    admin_ctx, grant_permission,
):
    row = _sso_row(
        saml_sp_private_key_enc=None,
        oidc_client_secret_enc="something",
    )
    with patch(
        "src.settings.sso.resolvers._get_sso_singleton",
        new=AsyncMock(return_value=row),
    ), patch(
        "src.settings.sso.resolvers.run_db", side_effect=_run_db_inline,
    ):
        result = await SettingsQuery().sso(_info())

    assert result.saml_sp_private_key_set is False
    assert result.oidc_client_secret_set is True


@pytest.mark.asyncio
async def test_sso_null_updated_at_passes_through(admin_ctx, grant_permission):
    row = _sso_row(updated_at=None)
    with patch(
        "src.settings.sso.resolvers._get_sso_singleton",
        new=AsyncMock(return_value=row),
    ), patch(
        "src.settings.sso.resolvers.run_db", side_effect=_run_db_inline,
    ):
        result = await SettingsQuery().sso(_info())

    assert result.updated_at is None


# ── scim_settings ─────────────────────────────────────────────────────────


def _scim_row(
    *,
    enabled: bool = False,
    default_role_id: str | None = None,
    token_hash: str | None = None,
    updated_at: datetime | None = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
):
    row = MagicMock()
    row.enabled = enabled
    row.default_role_id = default_role_id
    row.token_hash = token_hash
    row.updated_at = updated_at
    return row


@pytest.mark.asyncio
async def test_scim_missing_request_raises_unauthenticated(no_request_ctx):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().scim(_info())
    assert excinfo.value.extensions == {"code": "UNAUTHENTICATED"}


@pytest.mark.asyncio
async def test_scim_denies_without_permission(admin_ctx, deny_permission):
    with pytest.raises(GraphQLError) as excinfo:
        await SettingsQuery().scim(_info())
    assert excinfo.value.extensions == {"code": "PERMISSION_DENIED"}
    assert "manage_settings" in str(excinfo.value)


@pytest.mark.asyncio
async def test_scim_returns_shape_and_endpoint_url(admin_ctx, grant_permission):
    row = _scim_row(enabled=True, default_role_id="role-x", token_hash="abc")
    with patch(
        "src.settings.scim.resolvers._get_scim_singleton",
        new=AsyncMock(return_value=row),
    ), patch(
        "src.settings.scim.resolvers.run_db", side_effect=_run_db_inline,
    ):
        result = await SettingsQuery().scim(_info())

    assert result.enabled is True
    assert result.default_role_id == "role-x"
    assert result.token_set is True
    assert result.scim_endpoint_url == "https://aegis.example.com/scim/v2/"
    assert result.updated_at == "2026-06-01T12:00:00+00:00"


@pytest.mark.asyncio
async def test_scim_no_token_hash_reports_unset(admin_ctx, grant_permission):
    row = _scim_row(token_hash=None)
    with patch(
        "src.settings.scim.resolvers._get_scim_singleton",
        new=AsyncMock(return_value=row),
    ), patch(
        "src.settings.scim.resolvers.run_db", side_effect=_run_db_inline,
    ):
        result = await SettingsQuery().scim(_info())

    assert result.token_set is False


@pytest.mark.asyncio
async def test_scim_null_updated_at_passes_through(admin_ctx, grant_permission):
    row = _scim_row(updated_at=None)
    with patch(
        "src.settings.scim.resolvers._get_scim_singleton",
        new=AsyncMock(return_value=row),
    ), patch(
        "src.settings.scim.resolvers.run_db", side_effect=_run_db_inline,
    ):
        result = await SettingsQuery().scim(_info())

    assert result.updated_at is None


# ── singleton helpers ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_sso_singleton_upserts_then_selects():
    """ON CONFLICT DO NOTHING + re-SELECT pattern: insert is a no-op when
    the row already exists, but the helper still returns the persisted row.
    This documents the race-safe contract — two concurrent callers can't both
    INSERT and trip a UniqueViolation."""
    from src.settings.sso.resolvers import _get_sso_singleton

    row = _sso_row()
    insert_result = MagicMock()
    select_result = MagicMock()
    select_result.scalar_one.return_value = row

    session = MagicMock()
    session.execute = AsyncMock(side_effect=[insert_result, select_result])

    result = await _get_sso_singleton(session)

    assert result is row
    assert session.execute.await_count == 2  # one insert, one select


@pytest.mark.asyncio
async def test_get_scim_singleton_upserts_then_selects():
    from src.settings.scim.resolvers import _get_scim_singleton

    row = _scim_row()
    insert_result = MagicMock()
    select_result = MagicMock()
    select_result.scalar_one.return_value = row

    session = MagicMock()
    session.execute = AsyncMock(side_effect=[insert_result, select_result])

    result = await _get_scim_singleton(session)

    assert result is row
    assert session.execute.await_count == 2
