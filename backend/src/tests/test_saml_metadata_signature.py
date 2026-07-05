"""Tests for the signed-IdP-metadata enforcement flag.

Covers four shapes:
  - the column defaults to False and `_sp_config` does not invoke the check
  - flag on + unsigned metadata raises the documented RuntimeError before
    pysaml2 sees the XML
  - flag on + signed metadata (with a top-level <ds:Signature>) passes through
    to pysaml2
  - the new field round-trips through PATCH on /api/v1/settings/sso
    (the GET endpoint moved to GraphQL — covered by test_graphql_auth_settings.py)
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete
from unittest.mock import patch

os.environ.setdefault("APP_SECRET", Fernet.generate_key().decode())
os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-not-for-production")

from src.auth.federation import saml as saml_helpers  # noqa: E402
from src.settings.sso.router import sso_router  # noqa: E402
from src.db.helpers import run_db  # noqa: E402
from src.db.models import SsoConfig  # noqa: E402
from src.security.crypto import encrypt  # noqa: E402


_UNSIGNED_METADATA = (
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://idp.example.com/saml"></EntityDescriptor>'
)

_SIGNED_METADATA = (
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://idp.example.com/saml">'
    '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
    '<SignedInfo></SignedInfo>'
    '<SignatureValue>noop</SignatureValue>'
    '</Signature>'
    '</EntityDescriptor>'
)


@pytest.fixture(autouse=True)
def _audit_disabled(monkeypatch):
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")


def _wipe_sso_config() -> None:
    async def _do(session):
        await session.execute(delete(SsoConfig).where(SsoConfig.id == 1))

    run_db(_do)


def _seed_sso_config(
    *,
    metadata_xml: str,
    validate_signature: bool,
) -> None:
    async def _do(session):
        session.add(SsoConfig(
            id=1,
            enabled=True,
            protocol="saml",
            saml_metadata_xml=metadata_xml,
            saml_sp_private_key_enc=encrypt(
                "-----BEGIN PRIVATE KEY-----\nnoop\n-----END PRIVATE KEY-----\n"
            ),
            saml_sp_certificate=(
                "-----BEGIN CERTIFICATE-----\nnoop\n-----END CERTIFICATE-----\n"
            ),
            saml_validate_metadata_signature=validate_signature,
        ))

    run_db(_do)


@pytest.fixture(autouse=True)
def _wipe_sso_around_test():
    _wipe_sso_config()
    yield
    _wipe_sso_config()


# -------------------------------------------------------------------------
# enforce_metadata_signature() — pure function
# -------------------------------------------------------------------------


def test_enforce_metadata_signature_accepts_signed_top_level():
    saml_helpers.enforce_metadata_signature(_SIGNED_METADATA)


def test_enforce_metadata_signature_rejects_unsigned_top_level():
    with pytest.raises(RuntimeError) as exc:
        saml_helpers.enforce_metadata_signature(_UNSIGNED_METADATA)
    assert (
        "IdP metadata signature validation is enabled "
        "but the metadata document is not signed."
    ) in str(exc.value)


def test_enforce_metadata_signature_rejects_malformed_xml():
    with pytest.raises(RuntimeError) as exc:
        saml_helpers.enforce_metadata_signature("not actually xml")
    assert "IdP metadata XML is malformed." in str(exc.value)


# -------------------------------------------------------------------------
# _sp_config integration
# -------------------------------------------------------------------------


def _load_singleton() -> SsoConfig:
    from sqlalchemy import select

    async def _do(session):
        row = (
            await session.execute(select(SsoConfig).where(SsoConfig.id == 1))
        ).scalar_one()
        return row

    return run_db(_do)


def test_sp_config_skips_check_when_flag_off():
    """Default column value False; _sp_config must not call the enforcement
    helper, so unsigned metadata flows through to pysaml2 unchanged."""
    _seed_sso_config(metadata_xml=_UNSIGNED_METADATA, validate_signature=False)
    row = _load_singleton()

    calls: list[str] = []

    def _spy(xml: str) -> None:
        calls.append(xml)

    # Patch enforce_metadata_signature where _sp_config looks it up.
    with patch.object(saml_helpers, "enforce_metadata_signature", _spy):
        # Patch SPConfig.load so we don't need pysaml2/xmlsec1 to fully parse.
        with patch("saml2.config.SPConfig.load", lambda self, cfg: None):
            with saml_helpers._sp_config(row, "https://app.example.com"):
                pass

    assert calls == []


def test_sp_config_rejects_unsigned_metadata_when_flag_on():
    """Flag on + unsigned metadata: _sp_config must raise the documented
    RuntimeError before pysaml2 sees the XML."""
    _seed_sso_config(metadata_xml=_UNSIGNED_METADATA, validate_signature=True)
    row = _load_singleton()

    sp_load_called = False

    def _track_load(self, cfg):
        nonlocal sp_load_called
        sp_load_called = True

    with patch("saml2.config.SPConfig.load", _track_load):
        with pytest.raises(RuntimeError) as exc:
            with saml_helpers._sp_config(row, "https://app.example.com"):
                pass

    assert (
        "IdP metadata signature validation is enabled "
        "but the metadata document is not signed."
    ) in str(exc.value)
    assert sp_load_called is False


def test_sp_config_accepts_signed_metadata_when_flag_on():
    """Flag on + signed metadata: enforcement passes and pysaml2 is reached."""
    _seed_sso_config(metadata_xml=_SIGNED_METADATA, validate_signature=True)
    row = _load_singleton()

    sp_load_called = False

    def _track_load(self, cfg):
        nonlocal sp_load_called
        sp_load_called = True

    with patch("saml2.config.SPConfig.load", _track_load):
        with saml_helpers._sp_config(row, "https://app.example.com"):
            pass

    assert sp_load_called is True


# -------------------------------------------------------------------------
# Admin GET / PATCH round-trip
# -------------------------------------------------------------------------


def _make_admin_app() -> FastAPI:
    from src.authz.enforcement.dependencies import Permission
    from src.authz.permissions.catalog import MANAGE_SETTINGS

    app = FastAPI()
    app.include_router(sso_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = f"admin-{uuid4()}"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


def test_admin_patch_round_trips_validate_signature_flag():
    """PATCH flips the flag, and a subsequent PATCH read-modify-write echoes
    the value back. The first PATCH also implicitly creates the singleton."""
    if True:
        client = TestClient(_make_admin_app())

        # First PATCH creates the singleton and flips the flag to True.
        r = client.patch(
            "/api/v1/settings/sso",
            json={"samlValidateMetadataSignature": True},
        )
        assert r.status_code == 200
        assert r.json()["samlValidateMetadataSignature"] is True

        # Second PATCH (no-op) still reports True — the response always
        # echoes the current persisted state.
        r = client.patch(
            "/api/v1/settings/sso",
            json={},
        )
        assert r.status_code == 200
        assert r.json()["samlValidateMetadataSignature"] is True
