"""Tests for the license tier types, limits, and JWT key validation."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.license.keys import LicenseError, decode_license
from src.license.types import TIER_LIMITS, Tier


class TestTierEnum:
    def test_tier_values(self):
        assert Tier.COMMUNITY.value == "community"
        assert Tier.ENTERPRISE.value == "enterprise"

    def test_tier_from_string(self):
        assert Tier("community") is Tier.COMMUNITY
        assert Tier("enterprise") is Tier.ENTERPRISE


class TestTierComparison:
    def test_community_less_than_enterprise(self):
        assert Tier.COMMUNITY < Tier.ENTERPRISE

    def test_enterprise_greater_than_community(self):
        assert Tier.ENTERPRISE > Tier.COMMUNITY

    def test_le_same_tier(self):
        assert Tier.ENTERPRISE <= Tier.ENTERPRISE

    def test_ge_same_tier(self):
        assert Tier.ENTERPRISE >= Tier.ENTERPRISE

    def test_not_less_than_self(self):
        assert not (Tier.ENTERPRISE < Tier.ENTERPRISE)

    def test_not_greater_than_self(self):
        assert not (Tier.ENTERPRISE > Tier.ENTERPRISE)


class TestCommunityLimits:
    limits = TIER_LIMITS[Tier.COMMUNITY]

    def test_max_users(self):
        assert self.limits["max_users"] is None

    def test_max_remote_runners(self):
        assert self.limits["max_remote_runners"] is None

    def test_feature_flags_all_true(self):
        for key in ("custom_roles", "teams", "insights_tab", "health_tab",
                     "ai_review", "custom_scan_schedule"):
            assert self.limits[key] is True, f"{key} should be True for community"
        assert self.limits["sso"] is False, "sso should be False for community (enterprise-only)"
        assert self.limits["audit_log"] is False, "audit_log should be False for community (enterprise-only)"

    def test_data_retention_days(self):
        assert self.limits["data_retention_days"] is None



class TestEnterpriseLimits:
    limits = TIER_LIMITS[Tier.ENTERPRISE]

    def test_unlimited_users(self):
        assert self.limits["max_users"] is None

    def test_unlimited_remote_runners(self):
        assert self.limits["max_remote_runners"] is None

    def test_all_features_enabled(self):
        for key in ("custom_roles", "teams", "insights_tab", "health_tab",
                     "ai_review", "custom_scan_schedule", "sso", "audit_log"):
            assert self.limits[key] is True, f"{key} should be True for enterprise"

    def test_unlimited_data_retention(self):
        assert self.limits["data_retention_days"] is None


# ---------------------------------------------------------------------------
# Fixtures and helpers for JWT license key tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ec_key_pair():
    """Generate an EC P-384 key pair for ES384 signing."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def _make_token(private_pem: str, payload: dict) -> str:
    """Create a signed ES384 JWT from the given payload."""
    return jwt.encode(payload, private_pem, algorithm="ES384")


def _valid_payload(**overrides) -> dict:
    """Return a valid license payload with optional overrides."""
    now = int(time.time())
    base = {
        "tier": "enterprise",
        "org": "acme-corp",
        "max_users": 50,
        "iat": now,
        "exp": now + 3600,
        "jti": "lic-test-001",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# JWT license key decode tests
# ---------------------------------------------------------------------------

class TestDecodeLicense:
    def test_decode_valid_license(self, ec_key_pair):
        private_pem, public_pem = ec_key_pair
        payload = _valid_payload()
        token = _make_token(private_pem, payload)

        claims = decode_license(token, public_pem)

        assert claims.tier is Tier.ENTERPRISE
        assert claims.org == "acme-corp"
        assert claims.max_users == 50
        assert claims.issued_at == str(payload["iat"])
        assert claims.expires_at == str(payload["exp"])
        assert claims.license_id == "lic-test-001"

    def test_decode_expired_license(self, ec_key_pair):
        private_pem, public_pem = ec_key_pair
        now = int(time.time())
        payload = _valid_payload(iat=now - 7200, exp=now - 3600)
        token = _make_token(private_pem, payload)

        with pytest.raises(LicenseError, match="expired"):
            decode_license(token, public_pem)

    def test_decode_invalid_signature(self, ec_key_pair):
        private_pem, public_pem = ec_key_pair
        # Sign with a different key
        other_key = ec.generate_private_key(ec.SECP384R1())
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        token = _make_token(other_pem, _valid_payload())

        with pytest.raises(LicenseError, match="[Ss]ignature"):
            decode_license(token, public_pem)

    def test_decode_invalid_tier(self, ec_key_pair):
        private_pem, public_pem = ec_key_pair
        payload = _valid_payload(tier="platinum")
        token = _make_token(private_pem, payload)

        with pytest.raises(LicenseError, match="Unknown tier"):
            decode_license(token, public_pem)


# ---------------------------------------------------------------------------
# Middleware: resolve_current_tier
# ---------------------------------------------------------------------------

from src.license.middleware import resolve_current_tier


class TestResolveCurrentTier:
    def test_resolve_tier_no_license(self):
        tier, claims = resolve_current_tier(license_key=None, public_key="")
        assert tier == Tier.COMMUNITY
        assert claims is None

    def test_resolve_tier_empty_string(self):
        tier, claims = resolve_current_tier(license_key="", public_key="")
        assert tier == Tier.COMMUNITY
        assert claims is None

    def test_resolve_tier_invalid_falls_back(self):
        tier, claims = resolve_current_tier(license_key="garbage", public_key="some-key")
        assert tier == Tier.COMMUNITY
        assert claims is None

    def test_resolve_tier_valid_license(self, ec_key_pair):
        private_pem, public_pem = ec_key_pair
        token = _make_token(private_pem, _valid_payload())
        tier, claims = resolve_current_tier(license_key=token, public_key=public_pem)
        assert tier == Tier.ENTERPRISE
        assert claims is not None
        assert claims.org == "acme-corp"


# ---------------------------------------------------------------------------
# Guard: require_tier
# ---------------------------------------------------------------------------

from fastapi import HTTPException
from src.license.guard import require_tier


class TestRequireTier:
    def test_require_tier_passes_same(self):
        require_tier(current_tier=Tier.ENTERPRISE, required_tier=Tier.ENTERPRISE)  # should not raise

    def test_require_tier_passes_higher(self):
        require_tier(current_tier=Tier.ENTERPRISE, required_tier=Tier.COMMUNITY)  # should not raise

    def test_require_tier_blocks(self):
        with pytest.raises(HTTPException) as exc_info:
            require_tier(current_tier=Tier.COMMUNITY, required_tier=Tier.ENTERPRISE)
        assert exc_info.value.status_code == 403

    def test_require_tier_blocks_community_enterprise(self):
        with pytest.raises(HTTPException) as exc_info:
            require_tier(current_tier=Tier.COMMUNITY, required_tier=Tier.ENTERPRISE)
        assert exc_info.value.status_code == 403
        assert "Enterprise" in exc_info.value.detail
