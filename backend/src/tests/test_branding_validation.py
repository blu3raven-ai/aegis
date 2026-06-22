"""Tests for src.shared.branding_validation.

Covers validate_logo_data_url — the shared helper that enforces mime-type
allowlist, size cap, and data-URL format requirements. The three org branding
mutations that previously used this logic have moved to REST; their tests live
in test_organisations_router.py.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.shared.branding_validation import validate_logo_data_url  # noqa: E402

_DATA_URL = "data:image/png;base64,aGVsbG8="


# ── Validation ─────────────────────────────────────────────────────────────

def test_validate_logo_rejects_non_data_url():
    assert validate_logo_data_url("https://example.com/logo.png") is not None


def test_validate_logo_rejects_oversize():
    huge = "data:image/png;base64," + ("A" * (200 * 1024 + 1))
    assert validate_logo_data_url(huge) is not None


def test_validate_logo_rejects_bad_mime():
    assert validate_logo_data_url("data:image/tiff;base64,abc") is not None


def test_validate_logo_rejects_svg():
    assert validate_logo_data_url("data:image/svg+xml;base64,PHN2Zy8+") is not None


def test_validate_logo_rejects_missing_base64():
    assert validate_logo_data_url("data:image/png,abc") is not None


def test_validate_logo_accepts_valid_png():
    assert validate_logo_data_url(_DATA_URL) is None


def test_validate_logo_accepts_jpeg():
    assert validate_logo_data_url("data:image/jpeg;base64,aGVsbG8=") is None


def test_validate_logo_accepts_webp():
    assert validate_logo_data_url("data:image/webp;base64,aGVsbG8=") is None
