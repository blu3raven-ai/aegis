"""Tests for integrations.signature — HMAC and token verification helpers."""
from __future__ import annotations

import hashlib
import hmac

import pytest

from src.integrations.signature import (
    verify_bitbucket_signature,
    verify_github_signature,
    verify_gitlab_signature,
)


def _github_sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _bitbucket_sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ── GitHub ────────────────────────────────────────────────────────────────────


def test_github_valid_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
    body = b'{"ref":"refs/heads/main"}'
    assert verify_github_signature(body, _github_sig(body, "gh-secret")) is True


def test_github_wrong_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "real-secret")
    body = b'{"ref":"refs/heads/main"}'
    assert verify_github_signature(body, _github_sig(body, "wrong-secret")) is False


def test_github_empty_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "")
    body = b"body"
    assert verify_github_signature(body, _github_sig(body, "any")) is False


def test_github_missing_prefix(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
    body = b"body"
    digest = hmac.new("gh-secret".encode(), body, hashlib.sha256).hexdigest()
    # header without sha256= prefix
    assert verify_github_signature(body, digest) is False


def test_github_empty_header(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
    assert verify_github_signature(b"body", "") is False


# ── GitLab ────────────────────────────────────────────────────────────────────


def test_gitlab_valid_token(monkeypatch):
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "gl-token")
    assert verify_gitlab_signature(b"body", "gl-token") is True


def test_gitlab_wrong_token(monkeypatch):
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "correct-token")
    assert verify_gitlab_signature(b"body", "wrong-token") is False


def test_gitlab_empty_secret(monkeypatch):
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "")
    assert verify_gitlab_signature(b"body", "any-token") is False


def test_gitlab_empty_header(monkeypatch):
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "gl-token")
    assert verify_gitlab_signature(b"body", "") is False


# ── Bitbucket ─────────────────────────────────────────────────────────────────


def test_bitbucket_valid_signature(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
    body = b'{"repository":{}}'
    assert verify_bitbucket_signature(body, _bitbucket_sig(body, "bb-secret")) is True


def test_bitbucket_wrong_secret(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "real-secret")
    body = b'{"repository":{}}'
    assert verify_bitbucket_signature(body, _bitbucket_sig(body, "wrong-secret")) is False


def test_bitbucket_empty_secret(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "")
    body = b"body"
    assert verify_bitbucket_signature(body, _bitbucket_sig(body, "any")) is False


def test_bitbucket_missing_prefix(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
    body = b"body"
    digest = hmac.new("bb-secret".encode(), body, hashlib.sha256).hexdigest()
    assert verify_bitbucket_signature(body, digest) is False


def test_bitbucket_empty_header(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
    assert verify_bitbucket_signature(b"body", "") is False
