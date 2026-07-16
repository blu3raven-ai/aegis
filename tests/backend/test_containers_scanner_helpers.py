"""Pure-logic coverage for containers/scanner.py — registry username resolution
(per-registry auth conventions) and canonical image-ref construction."""
from __future__ import annotations

from src.containers.scanner import _image_external_ref, _resolve_registry_username


def test_resolve_registry_username_per_registry():
    assert _resolve_registry_username("123.dkr.ecr.us-east-1.amazonaws.com", "t") == "AWS"
    assert _resolve_registry_username("myorg.azurecr.io", "t") == "myorg"       # subdomain
    assert _resolve_registry_username("gcr.io/proj", "t") == "_json_key"
    assert _resolve_registry_username("us-docker.pkg.dev/proj", "t") == "_json_key"
    assert _resolve_registry_username("registry.gitlab.com", "t") == "oauth2"
    assert _resolve_registry_username("docker.io", "t") == "_token"             # default


def test_resolve_ghcr_without_pat_token_falls_through():
    # A non-PAT token skips the network lookup branch entirely → default.
    assert _resolve_registry_username("ghcr.io", "not-a-pat") == "_token"


def test_image_external_ref_strips_registry_and_digest():
    ref = _image_external_ref("ghcr", "ghcr.io/acme-org/app:1.2.3")
    assert "ghcr.io" not in ref and "acme-org/app" in ref and "1.2.3" in ref


def test_image_external_ref_defaults_tag_and_drops_digest():
    # No tag → 'latest'; a digest is dropped before parsing.
    ref = _image_external_ref("ghcr", "ghcr.io/acme-org/app@sha256:" + "a" * 64)
    assert "sha256" not in ref and "latest" in ref and "acme-org/app" in ref
