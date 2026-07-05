"""Unit tests for container image-ref normalization used by OSV ingest."""
from __future__ import annotations

import pytest

import src.containers.scanner as scanner_mod
from src.containers.scanner import _image_external_ref, _index_container_sboms


def test_strips_registry_hostname_and_keeps_tag():
    assert _image_external_ref("ghcr", "ghcr.io/acme/app:1.2.3") == "ghcr:acme/app:1.2.3"


def test_defaults_tag_to_latest():
    assert _image_external_ref("ghcr", "ghcr.io/acme/app") == "ghcr:acme/app:latest"


def test_drops_digest():
    assert _image_external_ref("ghcr", "ghcr.io/acme/app:1.2.3@sha256:abc123") == "ghcr:acme/app:1.2.3"


def test_no_hostname_prefix_kept_as_image():
    # bare image with no registry host -> whole thing is the image path
    assert _image_external_ref("dockerhub", "library/nginx:1.27") == "dockerhub:library/nginx:1.27"


def test_localhost_hostname_stripped():
    assert _image_external_ref("ghcr", "localhost:5000/acme/app:dev") == "ghcr:acme/app:dev"


def test_unknown_registry_raises():
    with pytest.raises(ValueError):
        _image_external_ref("not-a-registry", "ghcr.io/acme/app:1.0")


def test_docker_hub_source_token_normalizes():
    # the source connection's "docker-hub" token must resolve, not silently skip
    assert _image_external_ref("docker-hub", "docker.io/library/nginx:1.27") == "dockerhub:library/nginx:1.27"


def test_gitlab_registry_source_token():
    assert _image_external_ref("gitlab-registry", "registry.gitlab.com/acme/app:v1") == "gitlab-registry:acme/app:v1"


def test_index_stamps_display_name_with_registry_prefix(monkeypatch):
    """A clean (no-finding) image asset's display_name must be the canonical
    registry-prefixed ref, not the bare SBOM component name — so it reads the
    same way as a repo asset ("github:acme/repo") in the inventory."""
    sbom = {"metadata": {"component": {"name": "acme/app:1.2.3"}}}
    monkeypatch.setattr(
        scanner_mod, "_download_scan_output_from_minio",
        lambda org, run_id, prefix: {"acme_app": {"sbom": sbom, "digest": "sha256:deadbeef"}},
    )

    captured: dict = {}

    def fake_upsert_asset(session, **kwargs):
        captured.update(kwargs)
        return "asset-1"

    monkeypatch.setattr("src.assets.service.upsert_asset", fake_upsert_asset)
    monkeypatch.setattr("src.db.helpers.run_db", lambda fn: fn(None))
    monkeypatch.setattr(scanner_mod, "upsert_sbom", lambda *a, **k: None)

    result, _newer, _meta = _index_container_sboms(org="acme", run_id="run-1", source_type="ghcr", prefix="p")

    assert captured["external_ref"] == "ghcr:acme/app:1.2.3"
    # The fix: display mirrors the external_ref, not the bare "acme/app:1.2.3".
    assert captured["display_name"] == "ghcr:acme/app:1.2.3"
    assert result == {"asset-1": "ghcr:acme/app:1.2.3"}
