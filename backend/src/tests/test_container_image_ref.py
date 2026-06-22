"""Unit tests for container image-ref normalization used by OSV ingest."""
from __future__ import annotations

import pytest

from src.containers.scanner import _image_external_ref


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
