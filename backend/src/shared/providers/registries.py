"""Concrete ImageRegistry implementations.

Each class encapsulates one container registry's image-reference convention.
Adding a new registry: write a class with a `source_type` attribute and a
`normalize_image_ref` method, then register it at the bottom of this file.

Contract: `normalize_image_ref(org, name, instance_url)` is called only when
the input `name` does NOT already include a registry hostname prefix. Callers
(e.g. `shared/config.py::get_scan_sources_for_org`) gate on whether the first
path segment already contains a `.` (i.e. looks like a hostname).
"""
from __future__ import annotations

from src.shared.providers.base import register_image_registry


class GhcrRegistry:
    source_type = "ghcr"

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        return f"ghcr.io/{org}/{name}"


class DockerHubRegistry:
    source_type = "docker-hub"

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        # Docker Hub: if name already includes a "/" (e.g. "org/img"), keep as-is;
        # otherwise prefix with the org.
        name_without_tag = name.split(":")[0]
        if "/" not in name_without_tag:
            return f"{org}/{name}"
        return name


class EcrRegistry:
    source_type = "ecr"

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        registry_url = (instance_url or "").rstrip("/")
        return f"{registry_url}/{name}" if registry_url else name


class AcrRegistry:
    source_type = "acr"

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        registry_url = (instance_url or "").rstrip("/")
        return f"{registry_url}/{name}" if registry_url else name


class GcrRegistry:
    source_type = "gcr"

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        registry_url = (instance_url or "gcr.io").rstrip("/")
        return f"{registry_url}/{org}/{name}"


class GitLabContainerRegistry:
    source_type = "gitlab-registry"

    def normalize_image_ref(self, org: str, name: str, instance_url: str) -> str:
        base = instance_url or "registry.gitlab.com"
        return f"{base}/{org}/{name}"


for _cls in (
    GhcrRegistry, DockerHubRegistry, EcrRegistry,
    AcrRegistry, GcrRegistry, GitLabContainerRegistry,
):
    register_image_registry(_cls())
